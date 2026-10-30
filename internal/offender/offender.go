// Package offender hard-blocks an IP for a cooldown period after too many
// consecutive challenge/verification failures, instead of handing out an
// endless stream of fresh, equally-easy challenges to the same abuser.
package offender

import (
	"sync"
	"time"
)

type failState struct {
	count    int
	lastSeen time.Time
}

type unansweredState struct {
	count    int
	lastSeen time.Time
}

type answeredNoClearanceState struct {
	count    int
	lastSeen time.Time
}

type Tracker struct {
	mu                  sync.Mutex
	fails               map[string]*failState
	blockedUntil        map[string]time.Time
	unanswered          map[string]*unansweredState
	answeredNoClearance map[string]*answeredNoClearanceState
	threshold           int
	cooldown            time.Duration
}

func New(threshold int, cooldown time.Duration) *Tracker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 15 * time.Minute
	}
	t := &Tracker{
		fails:               make(map[string]*failState),
		blockedUntil:        make(map[string]time.Time),
		unanswered:          make(map[string]*unansweredState),
		answeredNoClearance: make(map[string]*answeredNoClearanceState),
		threshold:           threshold,
		cooldown:            cooldown,
	}
	go t.evict()
	return t
}

// Blocked reports whether ip is currently in its cooldown window.
func (t *Tracker) Blocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.blockedUntil[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(t.blockedUntil, ip)
		return false
	}
	return true
}

// Fail records a failed verification attempt, hard-blocking the IP once
// threshold consecutive failures are reached. Returns true the moment the
// block is triggered (useful for a one-time "now blocked" log line).
func (t *Tracker) Fail(ip string) (justBlocked bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fs, ok := t.fails[ip]
	if !ok {
		fs = &failState{}
		t.fails[ip] = fs
	}
	fs.count++
	fs.lastSeen = time.Now()
	if fs.count >= t.threshold {
		t.blockedUntil[ip] = time.Now().Add(t.cooldown)
		delete(t.fails, ip)
		return true
	}
	return false
}

// Success clears the failure count for ip. A completed challenge is a clean
// slate for future attempts — it does not lift an already-active cooldown,
// since Blocked() is checked earlier in the pipeline than any verify step.
func (t *Tracker) Success(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, ip)
}

// Issued records that a challenge or interstitial was served to key, and
// returns how many consecutive prior issuances to key were never answered.
// A nonzero return means the previous challenge(s) went unanswered — the
// caller feeds that count into reputation as evidence of automation, since
// failing to answer at all costs a real attacker nothing otherwise.
func (t *Tracker) Issued(key string) (priorUnanswered int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	us, ok := t.unanswered[key]
	if !ok {
		us = &unansweredState{}
		t.unanswered[key] = us
	}
	priorUnanswered = us.count
	us.count++
	us.lastSeen = time.Now()
	return priorUnanswered
}

// Unanswered reports key's consecutive-unanswered count without changing
// it. The count includes the issuance currently in flight, if any.
func (t *Tracker) Unanswered(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if us, ok := t.unanswered[key]; ok {
		return us.count
	}
	return 0
}

// Answered resets key's consecutive-unanswered counter to zero. Called the
// moment any answer arrives — a valid token reaching /loupe/pulse/verify,
// /loupe/verify, or /loupe/prism/verify — before that answer is
// scored, because answering at all is the property being measured. This is
// the NAT/CGNAT guard: if even one client behind a shared address runs JS,
// the key never accumulates unanswered pressure.
func (t *Tracker) Answered(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.unanswered, key)
}

// IncrAnsweredNoClearance records that key answered a challenge or probe —
// call this immediately after Answered at every site that accepts an
// answer (probe-result, challenge verify, Prism verify). Paired with
// ClearAnsweredNoClearance, this is the backstop for a client that
// accepts answers but never retains the resulting clearance cookie: the
// server-observable signature of the infinite redirect loop from §12.1,
// independent of whether the probe cookie (§12.2 primary detection) caught
// it too.
func (t *Tracker) IncrAnsweredNoClearance(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.answeredNoClearance[key]
	if !ok {
		s = &answeredNoClearanceState{}
		t.answeredNoClearance[key] = s
	}
	s.count++
	s.lastSeen = time.Now()
}

// AnsweredNoClearanceCount returns key's current consecutive
// answered-without-clearance count, without mutating it.
func (t *Tracker) AnsweredNoClearanceCount(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.answeredNoClearance[key]; ok {
		return s.count
	}
	return 0
}

// ClearAnsweredNoClearance resets key's counter. Call this wherever a
// request arrives bearing a valid clearance cookie — proof this client's
// cookies do work, so its earlier unanswered-clearance streak no longer
// indicates a loop in progress.
func (t *Tracker) ClearAnsweredNoClearance(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.answeredNoClearance, key)
}

func (t *Tracker) evict() {
	for range time.Tick(10 * time.Minute) {
		now := time.Now()
		cutoff := now.Add(-time.Hour)
		t.mu.Lock()
		for ip, fs := range t.fails {
			if fs.lastSeen.Before(cutoff) {
				delete(t.fails, ip)
			}
		}
		for ip, until := range t.blockedUntil {
			if now.After(until) {
				delete(t.blockedUntil, ip)
			}
		}
		for ip, us := range t.unanswered {
			if us.lastSeen.Before(cutoff) {
				delete(t.unanswered, ip)
			}
		}
		for ip, s := range t.answeredNoClearance {
			if s.lastSeen.Before(cutoff) {
				delete(t.answeredNoClearance, ip)
			}
		}
		t.mu.Unlock()
	}
}
