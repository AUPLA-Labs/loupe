package offender

import (
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// Escalations remembers that Loupe decided a client needs a harder
// challenge than its ASN alone would imply.
//
// Without this, escalation was purely advisory. The probe handler redirected a
// suspicious client to the challenge page with "&m=1", but the challenge page
// itself decided whether to request a manual challenge, and the verifier
// re-derived the requirement from the ASN only. A bot on a residential ASN
// could therefore skip the page, fetch the challenge endpoint with no "m",
// solve the easy auto challenge, and pass — with the singleclick_bypass and
// click_not_trusted signals never evaluated.
//
// Require only ever raises a client's level, so the client-supplied "m"
// parameter can make a challenge harder but never easier.
type Escalations struct {
	mu     sync.Mutex
	levels map[string]escalation
	// lumen holds what Lumen's difficulty (internal/lumen) needs from
	// earlier requests: the request score saved at dispatch (the challenge
	// is issued on a later request, which no longer has the navigation's
	// headers to score) and the minimum level an earlier answer demanded.
	// It expires on its own, so saving it never extends a tier escalation.
	lumen map[string]lumenScore
}

type escalation struct {
	level   tier.Tier
	expires time.Time
}

type lumenScore struct {
	score   int
	demand  int
	expires time.Time
}

func NewEscalations() *Escalations {
	e := &Escalations{levels: make(map[string]escalation), lumen: make(map[string]lumenScore)}
	go e.evict()
	return e
}

// Require raises key's required tier to at least level, for ttl from now.
// A repeated Require at the same or a lower level refreshes the expiry without
// lowering the level.
func (e *Escalations) Require(key string, level tier.Tier, ttl time.Duration) {
	if key == "" || level <= tier.Pass {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	next := escalation{level: level, expires: time.Now().Add(ttl)}
	if cur, ok := e.levels[key]; ok && time.Now().Before(cur.expires) {
		next.level = tier.Max(cur.level, level)
		if cur.expires.After(next.expires) {
			next.expires = cur.expires
		}
	}
	e.levels[key] = next
}

// RequireLumen raises key's saved Lumen request score to at least score,
// for ttl from now, with the same only-raises rule as Require.
func (e *Escalations) RequireLumen(key string, score int, ttl time.Duration) {
	if score <= 0 {
		return
	}
	e.raiseLumen(key, ttl, func(cur *lumenScore) { cur.score = max(cur.score, score) })
}

// DemandLumen raises the minimum Lumen level key's next challenges are
// issued at to at least level, for ttl from now. An answer that scored as
// suspicious demands it, so the evidence that only arrives with an answer
// still raises what the client pays next.
func (e *Escalations) DemandLumen(key string, level int, ttl time.Duration) {
	if level <= 0 {
		return
	}
	e.raiseLumen(key, ttl, func(cur *lumenScore) { cur.demand = max(cur.demand, level) })
}

func (e *Escalations) raiseLumen(key string, ttl time.Duration, raise func(*lumenScore)) {
	if key == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	next := lumenScore{expires: time.Now().Add(ttl)}
	if cur, ok := e.lumen[key]; ok && time.Now().Before(cur.expires) {
		next.score, next.demand = cur.score, cur.demand
		if cur.expires.After(next.expires) {
			next.expires = cur.expires
		}
	}
	raise(&next)
	e.lumen[key] = next
}

// Lumen reports key's saved Lumen request score, or 0 if there is none.
func (e *Escalations) Lumen(key string) int {
	cur, _ := e.lumenEntry(key)
	return cur.score
}

// LumenDemand reports the minimum Lumen level an earlier answer demanded
// for key, or 0 if there is none.
func (e *Escalations) LumenDemand(key string) int {
	cur, _ := e.lumenEntry(key)
	return cur.demand
}

func (e *Escalations) lumenEntry(key string) (lumenScore, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, ok := e.lumen[key]
	if !ok || time.Now().After(cur.expires) {
		return lumenScore{}, false
	}
	return cur, true
}

// Level reports the tier key must currently satisfy, or tier.Pass if there is
// no live escalation for it.
func (e *Escalations) Level(key string) tier.Tier {
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, ok := e.levels[key]
	if !ok {
		return tier.Pass
	}
	if time.Now().After(cur.expires) {
		delete(e.levels, key)
		return tier.Pass
	}
	return cur.level
}

// Clear drops any escalation for key. Called once a client has successfully
// cleared, so a later visit starts from a clean slate.
func (e *Escalations) Clear(key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.levels, key)
	delete(e.lumen, key)
}

func (e *Escalations) evict() {
	for range time.Tick(5 * time.Minute) {
		now := time.Now()
		e.mu.Lock()
		for k, v := range e.levels {
			if now.After(v.expires) {
				delete(e.levels, k)
			}
		}
		for k, v := range e.lumen {
			if now.After(v.expires) {
				delete(e.lumen, k)
			}
		}
		e.mu.Unlock()
	}
}
