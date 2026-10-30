package handler

import (
	"net/http"
	"sync"
	"time"
)

// Post-clearance behaviour scoring. A clearance proves a browser passed a
// challenge once; these signals look for a script driving the cookie
// afterwards. They read document navigations only: Cloudflare may serve
// assets from its cache, so their absence says nothing, and XHR polling is
// regular by design.
//
// The signals are scored, and by default only recorded on the clearance
// event. With behaviour.enforce, a score of behaviourThreshold drops the
// clearance and adds reputation pressure.

const (
	navRing            = 20               // navigation times kept per cookie
	behaviourThreshold = 3                // score at which enforce drops the clearance
	behaviourMaxKeys   = 50_000           // cookies tracked at once
	behaviourIdle      = 30 * time.Minute // a cookie unseen this long is forgotten

	// nav_too_regular: the last navRing navigations came at near-equal
	// intervals (coefficient of variation below regularCV) and quickly
	// (mean interval at most regularMaxMean). The mean bound spares a tab
	// that reloads itself every minute or so.
	regularCV      = 0.1
	regularMaxMean = 20 * time.Second

	// nav_sustained_rate: more than sustainedNavs navigations in one
	// sustainedWindow, more than one a second held for a minute.
	sustainedWindow = time.Minute
	sustainedNavs   = 60

	// path_enumeration: enumerationRun navigations in a row whose URLs
	// differ only in their last number, which goes up by one each time.
	enumerationRun = 10

	// no_referrer_chain: noReferrerRun navigations in a row that each
	// arrived from nowhere (Sec-Fetch-Site: none), never by a link.
	noReferrerRun = 20
)

var behaviourWeights = map[string]int{
	"nav_too_regular":    2,
	"nav_sustained_rate": 3,
	"path_enumeration":   3,
	"no_referrer_chain":  1,
}

// navState is what is kept per cookie: the ring of navigation times plus
// under 64 bytes of counters.
type navState struct {
	times    [navRing]int64 // unix nanoseconds, oldest overwritten
	n, next  uint8
	enumRun  uint8
	noneRun  uint8
	winCount uint16
	winStart int64
	enumTmpl uint64 // hash of the last URL with its last number blanked
	enumNum  uint64
	lastSeen int64
}

type behaviour struct {
	mu        sync.Mutex
	m         map[string]*navState
	lastSweep time.Time
}

func newBehaviour() *behaviour {
	return &behaviour{m: make(map[string]*navState)}
}

// Observe records a document navigation made with the clearance cookieID
// and returns its behaviour score and the signals behind it.
func (b *behaviour) Observe(cookieID string, r *http.Request, now time.Time) (score int, reasons []string) {
	if b == nil {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.lastSweep) >= time.Minute {
		b.sweep(now)
	}
	s := b.m[cookieID]
	if s == nil {
		if len(b.m) >= behaviourMaxKeys {
			return 0, nil
		}
		s = &navState{}
		b.m[cookieID] = s
	}
	t := now.UnixNano()
	s.lastSeen = t
	s.times[s.next] = t
	s.next = (s.next + 1) % navRing
	if s.n < navRing {
		s.n++
	}

	if t-s.winStart >= int64(sustainedWindow) {
		s.winStart, s.winCount = t, 0
	}
	if s.winCount < 0xffff {
		s.winCount++
	}

	tmpl, num, ok := lastNumber(r.URL.RequestURI())
	switch {
	case !ok:
		s.enumRun = 0
	case s.enumRun > 0 && tmpl == s.enumTmpl && num == s.enumNum+1:
		if s.enumRun < 0xff {
			s.enumRun++
		}
	default:
		s.enumRun = 1
	}
	s.enumTmpl, s.enumNum = tmpl, num

	if r.Header.Get("Sec-Fetch-Site") == "none" {
		if s.noneRun < 0xff {
			s.noneRun++
		}
	} else {
		s.noneRun = 0
	}

	flag := func(name string) {
		score += behaviourWeights[name]
		reasons = append(reasons, name)
	}
	if s.regular() {
		flag("nav_too_regular")
	}
	if s.winCount > sustainedNavs {
		flag("nav_sustained_rate")
	}
	if s.enumRun >= enumerationRun {
		flag("path_enumeration")
	}
	if s.noneRun >= noReferrerRun {
		flag("no_referrer_chain")
	}
	return score, reasons
}

// regular reports a full ring of fast, near-equal intervals.
func (s *navState) regular() bool {
	if s.n < navRing {
		return false
	}
	// s.next is the oldest entry once the ring is full.
	var iv [navRing - 1]float64
	var sum float64
	for i := range iv {
		a := s.times[(int(s.next)+i)%navRing]
		b := s.times[(int(s.next)+i+1)%navRing]
		iv[i] = float64(b - a)
		sum += iv[i]
	}
	mean := sum / float64(len(iv))
	if mean <= 0 || mean > float64(regularMaxMean) {
		return false
	}
	var ss float64
	for _, v := range iv {
		ss += (v - mean) * (v - mean)
	}
	variance := ss / float64(len(iv))
	// CV < regularCV ⇔ variance < (regularCV·mean)², without a square root.
	return variance < regularCV*regularCV*mean*mean
}

func (b *behaviour) sweep(now time.Time) {
	b.lastSweep = now
	cutoff := now.Add(-behaviourIdle).UnixNano()
	for k, s := range b.m {
		if s.lastSeen < cutoff {
			delete(b.m, k)
		}
	}
}

// lastNumber splits a URL around its last run of digits: a hash of the URL
// with that run blanked, and its value. ok is false without one, or when it
// is too long to be a counter.
func lastNumber(u string) (tmpl, num uint64, ok bool) {
	end := -1
	for i := len(u) - 1; i >= 0; i-- {
		if u[i] >= '0' && u[i] <= '9' {
			end = i + 1
			break
		}
	}
	if end < 0 {
		return 0, 0, false
	}
	start := end - 1
	for start > 0 && u[start-1] >= '0' && u[start-1] <= '9' {
		start--
	}
	if end-start > 18 {
		return 0, 0, false
	}
	for i := start; i < end; i++ {
		num = num*10 + uint64(u[i]-'0')
	}
	h := uint64(14695981039346656037) // FNV-1a over u without the digits
	for i := 0; i < len(u); i++ {
		if i == start {
			h ^= '#'
			h *= 1099511628211
			i = end - 1
			continue
		}
		h ^= uint64(u[i])
		h *= 1099511628211
	}
	return h, num, true
}
