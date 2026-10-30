// Per-key token bucket rate limiter. Safe for concurrent use.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      float64 // tokens added per second
	burst     float64 // max token capacity
	idle      time.Duration
	lastSweep time.Time
	maxKeys   int // 0 = unlimited

	now func() time.Time // overridable for tests
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// overflowKey is the bucket every new key shares once a limiter holds
// maxKeys: a flood of distinct keys is limited together instead of growing
// the map without bound.
const overflowKey = "\x00overflow"

// New limits each key to rate tokens per second with bursts of burst. Keys
// unseen for 5 minutes are forgotten.
func New(rate, burst float64) *Limiter {
	return NewWithIdle(rate, burst, 5*time.Minute)
}

// NewWithIdle is New with the time after which an unseen key is forgotten.
// It is raised to burst/rate, the time an empty bucket takes to fill, so
// forgetting a key never hands it more tokens than waiting would have.
func NewWithIdle(rate, burst float64, idle time.Duration) *Limiter {
	if full := time.Duration(burst / rate * float64(time.Second)); idle < full {
		idle = full
	}
	return &Limiter{buckets: make(map[string]*bucket), rate: rate, burst: burst, idle: idle, now: time.Now}
}

// SetMaxKeys caps how many keys are tracked; past it, new keys share one
// bucket until old ones are forgotten.
func (l *Limiter) SetMaxKeys(n int) {
	l.mu.Lock()
	l.maxKeys = n
	l.mu.Unlock()
}

func (l *Limiter) Allow(key string) bool {
	ok, _ := l.Take(key)
	return ok
}

// Take spends a token for key. When none is left it reports how long until
// one is.
func (l *Limiter) Take(key string) (ok bool, retryAfter time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= min(l.idle, time.Minute) {
		l.sweep(now)
	}
	b, found := l.buckets[key]
	if !found && l.maxKeys > 0 && len(l.buckets) >= l.maxKeys {
		key = overflowKey
		b, found = l.buckets[key]
	}
	if !found {
		l.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}
		return true, 0
	}
	b.tokens += now.Sub(b.lastSeen).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now
	if b.tokens < 1 {
		wait := math.Ceil((1 - b.tokens) / l.rate * float64(time.Second))
		return false, time.Duration(wait)
	}
	b.tokens--
	return true, 0
}

// sweep forgets keys unseen for idle. It runs from Take, so a limiter
// nobody uses costs nothing and needs no goroutine to stop.
func (l *Limiter) sweep(now time.Time) {
	l.lastSweep = now
	cutoff := now.Add(-l.idle)
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// Len is the number of keys tracked.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
