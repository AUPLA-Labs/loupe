package ratelimit

import (
	"testing"
	"time"
)

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time                 { return c.t }
func (c *clock) add(d time.Duration)            { c.t = c.t.Add(d) }
func testLimiter(l *Limiter, c *clock) *Limiter { l.now = c.now; return l }

func TestTakeReportsRetryAfter(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	l := testLimiter(NewWithIdle(5.0/60, 5, 0), c) // 5 a minute
	for i := range 5 {
		if ok, _ := l.Take("k"); !ok {
			t.Fatalf("request %d refused within the burst", i+1)
		}
	}
	ok, wait := l.Take("k")
	if ok || wait != 12*time.Second {
		t.Fatalf("6th request: ok=%v retryAfter=%v, want refused with 12s", ok, wait)
	}
	c.add(12 * time.Second)
	if ok, _ := l.Take("k"); !ok {
		t.Fatal("refused after waiting the reported time")
	}
	if ok, _ := l.Take("other"); !ok {
		t.Fatal("another key shares the first one's bucket")
	}
}

// A 1-a-minute limit must not forget a client after the old fixed 5
// minutes' idle while its bucket is still refilling.
func TestIdleEvictionRespectsLongWindows(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	l := testLimiter(NewWithIdle(1.0/3600, 10, time.Minute), c) // 10 an hour
	for range 10 {
		l.Take("k")
	}
	c.add(30 * time.Minute)
	l.Take("someone-else") // triggers a sweep
	if ok, _ := l.Take("k"); ok {
		t.Fatal("the key was forgotten half way through its window and got a fresh burst")
	}
	c.add(11 * time.Hour) // an empty bucket of 10 refills in 10h
	l.Take("someone-else")
	if l.Len() != 1 {
		t.Fatalf("tracking %d keys after a long idle, want only the active one", l.Len())
	}
}

func TestMaxKeysSharesOverflowBucket(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	l := testLimiter(NewWithIdle(1, 2, 0), c)
	l.SetMaxKeys(2)
	l.Take("a")
	l.Take("b")
	l.Take("c")
	l.Take("d")
	if ok, _ := l.Take("e"); ok {
		t.Fatal("new keys past the cap each got their own burst")
	}
	if l.Len() != 3 {
		t.Fatalf("tracking %d keys, want the 2 allowed plus the overflow bucket", l.Len())
	}
}
