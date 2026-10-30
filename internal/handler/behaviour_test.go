package handler

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
	"unsafe"
)

var behaviourStart = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func nav(path, site string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Sec-Fetch-Site", site)
	return r
}

// observeAll feeds navigations at the given offsets and returns the last
// result.
func observeAll(b *behaviour, id string, at []time.Duration, req func(i int) *http.Request) (int, []string) {
	var score int
	var reasons []string
	for i, d := range at {
		score, reasons = b.Observe(id, req(i), behaviourStart.Add(d))
	}
	return score, reasons
}

func every(n int, step time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = time.Duration(i) * step
	}
	return out
}

func TestRegularIntervalsFlagged(t *testing.T) {
	b := newBehaviour()
	_, reasons := observeAll(b, "c", every(25, 3*time.Second), func(i int) *http.Request { return nav(fmt.Sprintf("/p/%c", 'a'+i), "same-origin") })
	if !slices.Contains(reasons, "nav_too_regular") {
		t.Fatalf("a navigation every 3s exactly: %v, want nav_too_regular", reasons)
	}
	// A page reloading itself every minute is regular too, but slow.
	b = newBehaviour()
	_, reasons = observeAll(b, "c", every(25, time.Minute), func(int) *http.Request { return nav("/status", "same-origin") })
	if slices.Contains(reasons, "nav_too_regular") {
		t.Fatalf("a page reloading every minute was flagged: %v", reasons)
	}
}

func TestHumanIntervalsNotFlagged(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	at := make([]time.Duration, 40)
	var t0 time.Duration
	for i := range at {
		at[i] = t0
		t0 += time.Duration(2+rng.ExpFloat64()*8) * time.Second // reading time varies a lot
	}
	b := newBehaviour()
	score, reasons := observeAll(b, "c", at, func(i int) *http.Request { return nav(fmt.Sprintf("/article/%c", 'a'+i%26), "same-origin") })
	if score != 0 {
		t.Fatalf("jittered human browsing: score %d %v, want 0", score, reasons)
	}
}

func TestPathEnumerationFlagged(t *testing.T) {
	b := newBehaviour()
	at := make([]time.Duration, 12)
	for i := range at {
		at[i] = time.Duration(i*i+i) * time.Second // irregular, so only enumeration fires
	}
	score, reasons := observeAll(b, "c", at, func(i int) *http.Request { return nav(fmt.Sprintf("/invoice/%d?view=full", 1000+i), "same-origin") })
	if !slices.Contains(reasons, "path_enumeration") || score < behaviourThreshold {
		t.Fatalf("/invoice/1000..1011: score %d %v, want path_enumeration at the threshold", score, reasons)
	}
	// Paging back and forth isn't enumeration.
	b = newBehaviour()
	_, reasons = observeAll(b, "c", at, func(i int) *http.Request { return nav(fmt.Sprintf("/list?page=%d", 1+i%3), "same-origin") })
	if slices.Contains(reasons, "path_enumeration") {
		t.Fatalf("paging 1,2,3,1,2,3: %v", reasons)
	}
}

func TestSustainedRateAndNoReferrer(t *testing.T) {
	b := newBehaviour()
	_, reasons := observeAll(b, "c", every(70, 800*time.Millisecond), func(i int) *http.Request { return nav(fmt.Sprintf("/x/%c%c", 'a'+i%26, 'a'+i/26), "none") })
	if !slices.Contains(reasons, "nav_sustained_rate") || !slices.Contains(reasons, "no_referrer_chain") {
		t.Fatalf("70 typed-in navigations in 56s: %v, want nav_sustained_rate and no_referrer_chain", reasons)
	}
}

// Requests that aren't navigations never reach Observe, so a cleared
// browser whose assets come from Cloudflare's cache (and never reach
// Loupe) looks the same as one whose assets do.
func TestBehaviourIgnoresMissingAssets(t *testing.T) {
	f := newRulesFixture(t, "")
	clearance := issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav())
	// Fewer than a full ring: served back to back, 20 navigations would
	// rightly look too regular.
	for i := range 15 {
		r := chromeNav()
		r.URL.Path = fmt.Sprintf("/page/%c", 'a'+i%26)
		r.Header.Set("Sec-Fetch-Site", "same-origin") // following links
		for _, c := range clearance {
			r.AddCookie(c)
		}
		f.serve(r) // no asset requests at all
	}
	for _, e := range f.events("ALLOW", "clearance") {
		if e.Score != 0 {
			t.Fatalf("navigations without assets scored %d %v", e.Score, e.Reasons)
		}
	}
	// An XHR poll every second is not a navigation and is never observed.
	for range 30 {
		r := chromeNav()
		r.URL.Path = "/unread-count"
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		for _, c := range clearance {
			r.AddCookie(c)
		}
		f.serve(r)
	}
	if n := len(f.h.behaviour.m); n != 1 {
		t.Fatalf("tracking %d cookies, want 1", n)
	}
}

func TestBehaviourLogOnlyByDefault(t *testing.T) {
	f := newRulesFixture(t, "")
	clearance := issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav())
	req := func(i int) *http.Request {
		r := chromeNav()
		r.URL.Path = fmt.Sprintf("/invoice/%d", 1000+i)
		for _, c := range clearance {
			r.AddCookie(c)
		}
		return r
	}
	for i := range 12 {
		if w := f.serve(req(i)); w.Code != http.StatusOK {
			t.Fatalf("navigation %d: %d, want proxied (log only)", i, w.Code)
		}
	}
	var flagged bool
	for _, e := range f.events("ALLOW", "clearance") {
		if slices.Contains(e.Reasons, "path_enumeration") && e.Score >= behaviourThreshold {
			flagged = true
		}
	}
	if !flagged {
		t.Fatal("no clearance event records path_enumeration")
	}

	f.h.cfg.Behaviour.Enforce = true
	if w := f.serve(req(12)); w.Code == http.StatusOK {
		t.Fatal("enforce: a flagged client kept its clearance")
	}
	if evs := f.events("CHALLENGE", "clearance_behaviour"); len(evs) != 1 {
		t.Fatalf("CHALLENGE clearance_behaviour events = %+v, want one", evs)
	}
	if w := f.serve(req(13)); w.Code == http.StatusOK {
		t.Fatal("the dropped clearance still works: it must be revoked")
	}
}

func TestBehaviourMemoryBounded(t *testing.T) {
	if sz := unsafe.Sizeof(navState{}); sz > navRing*8+64 {
		t.Fatalf("navState is %d bytes, want at most the ring plus 64", sz)
	}
	b := newBehaviour()
	for i := range behaviourMaxKeys + 10 {
		b.Observe(fmt.Sprint(i), nav("/", "none"), behaviourStart)
	}
	if len(b.m) != behaviourMaxKeys {
		t.Fatalf("tracking %d cookies, want the cap %d", len(b.m), behaviourMaxKeys)
	}
	b.Observe("late", nav("/", "none"), behaviourStart.Add(behaviourIdle+2*time.Minute))
	if len(b.m) != 1 {
		t.Fatalf("after the idle time: %d cookies, want only the new one", len(b.m))
	}
}
