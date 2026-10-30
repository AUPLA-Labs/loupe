package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestUnderAttackRaisesFloor(t *testing.T) {
	f := newRulesFixture(t, "")
	if _, err := f.h.underAttack.Set(true, time.Hour, "prism", false, "test"); err != nil {
		t.Fatal(err)
	}
	w := f.serve(chromeNav())
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), f.h.prismPath) {
		t.Fatalf("status %d Location %q, want the Prism puzzle", w.Code, w.Header().Get("Location"))
	}
	if evs := f.events("CHALLENGE", "under_attack"); len(evs) != 1 || evs[0].Tier != 4 {
		t.Fatalf("CHALLENGE under_attack events = %+v, want one at Prism", evs)
	}
	f.h.underAttack.Set(false, 0, "", false, "test")
	if w := f.serve(chromeNav()); strings.HasPrefix(w.Header().Get("Location"), f.h.prismPath) {
		t.Fatal("still Prism after turning it off")
	}
}

func TestUnderAttackExemptsAllowRulesAndAPIRoutes(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: partner
    mode: enforce
    action: allow
    match: {ips: ["198.51.100.9"]}
  - id: api
    mode: enforce
    action: api
    api: {auth: none}
    match: {paths: [{prefix: /api/}]}
`)
	f.h.underAttack.Set(true, 0, "prism", true, "test")
	if w := f.serve(fromIP("198.51.100.9")); w.Code != http.StatusOK {
		t.Errorf("allow rule under attack: %d, want proxied", w.Code)
	}
	if w := f.serve(apiCall(http.MethodGet, "/api/x")); w.Code != http.StatusOK {
		t.Errorf("open api route under attack: %d, want proxied", w.Code)
	}
}

func TestUnderAttackRevokesOlderCookiesOnce(t *testing.T) {
	f := newRulesFixture(t, "")
	old := issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav())
	withCookies := func(cs []*http.Cookie) *http.Request {
		r := chromeNav()
		for _, c := range cs {
			r.AddCookie(c)
		}
		return r
	}
	// Without revoke_clearance, an existing clearance still passes.
	f.h.underAttack.Set(true, 0, "single_click", false, "test")
	if w := f.serve(withCookies(old)); w.Code != http.StatusOK {
		t.Fatalf("clearance without revoke: %d, want proxied", w.Code)
	}
	// Cookies carry whole seconds, so issue times only compare by second.
	time.Sleep(1100 * time.Millisecond)
	f.h.underAttack.Set(false, 0, "", false, "test")
	f.h.underAttack.Set(true, 0, "single_click", true, "test")
	if w := f.serve(withCookies(old)); w.Code == http.StatusOK {
		t.Fatal("a clearance from before the switch still passed")
	}
	fresh := issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav())
	if w := f.serve(withCookies(fresh)); w.Code != http.StatusOK {
		t.Fatalf("a clearance earned while under attack: %d, want proxied", w.Code)
	}
}
