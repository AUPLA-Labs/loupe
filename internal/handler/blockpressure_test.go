package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const pressureTestIP = "203.0.113.50"

// newPressureFixture is a real handler whose config lists /.env as an
// exploit path.
func newPressureFixture(t *testing.T) *rulesFixture {
	t.Helper()
	return newRulesFixtureWith(t, "", "hardening:\n  exploit_paths: [/.env]\n", nil)
}

func uaFrom(ua string) *http.Request {
	r := fromIP(pressureTestIP)
	r.Header.Set("User-Agent", ua)
	return r
}

func TestScannerUAAddsPressureOncePerMinute(t *testing.T) {
	f := newPressureFixture(t)
	for i := 0; i < 3; i++ {
		if w := f.serve(uaFrom("sqlmap/1.7")); w.Code != http.StatusForbidden {
			t.Fatalf("status %d, want the block page", w.Code)
		}
	}
	if got := f.h.reputation.IPPressure(pressureTestIP); got != 5 {
		t.Fatalf("pressure = %v, want 5 (one scanner hit per minute)", got)
	}
}

func TestClientLibraryUAAddsSmallPressure(t *testing.T) {
	for _, ua := range []string{"curl/8.5.0", "python-requests/2.31", ""} {
		f := newPressureFixture(t)
		f.serve(uaFrom(ua))
		if got := f.h.reputation.IPPressure(pressureTestIP); got != 1 {
			t.Errorf("UA %q: pressure = %v, want 1", ua, got)
		}
	}
}

func TestExploitPathAddsPressureUncleared(t *testing.T) {
	f := newPressureFixture(t)
	r := fromIP(pressureTestIP)
	r.URL.Path = "/.env"
	f.serve(r)
	if got := f.h.reputation.IPPressure(pressureTestIP); got < 8 {
		t.Fatalf("pressure = %v, want at least 8", got)
	}
}

func TestExploitPathAddsPressureWhenCleared(t *testing.T) {
	f := newPressureFixture(t)
	issuing := fromIP(pressureTestIP)
	w := httptest.NewRecorder()
	f.h.cookies.Issue(w, pressureTestIP, issuing)
	r := fromIP(pressureTestIP)
	r.URL.Path = "/.env"
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	if _, valid := f.h.cookies.Check(r, pressureTestIP); !valid {
		t.Fatal("test setup: clearance not valid")
	}
	f.serve(r)
	if got := f.h.reputation.IPPressure(pressureTestIP); got != 8 {
		t.Fatalf("pressure = %v, want 8", got)
	}
}

func TestExploitPathFromScannerStacks(t *testing.T) {
	f := newPressureFixture(t)
	r := uaFrom("Nuclei/3.0")
	r.URL.Path = "/.env"
	f.serve(r)
	if got := f.h.reputation.IPPressure(pressureTestIP); got != 13 {
		t.Fatalf("pressure = %v, want 13 (8 exploit + 5 scanner)", got)
	}
}

func TestOrdinaryRequestAddsNoBlockPressure(t *testing.T) {
	f := newPressureFixture(t)
	f.serve(fromIP(pressureTestIP))
	if got := f.h.reputation.IPPressure(pressureTestIP); got != 0 {
		t.Fatalf("pressure = %v, want 0", got)
	}
}

func TestSpoofedBotAddsPressure(t *testing.T) {
	f := newPressureFixture(t)
	f.serve(uaFrom("LinkedInBot/1.0 (compatible; Mozilla/5.0)"))
	if got := f.h.reputation.IPPressure(pressureTestIP); got != 5 {
		t.Fatalf("pressure = %v, want 5 for a spoofed LinkedInBot", got)
	}
}

// Apple's iMessage link preview claims to be Facebook's and X's preview
// bots from Apple's own addresses, so neither claim counts as a spoof.
func TestApplePreviewSpoofIsExempt(t *testing.T) {
	for _, ua := range []string{
		"facebookexternalhit/1.1 Facebot Twitterbot/1.0",
		"Twitterbot/1.0",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
	} {
		f := newPressureFixture(t)
		f.serve(uaFrom(ua))
		if got := f.h.reputation.IPPressure(pressureTestIP); got != 0 {
			t.Errorf("UA %q: pressure = %v, want 0", ua, got)
		}
	}
}
