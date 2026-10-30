package cookie

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIssueValidateRoundTrip(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")

	rr := httptest.NewRecorder()
	m.IssueWithProfile(rr, "1.2.3.4", req, "abc123profile")

	// Copy Set-Cookie into a new request for validation.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	req2.Header.Set("User-Agent", "Mozilla/5.0 TestBrowser")
	for _, c := range rr.Result().Cookies() {
		req2.AddCookie(c)
	}

	c, ok := m.Check(req2, "1.2.3.4")
	if !ok {
		t.Fatal("expected valid cookie")
	}
	if c.ProfileHash != "abc123profile" {
		t.Errorf("expected profile %q, got %q", "abc123profile", c.ProfileHash)
	}
	if len(c.ID) != 16 {
		t.Errorf("ID = %q, want 16 hex chars", c.ID)
	}
}

func TestIssueCookieDomainDerivedFromRequestHost(t *testing.T) {
	cases := []struct {
		host   string
		wantIn string // the value the Set-Cookie Domain attribute must equal
	}{
		{"example.net", "example.net"},
		{"www.example.net", "example.net"},
		{"media.example.org", "example.org"},
		{"example.org:443", "example.org"},
		{"shop.example.co.uk", "example.co.uk"},
		{"192.168.1.1", "192.168.1.1"},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			m := New("test-secret", "waf_pass", 3600)

			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tc.host
			req.Header.Set("User-Agent", "TestBrowser")

			rr := httptest.NewRecorder()
			m.Issue(rr, "1.2.3.4", req)

			cookies := rr.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("expected 1 cookie, got %d", len(cookies))
			}
			if cookies[0].Domain != tc.wantIn {
				t.Errorf("host %q: expected cookie Domain %q, got %q", tc.host, tc.wantIn, cookies[0].Domain)
			}
		})
	}
}

func TestValidateRejectsWrongIP(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "TestBrowser")

	rr := httptest.NewRecorder()
	m.Issue(rr, "1.2.3.4", req)

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", "TestBrowser")
	for _, c := range rr.Result().Cookies() {
		req2.AddCookie(c)
	}

	if m.Validate(req2, "9.9.9.9") {
		t.Error("expected validation to fail for wrong IP")
	}
}

// A browser that keeps its cookie but changes its UA fails Check, and
// UAChanged tells that apart from a missing or foreign cookie.
func TestUAChanged(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "BrowserA")
	rr := httptest.NewRecorder()
	m.Issue(rr, "1.2.3.4", req)

	with := func(ua string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", ua)
		for _, c := range rr.Result().Cookies() {
			r.AddCookie(c)
		}
		return r
	}
	if m.UAChanged(with("BrowserA"), "1.2.3.4") {
		t.Error("same UA reported as changed")
	}
	if _, ok := m.Check(with("BrowserB"), "1.2.3.4"); ok {
		t.Error("Check accepted a different UA")
	}
	if !m.UAChanged(with("BrowserB"), "1.2.3.4") {
		t.Error("different UA not reported")
	}
	if m.UAChanged(with("BrowserB"), "9.9.9.9") {
		t.Error("another IP's cookie reported as a UA change")
	}
	if m.UAChanged(httptest.NewRequest("GET", "/", nil), "1.2.3.4") {
		t.Error("no cookie reported as a UA change")
	}
}

// Pre-v2 cookies carry no header shape, so they must stop validating and
// send the client through the pulse once for a v2 cookie.
func TestCheckRejectsPreV2Formats(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	for _, payload := range []string{
		"9999999999|5.5.5.5|" + uaFingerprint("OldBrowser"),
		"9999999999|5.5.5.5|" + uaFingerprint("OldBrowser") + "|profile",
	} {
		value := base64.RawURLEncoding.EncodeToString([]byte(payload + m.sign(payload)))
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "OldBrowser")
		req.AddCookie(&http.Cookie{Name: "waf_pass", Value: value})
		if _, ok := m.Check(req, "5.5.5.5"); ok {
			t.Errorf("pre-v2 payload %q validated", payload)
		}
	}
}

func chromeRequest() *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome")
	r.Header.Set("Accept-Language", "de-AT,de;q=0.9,en;q=0.8")
	r.Header.Set("Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24"`)
	r.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	r.Header.Set("Sec-CH-UA-Mobile", "?0")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func TestCheckRecordsIssuanceHeaders(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	issue := chromeRequest()
	rr := httptest.NewRecorder()
	m.Issue(rr, "1.2.3.4", issue)

	later := chromeRequest()
	for _, c := range rr.Result().Cookies() {
		later.AddCookie(c)
	}
	c, ok := m.Check(later, "1.2.3.4")
	if !ok {
		t.Fatal("expected valid cookie")
	}
	if !c.HadSecFetch || !c.HadCHUA {
		t.Errorf("flags = fetch:%v chua:%v, want both", c.HadSecFetch, c.HadCHUA)
	}
	if c.Shape != ShapeOf(later) {
		t.Error("shape must match a request with the same headers")
	}

	safari := httptest.NewRequest("GET", "/", nil)
	safari.Header.Set("User-Agent", "Safari")
	rr = httptest.NewRecorder()
	m.Issue(rr, "1.2.3.4", safari)
	for _, ck := range rr.Result().Cookies() {
		safari.AddCookie(ck)
	}
	if c, _ := m.Check(safari, "1.2.3.4"); c.HadSecFetch || c.HadCHUA {
		t.Error("flags must be unset when the issuing request lacked the headers")
	}
}

func TestShapeOf(t *testing.T) {
	base := ShapeOf(chromeRequest())

	// Only the primary language subtag counts.
	r := chromeRequest()
	r.Header.Set("Accept-Language", "de")
	if ShapeOf(r) != base {
		t.Error("a reduced Accept-Language with the same primary subtag must keep the shape")
	}

	for name, val := range map[string]string{
		"Accept-Language":    "en-US,en",
		"Sec-CH-UA":          `"Chromium";v="132"`,
		"Sec-CH-UA-Platform": `"Linux"`,
		"Sec-CH-UA-Mobile":   "?1",
	} {
		r := chromeRequest()
		r.Header.Set(name, val)
		if ShapeOf(r) == base {
			t.Errorf("changing %s must change the shape", name)
		}
	}
}

func TestClearExpiresCookie(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "www.example.net"
	rr := httptest.NewRecorder()
	m.Clear(rr, r)
	cs := rr.Result().Cookies()
	if len(cs) != 1 || cs[0].Name != "waf_pass" || cs[0].MaxAge >= 0 || cs[0].Domain != "example.net" {
		t.Errorf("Clear set %+v", cs)
	}
}

func TestProfileHashBuckets(t *testing.T) {
	secret := []byte("test-secret")

	// Same inputs should produce same hash.
	h1 := ProfileHash(secret, 1.9, 5.0, "", false)
	h2 := ProfileHash(secret, 1.9, 5.0, "", false)
	if h1 != h2 {
		t.Error("same inputs should produce same hash")
	}

	// Different jitter bucket should produce different hash.
	h3 := ProfileHash(secret, 2.1, 5.0, "", false)
	if h1 == h3 {
		t.Error("different jitter buckets should produce different hashes")
	}

	// Uniform vs normal rAF variance.
	hU := ProfileHash(secret, 10.0, 0.3, "", false)
	hN := ProfileHash(secret, 10.0, 0.6, "", false)
	if hU == hN {
		t.Error("uniform vs normal rAF buckets should produce different hashes")
	}

	// WebGL renderer affects hash.
	hNoGL := ProfileHash(secret, 10.0, 5.0, "", false)
	hGL := ProfileHash(secret, 10.0, 5.0, "NVIDIA GeForce RTX 3080", false)
	if hNoGL == hGL {
		t.Error("different webgl renderers should produce different hashes")
	}
}

func TestProfileDrifted(t *testing.T) {
	if ProfileDrifted("", "abc") {
		t.Error("empty stored should not drift")
	}
	if ProfileDrifted("abc", "") {
		t.Error("empty current should not drift")
	}
	if ProfileDrifted("abc", "abc") {
		t.Error("matching hashes should not drift")
	}
	if !ProfileDrifted("abc", "def") {
		t.Error("different hashes should drift")
	}
}

func TestProbeCookie_IssueThenHasProbe(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)

	req := httptest.NewRequest("GET", "/loupe/pulse", nil)
	req.Host = "example.org"
	rr := httptest.NewRecorder()
	m.IssueProbe(rr, req)

	req2 := httptest.NewRequest("POST", "/loupe/pulse/verify", nil)
	req2.Host = "example.org"
	for _, c := range rr.Result().Cookies() {
		req2.AddCookie(c)
	}

	if !m.HasProbe(req2) {
		t.Fatal("expected HasProbe to see the cookie IssueProbe just set")
	}
}

func TestProbeCookie_AbsentWhenNeverIssued(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	req := httptest.NewRequest("POST", "/loupe/pulse/verify", nil)
	if m.HasProbe(req) {
		t.Fatal("expected HasProbe to be false when no probe cookie was ever set")
	}
}

func TestProbeCookie_DomainMatchesClearanceCookieDerivation(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	req := httptest.NewRequest("GET", "/loupe/pulse", nil)
	req.Host = "shop.example.co.uk"
	rr := httptest.NewRecorder()
	m.IssueProbe(rr, req)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if cookies[0].Domain != "example.co.uk" {
		t.Errorf("probe cookie Domain = %q, want %q (same derivation as the clearance cookie)", cookies[0].Domain, "example.co.uk")
	}
}

func TestIsHTTPS(t *testing.T) {
	cases := []struct {
		name  string
		tls   bool
		proto string
		want  bool
	}{
		{"plain", false, "", false},
		{"direct TLS", true, "", true},
		{"proxy says https", false, "https", true},
		{"proxy says HTTPS", false, "HTTPS", true},
		{"proxy says http", false, "http", false},
		{"chained, client hop first", false, "https, http", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "http://example.com/"
			if tc.tls {
				target = "https://example.com/"
			}
			req := httptest.NewRequest("GET", target, nil)
			if tc.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			if got := IsHTTPS(req); got != tc.want {
				t.Errorf("IsHTTPS = %v, want %v", got, tc.want)
			}
		})
	}
}

// Over HTTPS every cookie Loupe sets is Secure; over plain HTTP none are,
// or the browser would drop them and the visitor could never be cleared.
func TestCookiesSecureOnlyOverHTTPS(t *testing.T) {
	m := New("test-secret", "waf_pass", 3600)
	for _, https := range []bool{true, false} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "TestBrowser")
		if https {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		for name, issue := range map[string]func(http.ResponseWriter){
			"clearance": func(w http.ResponseWriter) { m.IssueWithProfile(w, "1.2.3.4", req, "") },
			"probe":     func(w http.ResponseWriter) { m.IssueProbe(w, req) },
			"clear":     func(w http.ResponseWriter) { m.Clear(w, req) },
		} {
			rr := httptest.NewRecorder()
			issue(rr)
			cs := rr.Result().Cookies()
			if len(cs) != 1 {
				t.Fatalf("%s: %d cookies set, want 1", name, len(cs))
			}
			if cs[0].Secure != https {
				t.Errorf("%s over https=%v: Secure = %v", name, https, cs[0].Secure)
			}
		}
	}
}
