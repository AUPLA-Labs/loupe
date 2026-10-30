package handler

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/cookie"
	"github.com/AUPLA-Labs/loupe/internal/offender"
	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
)

const clearanceTestIP = "1.2.3.4"

func testClearanceHandler(t *testing.T) *Handler {
	t.Helper()
	return testClearanceHandlerWith(t, config.ClearanceBudgetConfig{DocRate: 0.5, DocBurst: 300, AllRate: 5, AllBurst: 3000})
}

func testClearanceHandlerWith(t *testing.T, b config.ClearanceBudgetConfig) *Handler {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content")) //nolint:errcheck
	}))
	t.Cleanup(backend.Close)
	target, _ := url.Parse(backend.URL)
	return &Handler{
		cfg:            &config.Config{HMACSecret: "test-hmac-secret", ChallengePath: "/loupe/challenge"},
		cookies:        cookie.New("test-secret", "waf_pass", 3600),
		offenders:      offender.New(5, time.Minute),
		reputation:     testReputationStore(t),
		clearanceDocRL: ratelimit.New(b.DocRate, b.DocBurst),
		clearanceAllRL: ratelimit.New(b.AllRate, b.AllBurst),
		clearance:      newClearanceState(),
		proxy:          httputil.NewSingleHostReverseProxy(target),
		fontsPath:      "/loupe/fonts/",
	}
}

// chromeNav is a Chrome 131 top-level navigation with the headers real
// Chrome sends.
func chromeNav() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/page", nil)
	r.RemoteAddr = clearanceTestIP + ":1234"
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "de-AT,de;q=0.9")
	r.Header.Set("Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24"`)
	r.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	r.Header.Set("Sec-CH-UA-Mobile", "?0")
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	return r
}

// chromeImage is a same-origin image subresource from the same browser.
func chromeImage() *http.Request {
	r := chromeNav()
	r.URL.Path = "/logo.png"
	r.Header.Set("Accept", "image/avif,image/webp,*/*")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Sec-Fetch-Mode", "no-cors")
	r.Header.Set("Sec-Fetch-Dest", "image")
	return r
}

// issueClearance issues a cookie as the probe-result POST from the browser
// described by issuing would, and returns it.
func issueClearance(t *testing.T, h *Handler, issuing *http.Request) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	h.cookies.Issue(w, clearanceTestIP, issuing)
	return w.Result().Cookies()
}

func withCookies(r *http.Request, cs []*http.Cookie) *http.Request {
	for _, c := range cs {
		r.AddCookie(c)
	}
	return r
}

func serve(h *Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func checkOf(t *testing.T, h *Handler, r *http.Request) ([]string, bool) {
	t.Helper()
	c, ok := h.cookies.Check(r, clearanceTestIP)
	if !ok {
		t.Fatal("cookie should be valid")
	}
	return h.checkClearance(r, c)
}

func TestClearance_SameBrowserPasses(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())
	for _, r := range []*http.Request{chromeNav(), chromeImage()} {
		w := serve(h, withCookies(r, cs))
		if w.Code != http.StatusOK || w.Body.String() != "content" {
			t.Errorf("%s: status %d body %q, want proxied content", r.URL.Path, w.Code, w.Body.String())
		}
	}
}

// The hand-off revalidation exists to catch: a browser earned the cookie, a
// plain HTTP client with the same UA uses it.
func TestClearance_HandOffToScriptIsHostile(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())

	script := httptest.NewRequest(http.MethodGet, "/page", nil)
	script.RemoteAddr = clearanceTestIP + ":1234"
	script.Header.Set("User-Agent", chromeNav().UserAgent())
	script = withCookies(script, cs)

	reasons, hostile := checkOf(t, h, script)
	if !hostile || len(reasons) != 1 || reasons[0] != "clearance_sec_fetch_missing" {
		t.Errorf("reasons=%v hostile=%v, want hostile clearance_sec_fetch_missing", reasons, hostile)
	}

	c, _ := h.cookies.Check(script, clearanceTestIP)
	h.dropClearance(httptest.NewRecorder(), script, c, reasons, hostile)
	if reasons, _ := checkOf(t, h, withCookies(chromeNav(), cs)); len(reasons) == 0 || reasons[0] != "clearance_revoked" {
		t.Errorf("after a hostile drop the cookie ID must be revoked everywhere, got %v", reasons)
	}
	if p := h.reputation.IPPressure(clearanceTestIP); p <= 0 {
		t.Errorf("hostile drop must record pressure, got %v", p)
	}
}

func TestClearance_MissingClientHintsOnNavigationIsHostile(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())
	r := chromeNav()
	r.Header.Del("Sec-CH-UA")
	if reasons, hostile := checkOf(t, h, withCookies(r, cs)); !hostile || reasons[0] != "clearance_sec_ch_ua_missing" {
		t.Errorf("reasons=%v hostile=%v", reasons, hostile)
	}
}

// Client hints are only enforced on navigations; a subresource that lacks
// them must not lose the page its cookie.
func TestClearance_SubresourceWithoutClientHintsPasses(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())
	r := chromeImage()
	r.Header.Del("Sec-CH-UA")
	r.Header.Del("Accept-Language")
	if reasons, _ := checkOf(t, h, withCookies(r, cs)); len(reasons) != 0 {
		t.Errorf("reasons=%v, want none", reasons)
	}
}

// A browser that never sent the header families at issuance (older Safari,
// Firefox without client hints) is never penalised for not sending them.
func TestClearance_BrowserWithoutHeaderFamiliesPasses(t *testing.T) {
	h := testClearanceHandler(t)
	old := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/page", nil)
		r.RemoteAddr = clearanceTestIP + ":1234"
		r.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1")
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Accept-Language", "en-GB")
		return r
	}
	cs := issueClearance(t, h, old())
	if reasons, _ := checkOf(t, h, withCookies(old(), cs)); len(reasons) != 0 {
		t.Errorf("reasons=%v, want none", reasons)
	}
}

func TestClearance_ShapeChangeIsSilentRecheck(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())
	r := chromeNav()
	r.Header.Set("Accept-Language", "en-US,en")
	reasons, hostile := checkOf(t, h, withCookies(r, cs))
	if hostile || len(reasons) != 1 || reasons[0] != "clearance_shape_changed" {
		t.Errorf("reasons=%v hostile=%v, want non-hostile clearance_shape_changed", reasons, hostile)
	}

	// Through ServeHTTP the cookie is cleared, not revoked, and no pressure
	// is recorded. (The rest of the pipeline needs an ASN DB, so this only
	// exercises the drop itself.)
	w := httptest.NewRecorder()
	c, _ := h.cookies.Check(withCookies(r, cs), clearanceTestIP)
	h.dropClearance(w, r, c, reasons, hostile)
	if got := w.Result().Cookies(); len(got) != 1 || got[0].MaxAge >= 0 {
		t.Errorf("Set-Cookie = %+v, want the cookie expired", got)
	}
	if h.clearance.isRevoked(c.ID) {
		t.Error("a shape change must not revoke the cookie ID")
	}
	if p := h.reputation.IPPressure(clearanceTestIP); p != 0 {
		t.Errorf("a shape change must not record pressure, got %v", p)
	}
}

// A browser whose probe fetch and navigations differ in shape would loop
// through the pulse forever; the same mismatch on a second, fresh cookie is
// let through. Replaying one cookie never is.
func TestClearance_ShapeLoopGuard(t *testing.T) {
	h := testClearanceHandler(t)
	fetchReq := chromeNav()
	fetchReq.Header.Set("Accept-Language", "en")
	nav := func() *http.Request { return chromeNav() } // primary language "de"

	first := issueClearance(t, h, fetchReq)
	if reasons, _ := checkOf(t, h, withCookies(nav(), first)); len(reasons) == 0 {
		t.Fatal("first mismatch must be rechecked")
	}
	if reasons, _ := checkOf(t, h, withCookies(nav(), first)); len(reasons) == 0 {
		t.Error("replaying the same cookie must never trip the loop guard")
	}
	second := issueClearance(t, h, fetchReq)
	if reasons, _ := checkOf(t, h, withCookies(nav(), second)); len(reasons) != 0 {
		t.Errorf("the same mismatch on a fresh cookie must pass, got %v", reasons)
	}
}

func TestClearance_DocumentBudget(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())
	for i := 0; i < 300; i++ {
		if reasons, _ := checkOf(t, h, withCookies(chromeNav(), cs)); len(reasons) != 0 {
			t.Fatalf("request %d within budget rejected: %v", i, reasons)
		}
	}
	reasons, hostile := checkOf(t, h, withCookies(chromeNav(), cs))
	if !hostile || len(reasons) != 1 || reasons[0] != "clearance_budget_exceeded" {
		t.Errorf("reasons=%v hostile=%v, want hostile clearance_budget_exceeded", reasons, hostile)
	}
}

func TestClearance_ConfiguredDocumentBudget(t *testing.T) {
	h := testClearanceHandlerWith(t, config.ClearanceBudgetConfig{DocRate: 0.5, DocBurst: 2, AllRate: 5, AllBurst: 3000})
	cs := issueClearance(t, h, chromeNav())
	for i := 0; i < 2; i++ {
		if reasons, _ := checkOf(t, h, withCookies(chromeNav(), cs)); len(reasons) != 0 {
			t.Fatalf("request %d within budget rejected: %v", i, reasons)
		}
	}
	reasons, hostile := checkOf(t, h, withCookies(chromeNav(), cs))
	if !hostile || len(reasons) != 1 || reasons[0] != "clearance_budget_exceeded" {
		t.Errorf("reasons=%v hostile=%v, want hostile clearance_budget_exceeded", reasons, hostile)
	}
}

func TestClearance_SubresourcesDoNotSpendDocumentBudget(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())
	for i := 0; i < 300+50; i++ {
		if reasons, _ := checkOf(t, h, withCookies(chromeImage(), cs)); len(reasons) != 0 {
			t.Fatalf("subresource %d rejected: %v", i, reasons)
		}
	}
	if reasons, _ := checkOf(t, h, withCookies(chromeNav(), cs)); len(reasons) != 0 {
		t.Errorf("navigation after subresources rejected: %v", reasons)
	}
}

// The no-cookies backstop explains itself once and then lets the next
// navigation be challenged again; it used to keep the whole address on the
// explanation page until the streak expired, with no way to earn a clearance.
func TestNoCookiesBackstopIsNotSticky(t *testing.T) {
	h := testClearanceHandler(t)
	h.unverifiedTpl = mustParseTestTemplate(t, "unverified", `no cookies`)
	for i := 0; i < noCookiesThreshold; i++ {
		h.offenders.IncrAnsweredNoClearance(clearanceTestIP)
	}
	if w := serve(h, chromeNav()); w.Code != http.StatusForbidden || w.Body.String() != "no cookies" {
		t.Fatalf("first navigation: status %d body %q, want the no-cookies page", w.Code, w.Body.String())
	}
	if h.shouldServeNoCookies(clearanceTestIP) {
		t.Error("backstop still armed after explaining itself once")
	}
}

// Safari fetches service worker scripts without Fetch Metadata; that must
// not count as a hand-off, but the exemption must not cover other requests.
func TestClearance_ServiceWorkerScriptExempt(t *testing.T) {
	h := testClearanceHandler(t)
	cs := issueClearance(t, h, chromeNav())

	sw := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = clearanceTestIP + ":1234"
		r.Header.Set("User-Agent", chromeNav().UserAgent())
		r.Header.Set("Service-Worker", "script")
		return withCookies(r, cs)
	}
	if reasons, _ := checkOf(t, h, sw("/index.php/apps/files/preview-service-worker.js")); len(reasons) != 0 {
		t.Errorf("service worker script: reasons=%v, want none", reasons)
	}
	if reasons, hostile := checkOf(t, h, sw("/page")); !hostile || len(reasons) == 0 || reasons[0] != "clearance_sec_fetch_missing" {
		t.Errorf("non-script path with Service-Worker header: reasons=%v hostile=%v, want hostile", reasons, hostile)
	}
}
