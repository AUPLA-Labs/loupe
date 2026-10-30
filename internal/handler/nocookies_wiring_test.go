package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/cookie"
	"github.com/AUPLA-Labs/loupe/internal/lumen"
	"github.com/AUPLA-Labs/loupe/internal/offender"
	"github.com/AUPLA-Labs/loupe/internal/proof"
	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

// minimalTestConfig returns the smallest *config.Config servePulseResult
// needs. HMACSecret is used for the clearance cookie's profile hash on a pass.
func minimalTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{HMACSecret: "test-hmac-secret"}
}

// testReputationStore returns a real, empty *reputation.Store. servePulseResult
// only reaches h.reputation.* calls after the HasProbe check (and, for the
// scores these tests produce, not even then — see clientASN's nil-asnDB
// guard in escalation_rule.go), but a real store keeps this handler usable
// for the whole function rather than just the branch under test.
func testReputationStore(t *testing.T) *reputation.Store {
	t.Helper()
	return reputation.New(reputation.Config{})
}

func testPulseResultHandler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{
		cfg:         minimalTestConfig(t),
		cookies:     cookie.New("test-secret", "waf_pass", 3600),
		offenders:   offender.New(5, time.Minute),
		escalations: offender.NewEscalations(),
		reputation:  testReputationStore(t),
		proofs:      proof.NewStore(100),
		lumenCheck:  lumen.NewVerifier(2),
		// noCookiesPath must be a non-empty value distinct from the rest of a
		// JSON response body, or strings.Contains(body, h.noCookiesPath) is
		// vacuously true (empty string is a substring of everything) and the
		// assertions below pass/fail regardless of actual behavior.
		noCookiesPath: "/loupe/no-cookies",
	}
}

func TestServePulseResult_MissingProbeCookieRedirectsToNoCookies(t *testing.T) {
	h := testPulseResultHandler(t)
	ipKey := "1.2.3.4"
	sp := issueAnswerable(t, h, ipKey, proof.KindPulse, pulseSignalFields)

	form := url.Values{}
	form.Set("token", sp.ID)
	form.Set("sealed", sealAnswered(t, sp, "{}"))
	form.Set("return", "/")
	r := httptest.NewRequest(http.MethodPost, "/loupe/pulse/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ipKey + ":1234"
	// Deliberately no probe cookie attached.

	w := httptest.NewRecorder()
	h.servePulseResult(w, r)

	if !strings.Contains(w.Body.String(), h.noCookiesPath) {
		t.Errorf("body = %q, want it to contain noCookiesPath %q", w.Body.String(), h.noCookiesPath)
	}
	if got, want := len(w.Result().Cookies()), 0; got != want {
		t.Errorf("clearance cookie should not be issued when the probe cookie is missing, got %d Set-Cookie headers", got)
	}
}

func TestServePulseResult_WithProbeCookieDoesNotRedirectToNoCookies(t *testing.T) {
	h := testPulseResultHandler(t)
	ipKey := "1.2.3.4"
	sp := issueAnswerable(t, h, ipKey, proof.KindPulse, pulseSignalFields)

	form := url.Values{}
	form.Set("token", sp.ID)
	form.Set("sealed", sealAnswered(t, sp, "{}"))
	form.Set("return", "/")
	r := httptest.NewRequest(http.MethodPost, "/loupe/pulse/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ipKey + ":1234"
	r.AddCookie(&http.Cookie{Name: "loupe_probe", Value: "1"})

	w := httptest.NewRecorder()
	h.servePulseResult(w, r)

	if strings.Contains(w.Body.String(), h.noCookiesPath) {
		t.Errorf("body = %q, should not redirect to no-cookies when the probe cookie is present", w.Body.String())
	}
}

// testPrismVerifyHandler returns the smallest *Handler that servePrismVerify's
// token=="" failure branch (prism_no_token) can run against without
// panicking: h.ipKey needs no fields, h.emit is safe with h.store == nil,
// h.offenders.Fail needs a real *offender.Tracker, and h.reputation.Record
// needs a real *reputation.Store (h.clientASN nil-guards h.asnDB itself).
func testPrismVerifyHandler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{
		offenders:  offender.New(5, time.Minute),
		reputation: testReputationStore(t),
	}
}

// TestServePrismVerify_NoTokenDoesNotIncrementAnsweredNoClearance is the
// regression test for the headline bug this fix round addresses: the
// answered-without-clearance counter used to increment as soon as a
// challenge answer arrived, before it was judged correct or clearance was
// actually issued. A missing-token request never reaches the point of
// answering (or clearance) at all, so it must leave the counter at 0.
func TestServePrismVerify_NoTokenDoesNotIncrementAnsweredNoClearance(t *testing.T) {
	h := testPrismVerifyHandler(t)
	ipKey := "1.2.3.4"

	form := url.Values{}
	form.Set("token", "") // deliberately missing/empty
	form.Set("x", "10")
	form.Set("y", "10")
	form.Set("return", "/")
	r := httptest.NewRequest(http.MethodPost, "/loupe/prism/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ipKey + ":1234"

	w := httptest.NewRecorder()
	h.servePrismVerify(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (prism_no_token failure path)", w.Code, http.StatusForbidden)
	}
	if got := h.offenders.AnsweredNoClearanceCount(ipKey); got != 0 {
		t.Errorf("AnsweredNoClearanceCount after a failed (no-token) prism verify = %d, want 0", got)
	}
}

// TestServeHTTP_NoJSPathIsRateLimited is the regression test for the other
// important finding in this fix round: /loupe/no-js and
// /loupe/no-cookies used to have no rate limiter in front of them at
// all, unlike every other endpoint that calls h.emit. Both cases now reuse
// h.pulseRL, so driving that limiter to exhaustion must yield a 429 rather
// than another rendered page.
func TestServeHTTP_NoJSPathIsRateLimited(t *testing.T) {
	tpl := mustParseTestTemplate(t, "unverified", `<html><body>unverified</body></html>`)
	h := &Handler{
		cfg:           &config.Config{},
		noJSPath:      "/loupe/no-js",
		unverifiedTpl: tpl,
		offenders:     offender.New(5, time.Minute),
		pulseRL:       ratelimit.New(0, 0), // burst=0: even the first Allow() call for a new key succeeds, the second never does
	}

	r1 := httptest.NewRequest(http.MethodGet, "/loupe/no-js", nil)
	r1.RemoteAddr = "9.9.9.9:1234"
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)
	if w1.Code != http.StatusForbidden {
		t.Fatalf("first request status = %d, want %d (no-js page)", w1.Code, http.StatusForbidden)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/loupe/no-js", nil)
	r2.RemoteAddr = "9.9.9.9:1234"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request status = %d, want %d (rate limited)", w2.Code, http.StatusTooManyRequests)
	}
}

func TestServePulseResult_PairsAnsweredWithIncrAnsweredNoClearance(t *testing.T) {
	h := testPulseResultHandler(t)
	ipKey := "1.2.3.4"
	sp := issueAnswerable(t, h, ipKey, proof.KindPulse, pulseSignalFields)

	form := url.Values{}
	form.Set("token", sp.ID)
	// colorDepth and languages are set so reflexProbeScore scores this as a
	// clean pass (score 0): an empty {} signals object actually scores 4
	// (low_color_depth + no_languages), which is >= scoreSuspicious and
	// would exercise the escalation branch instead of the clean-pass branch
	// this test means to cover — the one place IncrAnsweredNoClearance is
	// now called after the Fix 1 relocation.
	form.Set("sealed", sealAnswered(t, sp, `{"colorDepth":24,"languages":"en-US"}`))
	form.Set("return", "/")
	r := httptest.NewRequest(http.MethodPost, "/loupe/pulse/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ipKey + ":1234"
	r.AddCookie(&http.Cookie{Name: "loupe_probe", Value: "1"})

	w := httptest.NewRecorder()
	h.servePulseResult(w, r)

	if !strings.Contains(w.Body.String(), `"action":"pass"`) {
		t.Fatalf("body = %q, want the clean-pass branch (action=pass) so this test actually covers the IncrAnsweredNoClearance call site", w.Body.String())
	}
	if got := h.offenders.AnsweredNoClearanceCount(ipKey); got != 1 {
		t.Errorf("AnsweredNoClearanceCount after one servePulseResult call = %d, want 1", got)
	}
}

// A pulse answer whose fingerprint readouts are randomised is sent to the
// "couldn't verify" page instead of being scored, and earns no clearance.
func TestServePulseResult_ReadoutNoiseGoesToUnverified(t *testing.T) {
	h := testPulseResultHandler(t)
	h.unverifiedPath = "/loupe/unverified"
	ipKey := "1.2.3.4"
	sp := issueAnswerable(t, h, ipKey, proof.KindPulse, pulseSignalFields)

	fp := fpWith(t, func(m map[string]interface{}) { m["canvas"] = []interface{}{"aaaa", "bbbb"} })
	sig, err := json.Marshal(map[string]interface{}{"colorDepth": 24, "languages": "en-US", "fp": fp})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("token", sp.ID)
	form.Set("sealed", sealAnswered(t, sp, string(sig)))
	form.Set("return", "/page")
	r := httptest.NewRequest(http.MethodPost, "/loupe/pulse/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ipKey + ":1234"
	r.AddCookie(&http.Cookie{Name: "loupe_probe", Value: "1"})
	w := httptest.NewRecorder()
	h.servePulseResult(w, r)

	if body := w.Body.String(); !strings.Contains(body, `"action":"unverifiable"`) || !strings.Contains(body, "/loupe/unverified?return=%2Fpage") {
		t.Errorf("body = %q", body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "waf_pass" {
			t.Error("clearance issued to an unverifiable answer")
		}
	}
}
