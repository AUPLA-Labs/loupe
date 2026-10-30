package handler

import (
	"encoding/json"
	"html/template"
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
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

const verifyTestIP = "1.2.3.4"

func testVerifyHandler(t *testing.T) *Handler {
	t.Helper()
	blocked, err := template.New("blocked").Parse("<p>blocked</p>")
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{
		blockedTpl: blocked,
		cfg: &config.Config{
			HMACSecret:    "test-hmac-secret",
			ChallengePath: "/loupe/challenge",
			VerifyPath:    "/loupe/verify",
		},
		lumenCheck:  lumen.NewVerifier(2),
		cookies:     cookie.New("test-secret", "waf_pass", 3600),
		offenders:   offender.New(5, time.Minute),
		escalations: offender.NewEscalations(),
		reputation:  testReputationStore(t),
		proofs:      proof.NewStore(100),
		prismPath:   "/loupe/prism",
	}
}

// cleanSignals is a plausible desktop-browser signal set that scores below
// scoreSuspicious, i.e. a genuine pass.
const cleanSignals = `{"mouseMoved":true,"movementDeltaSeen":true,"mouseJitter":12,"velocityVariance":0.4,` +
	`"firstInteractionMs":900,"pageOpenMs":2500,"solveTimeMs":2500,"screenW":1920,"screenH":1080,` +
	`"availW":1920,"availH":1040,"colorDepth":24,"outerWidth":1920,"outerHeight":1040,"innerHeight":900,` +
	`"hasFocus":true,"timezone":"Europe/Berlin","platform":"Linux x86_64","language":"en-US",` +
	`"languages":"en-US,en","hardwareConcurrency":8,"deviceMemory":8,"webglRenderer":"ANGLE (NVIDIA)",` +
	`"rafVariance":2.5,"manual":false}`

// postVerify answers a fresh proof challenge correctly, as the challenge
// page does, alongside signals.
func postVerify(t *testing.T, h *Handler, signals string, accept string) *httptest.ResponseRecorder {
	t.Helper()
	sp := issueAnswerable(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields)
	return postVerifyRaw(h, sp.ID, sealAnswered(t, sp, signals), accept)
}

func postVerifyRaw(h *Handler, proofID, sealed, accept string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Set("proof", proofID)
	form.Set("sealed", sealed)
	form.Set("return", "/dest")
	r := httptest.NewRequest(http.MethodPost, "/loupe/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	r.RemoteAddr = verifyTestIP + ":1234"
	w := httptest.NewRecorder()
	h.serveVerify(w, r)
	return w
}

func decodeVerdict(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json (status %d, body %q)", ct, w.Code, w.Body.String())
	}
	var v map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("bad JSON body %q: %v", w.Body.String(), err)
	}
	return v
}

func TestServeVerify_JSONPassIssuesCookie(t *testing.T) {
	h := testVerifyHandler(t)
	w := postVerify(t, h, cleanSignals, "application/json")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	v := decodeVerdict(t, w)
	if v["action"] != "pass" || v["url"] != "/dest" {
		t.Errorf("verdict = %v, want action=pass url=/dest", v)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("a pass must issue the clearance cookie")
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestServeVerify_PlainFormPostStillRedirects(t *testing.T) {
	h := testVerifyHandler(t)
	w := postVerify(t, h, cleanSignals, "text/html,application/xhtml+xml")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for a client that did not ask for JSON", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/dest" {
		t.Errorf("Location = %q, want /dest", loc)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Error("a pass must issue the clearance cookie")
	}
}

// A further challenge must come back as "redirect", never "pass": the page
// only shows "Verified!" for a pass.
func TestServeVerify_JSONEscalationIsNotAPass(t *testing.T) {
	h := testVerifyHandler(t)
	h.escalations.Require(verifyTestIP, tier.SingleClick, time.Minute)
	// An auto challenge from an IP that must do the manual one → manual_required.
	w := postVerify(t, h, cleanSignals, "application/json")

	v := decodeVerdict(t, w)
	if v["action"] != "redirect" {
		t.Errorf("action = %q, want redirect", v["action"])
	}
	if !strings.HasPrefix(v["url"], "/loupe/challenge?return=") || !strings.HasSuffix(v["url"], "&m=1") {
		t.Errorf("url = %q, want the manual challenge", v["url"])
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("an escalation must not issue the clearance cookie")
	}
}

func TestServeVerify_JSONPrismEscalationIsNotAPass(t *testing.T) {
	h := testVerifyHandler(t)
	// Conclusive automation signals score at or above scoreBlock → prism.
	signals := `{"screenW":0,"screenH":0,"colorDepth":0,"outerWidth":0,"availW":0,"webglRenderer":"Google SwiftShader","rafVariance":0}`
	w := postVerify(t, h, signals, "application/json")

	v := decodeVerdict(t, w)
	if v["action"] != "redirect" || !strings.HasPrefix(v["url"], "/loupe/prism?return=") {
		t.Errorf("verdict = %v, want a redirect to the prism puzzle", v)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("an escalation must not issue the clearance cookie")
	}
}

// Failures that are not redirects keep their HTML/text responses so the page
// can show the blocked page or its error message.
func TestServeVerify_JSONFailuresAreNotJSON(t *testing.T) {
	h := testVerifyHandler(t)

	w := postVerify(t, h, `{"webdriver":true}`, "application/json")
	if w.Code != http.StatusForbidden || strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Errorf("webdriver: status=%d type=%q, want 403 non-JSON", w.Code, w.Header().Get("Content-Type"))
	}

	w = postVerify(t, h, strings.TrimSuffix(cleanSignals, "}")+`,"lumen":null}`, "application/json")
	if w.Code != http.StatusForbidden || strings.Contains(w.Header().Get("Content-Type"), "json") {
		t.Errorf("no Lumen answer: status=%d type=%q, want 403 non-JSON", w.Code, w.Header().Get("Content-Type"))
	}
}
