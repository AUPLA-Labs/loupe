package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/lumen"
	"github.com/AUPLA-Labs/loupe/internal/proof"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// testLumen is a Lumen challenge cheap enough to brute-force in tests.
var testLumen = lumen.ParamsFor(lumen.Standard, lumen.Base{Work: 400, MemoryMB: 1, MaxMemoryMB: 1, MaxLevel: lumen.MaxLevel})

// issueAnswerable issues a challenge and backdates it past pulseMinAnswer,
// so tests that are not about timing don't trip result_too_fast.
func issueAnswerable(t *testing.T, h *Handler, ip string, kind proof.Kind, fields []string) *proof.Spec {
	t.Helper()
	return issueAnswerableOpts(t, h, ip, kind, fields, false)
}

func issueAnswerableOpts(t *testing.T, h *Handler, ip string, kind proof.Kind, fields []string, manual bool) *proof.Spec {
	t.Helper()
	ttl := pulseProofTTL
	if kind == proof.KindChallenge {
		ttl = challengeProofTTL
	}
	lp := testLumen
	sp, err := h.proofs.Issue(ip, kind, fields, ttl, proof.Options{Lumen: &lp, Manual: manual})
	if err != nil {
		t.Fatal(err)
	}
	sp.Issued = sp.Issued.Add(-time.Second)
	return sp
}

// solveLumen answers sp's Lumen challenge the way proof.js does.
func solveLumen(t *testing.T, sp *proof.Spec) lumen.Answer {
	t.Helper()
	a, ok := lumen.Solve(*sp.Client().Lumen)
	if !ok {
		t.Fatal("no Lumen solution found")
	}
	return a
}

// sealAnswered parses signalsJSON, adds the layout, colour and Lumen answers
// a real browser would produce, and seals it for sp. A "lumen" key in
// signalsJSON replaces the Lumen answer; null leaves it out.
func sealAnswered(t *testing.T, sp *proof.Spec, signalsJSON string) string {
	t.Helper()
	sig := map[string]interface{}{}
	if err := json.Unmarshal([]byte(signalsJSON), &sig); err != nil {
		t.Fatal(err)
	}
	if _, ok := sig["fp"]; !ok {
		sig["fp"] = cleanFP(t)
	}
	if l, ok := sig[proof.FieldLumen]; !ok {
		sig[proof.FieldLumen] = solveLumen(t, sp).Wire()
	} else if l == nil {
		delete(sig, proof.FieldLumen)
	}
	var rects []interface{}
	for _, b := range sp.Boxes {
		r := b.Expected(sp.ContainerW)
		rects = append(rects, []interface{}{r.X, r.Y, r.W, r.H})
	}
	c := sp.Color.RGB()
	sig[proof.FieldRects] = rects
	sig[proof.FieldColor] = fmt.Sprintf("rgb(%d, %d, %d)", c[0], c[1], c[2])
	return sealRaw(t, sp, sig)
}

func sealRaw(t *testing.T, sp *proof.Spec, sig map[string]interface{}) string {
	t.Helper()
	sealed, err := sp.Seal(sig)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

const cleanPulseSignals = `{"colorDepth":24,"languages":"en-US"}`

func postPulseResult(t *testing.T, h *Handler, ip, token, sealed string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	form.Set("sealed", sealed)
	form.Set("return", "/")
	r := httptest.NewRequest(http.MethodPost, "/loupe/pulse/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = ip + ":1234"
	r.AddCookie(&http.Cookie{Name: "loupe_probe", Value: "1"})
	w := httptest.NewRecorder()
	h.servePulseResult(w, r)
	return w
}

func TestPulseResult_AnsweredProofPasses(t *testing.T) {
	h := testPulseResultHandler(t)
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealAnswered(t, sp, cleanPulseSignals))
	if !strings.Contains(w.Body.String(), `"action":"pass"`) {
		t.Fatalf("body = %q, want pass", w.Body.String())
	}
}

// The attack proof-of-execution closes: a client that never ran the page posts a
// canned, unsealed signal blob.
func TestPulseResult_CannedBlobIsNotAPass(t *testing.T) {
	h := testPulseResultHandler(t)
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	canned := base64.StdEncoding.EncodeToString([]byte(cleanPulseSignals))
	w := postPulseResult(t, h, "1.2.3.4", sp.ID, canned)
	if strings.Contains(w.Body.String(), `"action":"pass"`) || len(w.Result().Cookies()) != 0 {
		t.Fatalf("canned blob passed: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "m=1") {
		t.Errorf("body = %q, want a manual challenge", w.Body.String())
	}
}

func TestPulseResult_TokenIsSingleUse(t *testing.T) {
	h := testPulseResultHandler(t)
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	sealed := sealAnswered(t, sp, cleanPulseSignals)
	if w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealed); !strings.Contains(w.Body.String(), `"action":"pass"`) {
		t.Fatalf("first answer: %q", w.Body.String())
	}
	if w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealed); w.Code != http.StatusForbidden {
		t.Errorf("replayed answer status = %d, want 403", w.Code)
	}
}

func TestPulseResult_WrongLayoutForcesManual(t *testing.T) {
	h := testPulseResultHandler(t)
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	// What a DOM emulator without layout reports.
	zeros := make([]interface{}, len(sp.Boxes))
	for i := range zeros {
		zeros[i] = []interface{}{0, 0, 0, 0}
	}
	sig := map[string]interface{}{"colorDepth": 24, "languages": "en-US", proof.FieldRects: zeros, proof.FieldColor: "",
		proof.FieldLumen: solveLumen(t, sp).Wire()}
	w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealRaw(t, sp, sig))
	if strings.Contains(w.Body.String(), `"action":"pass"`) || !strings.Contains(w.Body.String(), "m=1") {
		t.Errorf("body = %q, want a manual challenge", w.Body.String())
	}
}

func TestPulseResult_TooFastIsNotAPass(t *testing.T) {
	h := testPulseResultHandler(t)
	sp, err := h.proofs.Issue("1.2.3.4", proof.KindPulse, pulseSignalFields, pulseProofTTL, proof.Options{Lumen: &testLumen})
	if err != nil {
		t.Fatal(err)
	}
	w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealAnswered(t, sp, cleanPulseSignals))
	if strings.Contains(w.Body.String(), `"action":"pass"`) {
		t.Errorf("an answer faster than pulseMinAnswer passed: %q", w.Body.String())
	}
}

func TestPulseResult_ChallengeKindIsRejected(t *testing.T) {
	h := testPulseResultHandler(t)
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindChallenge, challengeSignalFields)
	if w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealAnswered(t, sp, cleanPulseSignals)); w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a challenge-page token", w.Code)
	}
}

func TestReflexProofScore(t *testing.T) {
	h := testPulseResultHandler(t)
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, nil)
	sealed := sealAnswered(t, sp, `{}`)
	sig, err := sp.Unseal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if score, reasons := reflexProofScore(sp, sig, time.Second); score != 0 {
		t.Errorf("correct answer scored %d %v", score, reasons)
	}
	if score, _ := reflexProofScore(sp, sig, 0); score != 0 {
		t.Errorf("elapsed=0 must skip the timing check, scored %d", score)
	}
	if _, reasons := reflexProofScore(sp, sig, 10*time.Millisecond); !contains(reasons, "result_too_fast") {
		t.Errorf("reasons = %v, want result_too_fast", reasons)
	}
	if score, reasons := reflexProofScore(sp, map[string]interface{}{}, time.Second); score < 2*scoreBlock ||
		!contains(reasons, "proof_layout_mismatch") || !contains(reasons, "proof_color_mismatch") {
		t.Errorf("missing answers scored %d %v", score, reasons)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// signalKeys extracts the property names of the object literal that starts
// at marker in a template, so the field lists can't drift from the pages.
func signalKeys(t *testing.T, file, marker string) []string {
	t.Helper()
	b, err := staticFiles.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("%s: marker %q not found", file, marker)
	}
	var lines []string
	for _, line := range strings.Split(src[i+len(marker):], "\n") {
		if strings.TrimSpace(line) == "};" {
			break
		}
		lines = append(lines, line)
	}
	body := strings.Join(lines, "\n")
	re := regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*[:,]`)
	var keys []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		keys = append(keys, m[1])
	}
	sort.Strings(keys)
	return keys
}

func sortedCopy(xs []string) []string {
	out := append([]string{}, xs...)
	sort.Strings(out)
	return out
}

func TestSignalFieldListsMatchTemplates(t *testing.T) {
	cases := []struct {
		file, marker string
		list         []string
	}{
		{"pulse.html", "var sig = {", pulseSignalFields},
		{"challenge.html", "const signals = {", challengeSignalFields},
	}
	for _, c := range cases {
		got := signalKeys(t, c.file, c.marker)
		if len(got) < 20 {
			t.Fatalf("%s: extracted only %v — the parser no longer matches the template", c.file, got)
		}
		want := sortedCopy(c.list)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s sends %v\nbut the field list is %v", c.file, got, want)
		}
	}
}

func TestServeVerify_MissingOrReplayedProofFails(t *testing.T) {
	h := testVerifyHandler(t)
	sp := issueAnswerable(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields)
	sealed := sealAnswered(t, sp, cleanSignals)

	w := postVerifyRaw(h, "", sealed, "application/json")
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Errorf("no proof: status=%d, want 403 without a cookie", w.Code)
	}

	if w := postVerifyRaw(h, sp.ID, sealed, "application/json"); w.Code != http.StatusOK {
		t.Fatalf("first answer: status=%d body=%q", w.Code, w.Body.String())
	}
	if w := postVerifyRaw(h, sp.ID, sealed, "application/json"); w.Code != http.StatusForbidden {
		t.Errorf("replayed proof: status=%d, want 403", w.Code)
	}
}

func TestServeVerify_CannedBlobFails(t *testing.T) {
	h := testVerifyHandler(t)
	sp := issueAnswerable(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields)
	canned := base64.StdEncoding.EncodeToString([]byte(cleanSignals))
	w := postVerifyRaw(h, sp.ID, canned, "application/json")
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Errorf("canned blob: status=%d, want 403 without a cookie", w.Code)
	}
}

func TestServeVerify_WrongLayoutEscalatesToPrism(t *testing.T) {
	h := testVerifyHandler(t)
	sp := issueAnswerable(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields)
	sig := map[string]interface{}{}
	if err := json.Unmarshal([]byte(cleanSignals), &sig); err != nil {
		t.Fatal(err)
	}
	sig[proof.FieldLumen] = solveLumen(t, sp).Wire()
	w := postVerifyRaw(h, sp.ID, sealRaw(t, sp, sig), "application/json")
	v := decodeVerdict(t, w)
	if v["action"] != "redirect" || !strings.HasPrefix(v["url"], "/loupe/prism?return=") {
		t.Errorf("verdict = %v, want a redirect to the prism puzzle", v)
	}
}

// The per-challenge spec must reach the page as a JS object literal and
// proof.js must be inlined verbatim, not HTML-escaped.
func TestTemplatesEmbedProof(t *testing.T) {
	js, err := staticFiles.ReadFile("proof.js")
	if err != nil {
		t.Fatal(err)
	}
	h := testPulseResultHandler(t)
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)

	for _, file := range []string{"pulse.html", "challenge.html"} {
		tmpl, err := parsePage(file, file)
		if err != nil {
			t.Fatal(err)
		}
		var buf strings.Builder
		fpJS, err := staticFiles.ReadFile("fingerprint.js")
		if err != nil {
			t.Fatal(err)
		}
		data := map[string]interface{}{"ProofJS": template.JS(js), "FingerprintJS": template.JS(fpJS), "Proof": sp.Client(),
			"AutomationArtifactsJS": template.JS("[]"), "NativeFnNamesJS": template.JS("[]")}
		if err := tmpl.Execute(&buf, data); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		out := buf.String()
		if !strings.Contains(out, "<script>var LoupeFP = (function () {") && !strings.Contains(out, "<script>// Browser fingerprint collection") {
			t.Errorf("%s: fingerprint.js not inlined in its own script block", file)
		}
		if !strings.Contains(out, "var LoupeProof = (function () {") || !strings.Contains(out, "x ^= x << 13;") {
			t.Errorf("%s: proof.js not inlined verbatim", file)
		}
		if file == "pulse.html" && !strings.Contains(out, `var PROOF = {"id":"`+sp.ID+`"`) {
			i := strings.Index(out, "var PROOF")
			t.Errorf("pulse.html: PROOF not rendered as an object literal: %.120q", out[i:])
		}
		if file == "pulse.html" && !strings.Contains(out, `"l":{"p":[{"s":"`+sp.Lumen.Puzzles[0].Salt+`"`) {
			i := strings.Index(out, "var PROOF")
			t.Errorf("pulse.html: Lumen challenge not rendered inside PROOF: %.400q", out[i:])
		}
	}
}

func TestPulseResult_LumenRequired(t *testing.T) {
	h := testPulseResultHandler(t)
	other := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	foreign, _ := json.Marshal(solveLumen(t, other).Wire())
	cases := map[string]string{
		"missing": `{"lumen":null}`,
		"garbage": `{"lumen":"bm90LWx1bWVu"}`,
		"wrong":   `{"lumen":{"n":[0,0,0,0],"d":""}}`,
		// A correct answer to a different challenge.
		"foreign": `{"lumen":` + string(foreign) + `}`,
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
			w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealAnswered(t, sp, sig))
			if strings.Contains(w.Body.String(), `"action":"pass"`) || !strings.Contains(w.Body.String(), "m=1") {
				t.Errorf("body = %q, want a manual challenge", w.Body.String())
			}
		})
	}
}

// sealWithSpace seals a clean answer to sp whose proof-of-space digest is
// replaced by digest.
func sealWithSpace(t *testing.T, sp *proof.Spec, signalsJSON, digest string) string {
	t.Helper()
	a := solveLumen(t, sp)
	a.Digest = digest
	l, _ := json.Marshal(a.Wire())
	sig := strings.TrimSuffix(strings.TrimSpace(signalsJSON), "}")
	if sig != "{" {
		sig += ","
	}
	return sealAnswered(t, sp, sig+`"lumen":`+string(l)+`}`)
}

func TestPulseResult_SpaceShadowVsEnforced(t *testing.T) {
	bad := strings.Repeat("0", 64)
	for _, digest := range []string{bad, ""} {
		h := testPulseResultHandler(t)
		sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
		if w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealWithSpace(t, sp, cleanPulseSignals, digest)); !strings.Contains(w.Body.String(), `"action":"pass"`) {
			t.Errorf("shadow, digest %q: body = %q, want a pass (space failures only logged)", digest, w.Body.String())
		}

		h.cfg.Lumen.Enforce = true
		sp = issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
		w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealWithSpace(t, sp, cleanPulseSignals, digest))
		if strings.Contains(w.Body.String(), `"action":"pass"`) || !strings.Contains(w.Body.String(), "m=1") {
			t.Errorf("enforced, digest %q: body = %q, want a manual challenge", digest, w.Body.String())
		}
	}
}

func TestServeVerify_SpaceEnforced(t *testing.T) {
	h := testVerifyHandler(t)
	h.cfg.Lumen.Enforce = true
	sp := issueAnswerable(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields)
	w := postVerifyRaw(h, sp.ID, sealWithSpace(t, sp, cleanSignals, strings.Repeat("0", 64)), "application/json")
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Errorf("wrong space, enforced: status=%d, want 403 without a cookie", w.Code)
	}
}

// The downgrade the old proof-of-work allowed: the pulse page's cheaper
// proof-of-work redeemed at /loupe/verify. A Lumen answer belongs to its
// proof challenge, whose kind Consume checks.
func TestServeVerify_PulseChallengeNotRedeemable(t *testing.T) {
	h := testVerifyHandler(t)
	sp := issueAnswerable(t, h, verifyTestIP, proof.KindPulse, pulseSignalFields)
	w := postVerifyRaw(h, sp.ID, sealAnswered(t, sp, cleanSignals), "application/json")
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Errorf("pulse challenge at verify: status=%d, want 403 without a cookie", w.Code)
	}
}

// The manual flag lives in the spec: an escalated client answering an auto
// challenge is sent back to the manual one; answering a manual one passes.
func TestServeVerify_ManualFlagFromSpec(t *testing.T) {
	h := testVerifyHandler(t)
	h.escalations.Require(verifyTestIP, tier.SingleClick, time.Minute)

	sp := issueAnswerableOpts(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields, false)
	v := decodeVerdict(t, postVerifyRaw(h, sp.ID, sealAnswered(t, sp, cleanSignals), "application/json"))
	if v["action"] != "redirect" || !strings.Contains(v["url"], "m=1") {
		t.Errorf("auto spec while escalated: verdict = %v, want the manual challenge", v)
	}

	manual := strings.Replace(cleanSignals, `"manual":false`, `"manual":true,"clickTrusted":true,"firstDeliberateMs":1500`, 1)
	sp = issueAnswerableOpts(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields, true)
	v = decodeVerdict(t, postVerifyRaw(h, sp.ID, sealAnswered(t, sp, manual), "application/json"))
	if v["action"] != "pass" {
		t.Errorf("manual spec: verdict = %v, want a pass", v)
	}
}

// cleanFPJSON is what fingerprint.js sends from a real desktop Chrome 126
// on Linux. nav.ua is left empty so it fits any test request's UA (the
// ua_header_mismatch check skips an empty JS UA).
const cleanFPJSON = `{
	"v": 1,
	"canvas": ["a1b2", "a1b2"],
	"webgl": {"vendor": "Google Inc. (Intel)", "renderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)",
	          "params": {"MAX_TEXTURE_SIZE": 16384}, "ext": ["ANGLE_instanced_arrays"], "prec": [[127, 127, 23]], "render": "c3d4"},
	"fonts": ["Arial", "DejaVu Sans", "Liberation Sans"],
	"engine": {"err": "Cannot read properties of null (reading 'x')", "v8stack": true, "moz": false, "evalLen": 33},
	"features": {"findLast": true, "hasOwn": true, "structuredClone": true, "at": true, "toSorted": true,
	             "fromAsync": true, "withResolvers": true, "groupBy": true, "setUnion": true, "iterHelpers": true,
	             "regexpEscape": false, "promiseTry": false, "cssHas": true, "cssContainer": true,
	             "cssOklch": true, "cssTextWrapBalance": true},
	"intl": {"languages": ["en-US", "en"], "locale": "en-US", "timeZone": "Europe/Berlin"},
	"mq": {"pointerCoarse": false, "anyCoarse": false},
	"codecs": [["probably", true]],
	"nav": {"ua": "", "platform": "Linux x86_64", "hc": 8, "langs": "en-US,en", "maxTouchPoints": 0, "brave": false},
	"screen": {"w": 1920, "h": 1080},
	"iframe": {"ua": "", "platform": "Linux x86_64", "hc": 8, "webdriver": false},
	"integrity": {"getterNoThrow": [], "navOwnProps": [], "toStringNative": true},
	"cdp": false,
	"gpu": null, "audio": ["124.04", "124.04"], "uach": null, "voices": null, "devices": null, "navAsync": null,
	"worker": {"ua": "", "platform": "Linux x86_64", "hc": 8, "langs": "en-US,en"}
}`

func cleanFP(t *testing.T) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(cleanFPJSON), &m); err != nil {
		t.Fatal(err)
	}
	return m
}
