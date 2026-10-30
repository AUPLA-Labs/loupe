package handler

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/lumen"
	"github.com/AUPLA-Labs/loupe/internal/proof"
)

func TestLumenDemandFor(t *testing.T) {
	cases := map[int]lumen.Level{
		0:                   lumen.Glow,
		scoreSuspicious - 1: lumen.Glow,
		scoreSuspicious:     lumen.Bright,
		scoreBlock - 1:      lumen.Bright,
		scoreBlock:          lumen.Intense,
		2*scoreBlock - 1:    lumen.Intense,
		2 * scoreBlock:      lumen.Blinding,
	}
	for score, want := range cases {
		if got := lumenDemandFor(score); got != want {
			t.Errorf("lumenDemandFor(%d) = %v, want %v", score, got, want)
		}
	}
}

func TestLumenParams_AnswerDemandRaisesNextLevel(t *testing.T) {
	h := testLumenHandler(t, true)
	h.demandLumen("1.2.3.4", scoreBlock)
	if p := h.lumenParams(lumenRequest("1.2.3.4"), "1.2.3.4", false); p.Level != lumen.Intense {
		t.Errorf("enforced: level %v, want intense", p.Level)
	}

	h = testLumenHandler(t, false)
	h.demandLumen("1.2.3.4", scoreBlock)
	if p := h.lumenParams(lumenRequest("1.2.3.4"), "1.2.3.4", false); p.Level != lumen.Standard || p.Scored != lumen.Intense {
		t.Errorf("shadow: %+v, want Standard served, scored intense", p)
	}
}

func TestLumenPrismParams_Floor(t *testing.T) {
	h := testLumenHandler(t, true)
	if p := h.lumenPrismParams(lumenRequest("1.2.3.4"), "1.2.3.4"); p.Level != lumenPrismFloor {
		t.Errorf("clean client on prism: level %v, want %v", p.Level, lumenPrismFloor)
	}
	h.demandLumen("1.2.3.4", 2*scoreBlock)
	if p := h.lumenPrismParams(lumenRequest("1.2.3.4"), "1.2.3.4"); p.Level != lumen.Blinding {
		t.Errorf("demanded blinding on prism: level %v", p.Level)
	}

	h = testLumenHandler(t, false)
	if p := h.lumenPrismParams(lumenRequest("1.2.3.4"), "1.2.3.4"); p.Level != lumen.Standard || p.Scored != lumenPrismFloor {
		t.Errorf("shadow prism: %+v, want Standard served, scored %v", p, lumenPrismFloor)
	}
}

// The follow-up compares against the demand as the page would serve it, so
// a MaxLevel below the demand can't send a client round forever.
func TestLumenFollowup_RespectsMaxLevel(t *testing.T) {
	h := testLumenHandler(t, true)
	paid := lumen.ParamsFor(lumen.Bright, h.lumenBase(false))
	sp := &proof.Spec{Lumen: &lumen.Challenge{Params: paid}}
	if !h.lumenFollowup(sp, scoreBlock) {
		t.Error("bright paid, intense demanded: want a follow-up")
	}
	if h.lumenFollowup(sp, scoreSuspicious) {
		t.Error("bright paid, bright demanded: want none")
	}
	h.cfg.Lumen.MaxLevel = int(lumen.Bright)
	if h.lumenFollowup(sp, 2*scoreBlock) {
		t.Error("bright paid at max_level bright: want none")
	}
}

func testFollowupHandler(t *testing.T, enforce bool) *Handler {
	t.Helper()
	h := testVerifyHandler(t)
	def, err := config.LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Lumen = def.Lumen
	h.cfg.Lumen.Enforce = enforce
	return h
}

// issueAtLevel issues a manual challenge whose Lumen is recorded as level l
// but stays cheap enough to brute-force.
func issueAtLevel(t *testing.T, h *Handler, l lumen.Level) *proof.Spec {
	t.Helper()
	lp := testLumen
	lp.Level, lp.Scored = l, l
	sp, err := h.proofs.Issue(verifyTestIP, proof.KindChallenge, challengeSignalFields, challengeProofTTL, proof.Options{Lumen: &lp, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	sp.Issued = sp.Issued.Add(-time.Second)
	return sp
}

// A manual answer that scores suspicious but paid only Standard gets one
// more challenge at the level it demands; paying that, it passes.
func TestServeVerify_SuspiciousManualFollowup(t *testing.T) {
	suspicious := strings.Replace(cleanSignals, `"manual":false`,
		`"manual":true,"clickTrusted":true,"firstDeliberateMs":1500,"languageInconsistent":true`, 1)

	h := testFollowupHandler(t, true)
	sp := issueAtLevel(t, h, lumen.Standard)
	v := decodeVerdict(t, postVerifyRaw(h, sp.ID, sealAnswered(t, sp, suspicious), "application/json"))
	if v["action"] != "redirect" || !strings.Contains(v["url"], "m=1") {
		t.Fatalf("enforced, standard paid: verdict = %v, want the manual challenge again", v)
	}
	if got := lumen.Level(h.escalations.LumenDemand(verifyTestIP)); got != lumen.Bright {
		t.Errorf("demand = %v, want bright", got)
	}
	sp = issueAtLevel(t, h, lumen.Bright)
	if v := decodeVerdict(t, postVerifyRaw(h, sp.ID, sealAnswered(t, sp, suspicious), "application/json")); v["action"] != "pass" {
		t.Errorf("enforced, bright paid: verdict = %v, want a pass", v)
	}

	h = testFollowupHandler(t, false)
	sp = issueAtLevel(t, h, lumen.Standard)
	if v := decodeVerdict(t, postVerifyRaw(h, sp.ID, sealAnswered(t, sp, suspicious), "application/json")); v["action"] != "pass" {
		t.Errorf("shadow: verdict = %v, want a pass", v)
	}
}

func TestServeVerify_PrismEscalationDemandsLumen(t *testing.T) {
	h := testFollowupHandler(t, true)
	signals := `{"screenW":0,"screenH":0,"colorDepth":0,"outerWidth":0,"availW":0,"webglRenderer":"Google SwiftShader","rafVariance":0}`
	postVerify(t, h, signals, "application/json")
	if got := lumen.Level(h.escalations.LumenDemand(verifyTestIP)); got < lumen.Intense {
		t.Errorf("demand after a prism escalation = %v, want intense or more", got)
	}
}

const cleanPrismSignals = `{"screenW":1920,"screenH":1080,"languages":"en-US","dragDuration":800,"preDragTime":1500,"attempts":1}`

// postPrism answers a fresh Prism puzzle correctly. lumenID and answer are
// the Lumen form fields as the page sends them.
func postPrism(t *testing.T, h *Handler, lumenID, answer string) *httptest.ResponseRecorder {
	t.Helper()
	gaps := [prismNumGaps]prismGap{{100, 100}, {300, 100}, {200, 230}}
	token, err := buildPrismToken(1, gaps, 0, verifyTestIP, h.cfg.HMACSecret)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("token", token)
	form.Set("x", strconv.Itoa(gaps[0].X))
	form.Set("y", strconv.Itoa(gaps[0].Y))
	form.Set("return", "/dest")
	form.Set("signals", cleanPrismSignals)
	form.Set("lumen_id", lumenID)
	form.Set("lumen", answer)
	r := httptest.NewRequest(http.MethodPost, "/loupe/prism/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = verifyTestIP + ":1234"
	w := httptest.NewRecorder()
	h.servePrismVerify(w, r)
	return w
}

func issuePrismLumen(t *testing.T, h *Handler) (*proof.Spec, string) {
	t.Helper()
	lp := testLumen
	sp, err := h.proofs.Issue(verifyTestIP, proof.KindPrism, nil, prismTTL*time.Second, proof.Options{Lumen: &lp})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(solveLumen(t, sp).Wire())
	return sp, string(a)
}

func prismPassed(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusFound && w.Header().Get("Location") == "/dest" && len(w.Result().Cookies()) > 0
}

func TestPrismVerify_Lumen(t *testing.T) {
	h := testFollowupHandler(t, true)
	sp, answer := issuePrismLumen(t, h)
	if w := postPrism(t, h, sp.ID, answer); !prismPassed(w) {
		t.Errorf("solved puzzle and Lumen: status %d, location %q, want a pass", w.Code, w.Header().Get("Location"))
	}
	// Spent: the same answer can't be replayed.
	if w := postPrism(t, h, sp.ID, answer); w.Code != http.StatusForbidden {
		t.Errorf("replayed Lumen: status %d, want 403", w.Code)
	}

	noAnswer, _ := issuePrismLumen(t, h)
	foreignSp, _ := issuePrismLumen(t, h)
	_, foreign := issuePrismLumen(t, h)
	for name, c := range map[string][2]string{
		"missing":   {"", ""},
		"no answer": {noAnswer.ID, ""},
		"foreign":   {foreignSp.ID, foreign},
	} {
		if w := postPrism(t, h, c[0], c[1]); w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
			t.Errorf("enforced, %s: status %d, want 403 without a cookie", name, w.Code)
		}
	}

	// Pulse and challenge-page answers don't count on Prism.
	cp := issueAnswerable(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields)
	ca, _ := json.Marshal(solveLumen(t, cp).Wire())
	if w := postPrism(t, h, cp.ID, string(ca)); w.Code != http.StatusForbidden {
		t.Errorf("challenge-page Lumen on prism: status %d, want 403", w.Code)
	}

	// Shadow mode never fails a Prism answer over its Lumen.
	h = testFollowupHandler(t, false)
	if w := postPrism(t, h, "", ""); !prismPassed(w) {
		t.Errorf("shadow, no Lumen: status %d, want a pass", w.Code)
	}
}

func TestPrismTemplateEmbedsLumen(t *testing.T) {
	js, err := staticFiles.ReadFile("proof.js")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := parsePage("prism", "prism.html")
	if err != nil {
		t.Fatal(err)
	}
	h := testVerifyHandler(t)
	sp, _ := issuePrismLumen(t, h)
	var buf strings.Builder
	data := map[string]interface{}{"ProofJS": template.JS(js), "Lumen": sp.Client().Lumen, "LumenID": sp.ID,
		"GapsJSON": template.JS("[]"), "PieceW": 100, "PieceH": 100, "TabR": 18, "PieceX": 1, "PieceY": 1, "ImageID": 1}
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `var LUMEN = {"p":[{"s":"`+sp.Lumen.Puzzles[0].Salt+`"`) {
		i := strings.Index(out, "var LUMEN")
		t.Errorf("LUMEN not rendered as an object literal: %.200q", out[i:])
	}
	if !strings.Contains(out, `name="lumen_id" value="`+sp.ID+`"`) {
		t.Error("lumen_id field missing")
	}
	if !strings.Contains(out, "var LoupeProof = (function () {") {
		t.Error("proof.js not inlined")
	}
}
