package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/proof"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// Proof-of-execution wiring. See
// internal/proof for the challenge itself and proof.js for the client half.

const (
	// proofStoreMax bounds outstanding challenges. Issuance is rate limited
	// per client key, so this only matters under a distributed flood; at
	// roughly 1 KB per challenge it caps the store at ~50 MB.
	proofStoreMax = 50000

	// pulseProofTTL covers page load plus the interstitial's 500 ms budget,
	// with generous slack for slow networks.
	pulseProofTTL = 60 * time.Second

	// challengeProofTTL covers the challenge page's Lumen solve and, on the
	// single-click flow, the visitor's click, with slack for slow networks.
	challengeProofTTL = 5 * time.Minute

	// pulseMinAnswer is the fastest a real browser can answer the pulse
	// interstitial, measured server-side from issue to result: the page
	// waits for 32 animation frames (~89 ms even on a 360 Hz display) and
	// the result needs a network round trip on top. A faster answer means
	// the page's script never really ran.
	pulseMinAnswer = 80 * time.Millisecond
)

// pulseSignalFields and challengeSignalFields list every signal name
// pulse.html and challenge.html send. Each challenge randomises these names,
// and anything not listed is dropped on both sides — proofwire_test.go
// checks these lists against the templates so a new signal can't silently
// vanish.
var pulseSignalFields = []string{
	"webdriver", "automationArtifact", "screenW", "screenH", "colorDepth",
	"outerWidth", "outerHeight", "innerHeight", "platform", "language",
	"languages", "languageInconsistent", "platformTzMismatch",
	"hardwareConcurrency", "deviceMemory", "maxTouchPoints", "webglRenderer",
	"hasUaData", "uaDataBrandVersion", "webdriverPropPresent",
	"hasWindowChrome", "innerWidth", "devicePixelRatio", "tzOffsetMismatch",
	"canvasBlank", "permissionConflict", "nativeFnTamperedCount",
	"rafVariance", "rafHidden", "visibilityState", "pageOpenMs", "powMs", "fp",
}

var challengeSignalFields = []string{
	"webdriver", "mouseMoved", "mousePath", "movementDeltaSeen", "mouseJitter",
	"velocityVariance", "scrollCount", "scrollIntervalVar", "scrollCanScroll",
	"ikiMax", "keyCount", "rafVariance", "rafHidden", "firstInteractionMs",
	"pageOpenMs", "maxTouchPoints", "screenW", "screenH", "availW", "availH",
	"colorDepth", "outerWidth", "outerHeight", "innerHeight", "hasFocus",
	"timezone", "platform", "language", "languages", "hardwareConcurrency",
	"deviceMemory", "webglRenderer", "webglVendor", "solveTimeMs", "manual",
	"clickTrusted", "platformTzMismatch", "languageInconsistent",
	"firstDeliberateMs", "isBrave", "fp",
}

// reflexProofScore scores the proof-of-execution answers. A wrong layout or
// colour answer is weighted at scoreBlock: it is the one thing a client that
// did not run the page in a real engine cannot get right, so it alone moves
// a pulse to a manual challenge and a verify to Prism — never to a block.
// elapsed is the server-measured time from issue to answer; pass 0 to skip
// the timing check (the challenge page's timing is driven by a human click).
func reflexProofScore(sp *proof.Spec, signals map[string]interface{}, elapsed time.Duration) (score int, reasons []string) {
	add := func(n int, reason string) {
		score += n
		reasons = append(reasons, reason)
	}
	if !sp.CheckRects(signals[proof.FieldRects]) {
		add(scoreBlock, "proof_layout_mismatch")
	}
	if !sp.CheckColor(signals[proof.FieldColor]) {
		add(scoreBlock, "proof_color_mismatch")
	}
	if elapsed > 0 && elapsed < pulseMinAnswer {
		add(4, "result_too_fast")
	}
	return
}

// pulseFailedAnswer handles a pulse answer the page's script could not have
// produced: an unsealable blob or a missing/wrong Lumen answer. It costs a
// failed verification's pressure and a manual challenge, never a block.
func (h *Handler) pulseFailedAnswer(w http.ResponseWriter, r *http.Request, reason, returnURL string, asnNum uint) {
	ipKey := h.ipKey(r)
	log.Printf("CHALLENGE %s ip=%s ua=%q", reason, ipKey, r.UserAgent())
	h.emit(h.newEvent(r, ipKey, 0, "", "CHALLENGE", reason, 0))
	h.reputation.Record(ipKey, asnNum, reputation.VerifyFailure)
	h.escalations.Require(ipKey, tier.SingleClick, escalationTTL)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"action": "challenge",
		"url":    withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL)+"&m=1"),
	})
}
