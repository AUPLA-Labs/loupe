package handler

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/lumen"
	"github.com/AUPLA-Labs/loupe/internal/proof"
)

// Lumen wiring: picking a challenge's level from what Loupe already
// knows about the client, and checking the answer. See internal/lumen for
// the check itself and proof.js for the client half.

const (
	// lumenFastRate is a server-measured hash rate (issue to answer, so
	// network time only lowers it) no browser's JavaScript SHA-256 reaches;
	// above it the work was done by a native solver. Log-only for now: the
	// old solve_too_fast signal was removed for false positives, so this
	// waits on real data before it scores anything.
	lumenFastRate = 30e6
	// lumenFastMinHashes keeps the rate check to answers with enough work
	// for the measurement to mean something.
	lumenFastMinHashes = 1_000_000
)

// lumenBase is the Standard level's cost on the pulse interstitial or the
// challenge page. Pulse never goes past Standard: its ~500 ms budget can't
// fit more, and a client that scores higher is sent to the challenge page by
// its tier anyway.
func (h *Handler) lumenBase(pulse bool) lumen.Base {
	c := h.cfg.Lumen
	b := lumen.Base{Work: c.Work, MemoryMB: c.MemoryMB, MaxMemoryMB: c.MaxMemoryMB, MaxLevel: lumen.Level(c.MaxLevel)}
	if pulse {
		b.Work, b.MemoryMB = c.PulseWork, c.PulseMemoryMB
		b.MaxLevel = min(b.MaxLevel, lumen.Standard)
	}
	return b
}

// lumenInputs gathers the scoring inputs for ipKey. reqScore and unanswered
// come from the caller because they differ between dispatch (the
// navigation itself) and issue (a later request).
func (h *Handler) lumenInputs(ipKey string, asnNum uint, isDatacenter bool, reqScore, unanswered int) lumen.Inputs {
	in := lumen.Inputs{
		RequestScore: reqScore,
		Datacenter:   isDatacenter,
		Escalation:   h.escalations.Level(ipKey),
		Unanswered:   unanswered,
	}
	if h.reputation != nil {
		in.IPPressure = h.reputation.IPPressure(ipKey)
		in.ASNHot = h.reputation.ASNHot(asnNum, isDatacenter)
	}
	return in
}

// lumenPrismFloor is the lowest level the Prism puzzle page's Lumen is
// scored at. Every client there has already looked like a bot, and a bot
// that learns to solve the puzzle should still pay for each attempt.
const lumenPrismFloor = lumen.Intense

// lumenDemandFor is the minimum level an answer scoring score demands of
// the client's next challenge: the evidence that only arrives with an
// answer (fingerprint contradictions, behaviour) can't raise the level the
// answer was issued at, so it raises the next one's.
func lumenDemandFor(score int) lumen.Level {
	switch {
	case score >= 2*scoreBlock:
		return lumen.Blinding
	case score >= scoreBlock:
		return lumen.Intense
	case score >= scoreSuspicious:
		return lumen.Bright
	default:
		return lumen.Glow
	}
}

// demandLumen records the level an answer scoring score demands of ipKey's
// next challenge (lumenDemandFor).
func (h *Handler) demandLumen(ipKey string, score int) {
	h.escalations.DemandLumen(ipKey, int(lumenDemandFor(score)), escalationTTL)
}

// lumenFollowup reports whether an answer scoring score paid for a lower
// level than it demands: enforced, the client is sent back for a challenge
// at that level instead of passing. Comparing against the demand as the
// challenge page would serve it (after its MaxLevel clamp) keeps the round
// from repeating forever on a clamped page.
func (h *Handler) lumenFollowup(sp *proof.Spec, score int) bool {
	if sp.Lumen == nil {
		return false
	}
	want := lumen.ParamsFor(lumenDemandFor(score), h.lumenBase(false))
	return want.Level > sp.Lumen.Level
}

// lumenParams picks the Lumen challenge about to be issued to r on the
// pulse interstitial or the challenge page.
func (h *Handler) lumenParams(r *http.Request, ipKey string, pulse bool) lumen.Params {
	return h.lumenParamsAt(r, ipKey, h.lumenBase(pulse), lumen.Glow)
}

// lumenPrismParams picks the Lumen challenge for the Prism puzzle page: the
// challenge page's costs, scored at lumenPrismFloor or above.
func (h *Handler) lumenPrismParams(r *http.Request, ipKey string) lumen.Params {
	return h.lumenParamsAt(r, ipKey, h.lumenBase(false), lumenPrismFloor)
}

// lumenParamsAt scores ipKey's challenge on a page with base b, at no less
// than floor or an earlier answer's demand. Enforced, it serves the scored
// level; in shadow mode it serves what Loupe served before Lumen
// (Standard, with work doubled by IP pressure) and only records the scored
// level.
func (h *Handler) lumenParamsAt(r *http.Request, ipKey string, base lumen.Base, floor lumen.Level) lumen.Params {
	asnNum, _, isDatacenter := h.clientASN(r)
	// The unanswered count includes this client's challenge in flight —
	// the one being issued now — which says nothing against it.
	unanswered := max(0, h.offenders.Unanswered(ipKey)-1)
	in := h.lumenInputs(ipKey, asnNum, isDatacenter, h.escalations.Lumen(ipKey), unanswered)
	score, _ := lumen.Score(in)
	scored := max(lumen.LevelFor(score), lumen.Level(h.escalations.LumenDemand(ipKey)), floor)
	if h.cfg.Lumen.Enforce {
		return lumen.ParamsFor(scored, base)
	}
	p := lumen.ParamsFor(lumen.Standard, base)
	p.Work = lumen.LegacyWork(base.Work, in.IPPressure)
	p.Scored = scored
	return p
}

// lumenResult is the outcome of checking an answer's Lumen part.
type lumenResult struct {
	// failure names a hard failure ("" when the answer passed): the work
	// was missing or wrong, or — enforced — the space was.
	failure string
	// shadow names a space failure that shadow mode only records, as a
	// zero-point reason on the answer's event.
	shadow string
	// busy means every space check slot stayed taken; the answer was
	// neither accepted nor rejected.
	busy bool
}

// checkLumen checks the Lumen answer in signals against sp. elapsed is the
// server-measured time from issue to answer. It returns r carrying the
// answer's Lumen details for newEvent.
func (h *Handler) checkLumen(r *http.Request, sp *proof.Spec, signals map[string]interface{}, elapsed time.Duration) (lumenResult, *http.Request) {
	if sp.Lumen == nil {
		return lumenResult{failure: "lumen_missing"}, r
	}
	info := lumenInfo{level: int(sp.Lumen.Scored)}
	a, ok := lumen.ParseAnswer(signals[proof.FieldLumen])
	if !ok {
		return lumenResult{failure: "lumen_missing"}, withLumenInfo(r, info)
	}
	if !sp.Lumen.CheckWork(a) {
		return lumenResult{failure: "lumen_invalid"}, withLumenInfo(r, info)
	}
	// Only now are the numbers the server's own, so the rate is real.
	info.spaceMs = a.SpaceMs
	if elapsed > 0 {
		info.rate = float64(a.Hashes()) / elapsed.Seconds()
	}
	r = withLumenInfo(r, info)
	if a.Hashes() >= lumenFastMinHashes && info.rate > lumenFastRate {
		log.Printf("LUMEN fast ip=%s hashes=%d rate=%.0f/s ua=%q", sp.IP, a.Hashes(), info.rate, r.UserAgent())
	}

	ok, err := h.lumenCheck.CheckSpace(r.Context(), sp.Lumen, a)
	if err != nil {
		if !errors.Is(err, lumen.ErrBusy) && !errors.Is(err, context.Canceled) {
			log.Printf("lumen space check error: %v", err)
		}
		return lumenResult{busy: true}, r
	}
	if ok {
		return lumenResult{}, r
	}
	reason := "lumen_space_invalid"
	if a.Digest == "" {
		reason = "lumen_space_missing"
	}
	if h.cfg.Lumen.Enforce {
		return lumenResult{failure: reason}, r
	}
	log.Printf("LUMEN shadow %s ip=%s space_ms=%.0f ua=%q", reason, sp.IP, a.SpaceMs, r.UserAgent())
	return lumenResult{shadow: reason}, r
}

// lumenBusy answers a request whose space check couldn't get a slot.
func lumenBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	http.Error(w, "busy", http.StatusServiceUnavailable)
}

// lumenInfo is the Lumen detail newEvent copies onto every event of a
// request, like the bot claim.
type lumenInfo struct {
	level    int
	dispatch bool    // the navigation being sent to a challenge, not an answer
	rate     float64 // server-measured hashes per second; 0 if unknown
	spaceMs  float64 // client-reported proof-of-space time
}

type lumenInfoKey struct{}

func withLumenInfo(r *http.Request, info lumenInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), lumenInfoKey{}, info))
}
