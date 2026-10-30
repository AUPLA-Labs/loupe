package handler

import (
	"net/http"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/asn"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// escalationTTL is how long a recorded escalation binds a client. Long enough
// that a bot cannot simply wait out a hard challenge within one crawl, short
// enough that a shared address is not penalised for long.
const escalationTTL = 15 * time.Minute

// requiresSingleClick is the single definition of "this client must complete a
// manual challenge". serveChallengePage (which decides what the page renders),
// serveLumenChallenge (which issues the challenge), and serveVerify (which
// checks it) all call this, so none of the three can disagree — a disagreement
// between any of them is exactly how the original bypass worked.
func requiresSingleClick(isDatacenter bool, escalated tier.Tier) bool {
	return isDatacenter || escalated >= tier.SingleClick
}

// dispatchReason names why a fresh request was sent to effTier, for the
// events log and admin dashboard. Reputation pressure is checked first: if
// it alone explains reaching effTier (it equals effTier and exceeds what the
// signal tier already implied), that is the most specific and most
// actionable thing to show an operator — it is the one input that means
// "this source has a history," as opposed to a one-off high score or a
// static ASN classification. Ties (reputation merely matching what the
// signal or ASN floor already reached) fall through to the older, more
// specific reasons so a plain datacenter or request-score dispatch keeps its
// existing label.
func dispatchReason(effTier tier.Tier, isDatacenter bool, signalTier, asnFloor, reputationFloor tier.Tier) string {
	if reputationFloor == effTier && reputationFloor > signalTier && reputationFloor > asnFloor {
		return "reputation_pressure"
	}
	if isDatacenter && signalTier < tier.SingleClick {
		return "datacenter"
	}
	switch effTier {
	case tier.Prism:
		return "request_score_prism"
	case tier.SingleClick:
		return "request_score_singleclick"
	case tier.LumenAuto:
		return "request_score_lumen"
	default:
		return "pulse_check"
	}
}

// clientASN looks up the request's ASN once, returning the record fields the
// callers need plus the datacenter classification that feeds requiresSingleClick.
func (h *Handler) clientASN(r *http.Request) (asnNum uint, org string, isDatacenter bool) {
	rec := h.clientNet(r)
	return rec.ASN, rec.Org, rec.Datacenter
}

// clientNet is everything known about the request's network: the AUPLA
// database's record and the overlay's lists.
func (h *Handler) clientNet(r *http.Request) asn.Record {
	if h.asnDB == nil {
		// Real Handlers (New) always populate asnDB; nil only occurs in unit
		// tests that build a bare Handler{} literal without a database
		// fixture. Failing open here to "unknown network" keeps clientNet safe
		// to call from any handler that doesn't itself need it (e.g.
		// servePulseResult's post-probe-check path).
		return asn.Record{}
	}
	if ip := h.realIP(r); ip != nil {
		if rec, err := h.asnDB.Lookup(ip); err == nil {
			return rec
		}
	}
	return asn.Record{}
}

// overlayDir maps the config's "off" to no overlay.
func overlayDir(dir string) string {
	if dir == "off" {
		return ""
	}
	return dir
}

// datacenterListURL is asn.datacenter_asns_url with "off" meaning none.
func datacenterListURL(u string) string {
	if u == "off" {
		return ""
	}
	return u
}
