package lumen

import (
	"math"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// Inputs is what Loupe knows about a client when it issues a challenge.
// Everything here is server-side state: nothing the client sends with the
// challenge request itself can lower it.
type Inputs struct {
	// RequestScore is reflexRequestScore of the navigation that was sent to
	// the challenge, saved at dispatch (the challenge itself is issued on a
	// later request).
	RequestScore int
	IPPressure   float64
	// ASNHot means the client's network is over its reputation floor. It
	// adds at most one point, so a busy residential network never slows
	// all of its customers down.
	ASNHot     bool
	Datacenter bool
	Escalation tier.Tier
	// Unanswered counts challenges issued to this client that it never
	// answered — fishing for an easy challenge makes the next one harder.
	Unanswered int
}

// maxUnansweredPoints caps the unanswered contribution.
const maxUnansweredPoints = 3

// Score scores in, reasons naming each contribution like the other reflex
// scorers do.
func Score(in Inputs) (score int, reasons []string) {
	add := func(n int, reason string) {
		if n > 0 {
			score += n
			reasons = append(reasons, reason)
		}
	}
	add(in.RequestScore, "lumen_request_score")
	// Pressure is scaled like the old difficulty doubling: a point per 4,
	// the tier-2 reputation floor.
	add(int(math.Floor(in.IPPressure/4)), "lumen_ip_pressure")
	if in.ASNHot {
		add(1, "lumen_asn_pressure")
	}
	if in.Datacenter {
		add(2, "lumen_datacenter")
	}
	switch {
	case in.Escalation >= tier.Prism:
		add(2, "lumen_escalated")
	case in.Escalation >= tier.SingleClick:
		add(1, "lumen_escalated")
	}
	add(min(in.Unanswered, maxUnansweredPoints), "lumen_unanswered")
	return
}

// LevelFor maps a Score result onto the levels.
func LevelFor(score int) Level {
	switch {
	case score >= 8:
		return Blinding
	case score >= 5:
		return Intense
	case score >= 3:
		return Bright
	case score >= 1:
		return Standard
	default:
		return Glow
	}
}

// maxPressureDoublings caps shadow mode's legacy scaling at 2^5 = 32×.
const maxPressureDoublings = 5

// LegacyWork is the difficulty Loupe served before Lumen scaling: the
// base doubled every 4 points of IP pressure, up to 32×. Shadow mode keeps
// serving it so turning Lumen on in shadow mode never lowers what a
// pressured client pays.
func LegacyWork(base int64, ipPressure float64) int64 {
	exp := math.Max(0, math.Min(ipPressure/4, maxPressureDoublings))
	return int64(float64(base) * math.Pow(2, exp))
}
