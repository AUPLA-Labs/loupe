// Package tier defines Loupe's challenge ladder.
//
// Every scored decision in Loupe resolves to a Tier rather than to a
// verdict: a score chooses how hard a challenge is, never whether a request
// is refused. Blocks remain the exclusive province of categorical rules
// (bad-bot User-Agent, blocked ASN, webdriver, honeypot, repeat offender),
// which is what makes it safe to score aggressively — a misjudged human pays
// one extra click, never loss of access.
//
// Tiers are ordered by severity so that independent sources (request signals,
// IP reputation, ASN reputation, escalation state) can each contribute a floor
// and the effective tier is simply the maximum.
package tier

import "strconv"

type Tier int

const (
	// Pass means no challenge: valid clearance cookie, verified bot,
	// allowlisted ASN, or a private/loopback address.
	Pass Tier = iota
	// Pulse is the silent JS interstitial (~500ms, invisible to the user).
	Pulse
	// LumenAuto is the Lumen check (proof-of-work + proof-of-space) with no
	// interaction required.
	LumenAuto
	// SingleClick requires a genuine, trusted user click.
	SingleClick
	// Prism is the drag-puzzle CAPTCHA, the hardest tier.
	Prism
)

func (t Tier) String() string {
	switch t {
	case Pass:
		return "pass"
	case Pulse:
		return "pulse"
	case LumenAuto:
		return "lumen_auto"
	case SingleClick:
		return "singleclick"
	case Prism:
		return "prism"
	}
	return "tier(" + strconv.Itoa(int(t)) + ")"
}

// Max returns the more severe of two tiers. Floors combine by taking the
// maximum, so any single source can raise the tier and none can lower it.
func Max(a, b Tier) Tier {
	if a > b {
		return a
	}
	return b
}
