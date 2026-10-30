package handler

import (
	"net/http"
	"strings"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// reflexRequestScore scores a request using only information available
// before any JavaScript has run: headers and the request line. It mirrors
// the reflexScore / reflexProbeScore / reflexPrismScore idiom, so its
// reasons flow into the events log and admin dashboard with no extra
// plumbing.
//
// By the time this runs in ServeHTTP, isKnownBotUA and the bot policy (h.bots)
// have already passed known bots and cryptographically verified crawlers
// through, so a missing "Mozilla/" prefix here is scored, never treated as
// proof of a bot on its own — a score never blocks.
func reflexRequestScore(r *http.Request, exploitPaths []string) (score int, reasons []string) {
	add := func(n int, reason string) {
		score += n
		reasons = append(reasons, reason)
	}

	ua := r.UserAgent()
	claims := parseUAClaims(ua)
	doc := isDocumentNavigation(r)

	if claims.isChromium && hasMalformedChromeVersion(ua) {
		add(5, "ua_malformed_chrome")
	}

	claimsModernBrowser := versionAtLeast(claims.chromiumMajor, claims.chromiumMinor, 76, 0) ||
		versionAtLeast(claims.firefoxMajor, claims.firefoxMinor, 90, 0) ||
		versionAtLeast(claims.safariMajor, claims.safariMinor, 16, 4)
	if claimsModernBrowser && doc {
		if r.Header.Get("Sec-Fetch-Mode") == "" || r.Header.Get("Sec-Fetch-Dest") == "" || r.Header.Get("Sec-Fetch-Site") == "" {
			add(4, "sec_fetch_missing")
		}
	}

	if versionAtLeast(claims.chromiumMajor, claims.chromiumMinor, 89, 0) && r.Header.Get("Sec-CH-UA") == "" {
		add(2, "sec_ch_ua_missing")
	}

	if !claims.hasMozilla {
		add(3, "ua_not_browser_shaped")
	}

	if claims.hasMozilla && doc && r.Header.Get("Accept-Language") == "" {
		add(2, "no_accept_language")
	}

	clean, anomalies := canonicalPath(r)
	lowPath := strings.ToLower(clean)
	for _, p := range exploitPaths {
		if p != "" && strings.Contains(lowPath, strings.ToLower(p)) {
			add(4, "exploit_path")
			break
		}
	}

	// Encoding tricks in the path: +3 each, at most +6. Scored, never
	// blocked on their own; a rule on anomalies can block them.
	for i, a := range anomalies {
		if i == 2 {
			break
		}
		add(3, "path_"+a)
	}

	return
}

// isDocumentNavigation reports whether r looks like a top-level page request
// rather than a subresource or API call. Prefers the client's own
// Sec-Fetch-Dest claim when present; falls back to the Accept header, which
// every browser (and no plain HTTP client) sets to prefer text/html for a
// navigation.
func isDocumentNavigation(r *http.Request) bool {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// hasMalformedChromeVersion detects structurally impossible Chrome UAs: a
// missing "(KHTML, like Gecko)" token, which every real Chrome UA carries; a
// Chrome version with the wrong number of dot-separated components (real
// Chrome always ships major.minor.build.patch, i.e. exactly three dots); or
// a run of two or more consecutive whitespace characters, which real Chrome
// never emits. Caller must already know claims.isChromium is true.
func hasMalformedChromeVersion(ua string) bool {
	if !strings.Contains(ua, "(KHTML, like Gecko)") {
		return true
	}
	idx := strings.Index(ua, "Chrome/")
	rest := ua[idx+len("Chrome/"):]
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		end = len(rest)
	}
	if strings.Count(rest[:end], ".") != 3 {
		return true
	}
	return hasWhitespaceRun(ua)
}

func hasWhitespaceRun(s string) bool {
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if prevSpace {
				return true
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
	}
	return false
}

// requestScoreTier maps a reflexRequestScore result onto the challenge tier
// ladder using the operator-configured thresholds. A score below Tier2
// leaves the request at Pulse, the ladder's default — the pre-JS score can
// raise a request above Pulse, but never below it.
func requestScoreTier(score int, cfg config.RequestScoreConfig) tier.Tier {
	switch {
	case score >= cfg.Tier4:
		return tier.Prism
	case score >= cfg.Tier3:
		return tier.SingleClick
	case score >= cfg.Tier2:
		return tier.LumenAuto
	default:
		return tier.Pulse
	}
}
