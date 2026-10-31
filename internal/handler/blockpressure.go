package handler

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/bots"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

// blockPressureWindow throttles block pressure to one increment per IP and
// event: a scanner's hundreds of blocked requests a minute count once.
const blockPressureWindow = time.Minute

// spoofExempt lists bots whose User-Agent real clients borrow on purpose.
// Apple's iMessage link preview sends "facebookexternalhit/1.1 Facebot
// Twitterbot/1.0" from Apple's own addresses, so a failed check for either
// bot is not evidence of a lie.
var spoofExempt = map[string]bool{
	"facebookexternalhit": true,
	"twitterbot":          true,
}

// recordBlockPressure adds ev to the request's IP, throttled.
func (h *Handler) recordBlockPressure(r *http.Request, ev reputation.Event) {
	h.reputation.RecordIPOnce(h.ipKey(r), ev, blockPressureWindow)
}

// recordExploitProbe adds pressure when a public address requests one of
// the operator's exploit paths, whatever happens to the request next — a
// clearance or a block for some other reason doesn't excuse the probe.
func (h *Handler) recordExploitProbe(r *http.Request, ip net.IP) {
	if isPrivateIP(ip) || !matchesExploitPath(r, h.cfg.Hardening.ExploitPaths) {
		return
	}
	h.recordBlockPressure(r, reputation.ExploitProbe)
}

// recordSpoofPressure adds pressure for a bot claim its address disproves.
func (h *Handler) recordSpoofPressure(r *http.Request, d bots.Decision) {
	if d.Spoofed && d.Bot != nil && !spoofExempt[d.Bot.ID] {
		h.recordBlockPressure(r, reputation.SpoofedBot)
	}
}

// botUAPressure is the event for a bot_ua block: a built-in scanner weighs
// more than an HTTP client library, an empty User-Agent or an operator
// pattern, which are scripts but often harmless ones.
func botUAPressure(ua string) reputation.Event {
	lower := strings.ToLower(ua)
	for _, p := range scannerUAPatterns {
		if strings.Contains(lower, p) {
			return reputation.ScannerUA
		}
	}
	return reputation.ClientUA
}

// matchesExploitPath reports whether the request's canonical path contains
// one of the operator's exploit paths.
func matchesExploitPath(r *http.Request, exploitPaths []string) bool {
	if len(exploitPaths) == 0 {
		return false
	}
	clean, _ := canonicalPath(r)
	lowPath := strings.ToLower(clean)
	for _, p := range exploitPaths {
		if p != "" && strings.Contains(lowPath, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
