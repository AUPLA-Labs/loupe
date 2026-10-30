package handler

import (
	"net/http"
	"strconv"

	"github.com/AUPLA-Labs/loupe/internal/badip"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// BadIPs returns the known-bad-IP feed, nil when bad_ips is disabled.
func (h *Handler) BadIPs() *badip.Feed { return h.badIPs }

// badIPBlocked reports whether the feed refuses this request's address.
func (h *Handler) badIPBlocked(r *http.Request) bool {
	_, act := h.badIPs.Check(h.realIP(r))
	return act == badip.Block
}

// prismRequired names why this client must solve Prism before any other
// answer can clear it, or "" if nothing does: its address is on the bad-IP
// feed ("bad_ip:<lists>"), or dispatch or an earlier answer escalated it to
// Prism and that escalation is still live ("escalation:prism"). The
// silent-check and click-challenge answer handlers both call this, so a
// client sent to Prism can't follow a stale link or a hand-typed URL to an
// easier challenge and collect its clearance instead.
func (h *Handler) prismRequired(r *http.Request, ipKey string) string {
	if n, act := h.badIPs.Check(h.realIP(r)); act == badip.Challenge {
		return "bad_ip:" + strconv.Itoa(n)
	}
	if h.escalations != nil && h.escalations.Level(ipKey) >= tier.Prism {
		return "escalation:prism"
	}
	return ""
}
