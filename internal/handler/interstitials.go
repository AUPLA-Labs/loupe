package handler

import (
	"html/template"
	"log"
	"net/http"
)

// noCookiesThreshold is the consecutive answered-but-never-cleared count
// that indicates a client's clearance cookie is never surviving to its next
// navigation (an infinite redirect loop) rather than a one-off skipped
// answer.
const noCookiesThreshold = 3

// shouldServeNoCookies reports whether ipKey has hit the backstop
// threshold. Extracted as its own function so it's unit-testable without a
// ServeHTTP-level harness (none exists in this codebase — see Global
// Constraints).
func (h *Handler) shouldServeNoCookies(ipKey string) bool {
	return h.offenders.AnsweredNoClearanceCount(ipKey) >= noCookiesThreshold
}

// serveUnverifiable renders the one "your browser couldn't be verified"
// page. Every case where Loupe cannot verify a real browser because
// something on the client blocks or changes what it checks ends here, with
// the same advice to turn that setting off and try again; only the logged
// reason tells them apart:
//
//   - no_js: the challenge pages' <noscript> refresh.
//   - no_cookies: the pulse's probe cookie never came back, or the browser
//     keeps answering challenges without its clearance sticking (a
//     verification loop).
//   - ua_changing: that loop, with the clearance kept but the User-Agent
//     different on each request (UA switchers and randomisers).
//   - readout_noise / readout_blocked: see unverifiableReadout.
//
// None of these cost reputation pressure: they describe a
// browser's settings, not evidence of automation. An empty reason renders
// without logging, for pages whose decision was logged where it was made.
// ret is where "try again" leads.
func (h *Handler) serveUnverifiable(w http.ResponseWriter, r *http.Request, reason, ret string) {
	if reason != "" {
		h.emit(h.newEvent(r, h.ipKey(r), 0, "", "BLOCK", reason, 0))
	}
	loc := negotiateLocale(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	// The no-cookies and unverified routes are where redirects land; the
	// backstop renders inline on whatever page was requested.
	carried := r.URL.Path == h.unverifiedPath || r.URL.Path == h.noCookiesPath
	data := struct {
		Lang   string
		T      map[string]template.HTML
		Return string
		Footer footerData
	}{loc.Lang, loc.T, ret, h.footer(r, carried)}
	if err := h.unverifiedTpl.Execute(w, data); err != nil {
		log.Printf("unverified template error: %v", err)
	}
}

// serveNoJS is the <noscript> target. A real browser reaches this only by
// parsing challenge.html/pulse.html's <noscript> meta-refresh — an
// automated scanner that ignores <noscript> never arrives here.
func (h *Handler) serveNoJS(w http.ResponseWriter, r *http.Request) {
	h.offenders.Answered(h.ipKey(r))
	h.serveUnverifiable(w, r, "no_js", "/")
}

// serveNoCookies covers both no-cookies triggers: the pulse's missing probe
// cookie (servePulseResult redirects here) and the answered-without-
// clearance backstop (ServeHTTP). A browser that kept its clearance but
// sent a different User-Agent with it is logged as ua_changing.
func (h *Handler) serveNoCookies(w http.ResponseWriter, r *http.Request, ret string) {
	reason := "no_cookies"
	if h.cookies != nil && h.cookies.UAChanged(r, h.ipKey(r)) {
		reason = "ua_changing"
	}
	h.serveUnverifiable(w, r, reason, ret)
}
