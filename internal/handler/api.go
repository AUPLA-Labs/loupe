package handler

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/AUPLA-Labs/loupe/internal/apikeys"
	"github.com/AUPLA-Labs/loupe/internal/rules"
)

// serveAPI answers a request on an api route that holds no clearance and
// was not blocked: it is proxied when the route's policy lets it through,
// and gets a 401 otherwise. It is never challenged: an API client can't run
// an interstitial.
func (h *Handler) serveAPI(w http.ResponseWriter, r *http.Request, p *rules.APIPolicy, entry logEntry) {
	key := h.ipKey(r)
	pass := func(reason string, reasons ...string) {
		ev := h.newEvent(r, key, entry.ASN, entry.Org, "ALLOW", reason, 0)
		ev.Rule = ruleResultOf(r).hit.APIID
		ev.Reasons = reasons
		h.emitRolled(rollupKey{"ALLOW", reason, key, r.Host, r.UserAgent(), ruleResultOf(r).rollupPart(true)}, ev, false)
		h.proxyThrough(w, r)
	}
	refuse := func(reason string, reasons []string) {
		ev := h.newEvent(r, key, entry.ASN, entry.Org, "BLOCK", reason, 0)
		ev.Rule = ruleResultOf(r).hit.APIID
		ev.Reasons = reasons
		h.emitRolled(rollupKey{"BLOCK", reason, key, r.Host, "", ruleResultOf(r).rollupPart(true)}, ev, false)
	}
	switch {
	case isPreflight(r):
		// A browser asks before a cross-origin call, without credentials;
		// the backend answers with its CORS policy.
		pass("api_preflight")
		return
	case p.Auth == rules.APIAuthNone:
		pass("api_open")
		return
	case p.Auth == rules.APIAuthBackendHeader && strings.TrimSpace(r.Header.Get(p.Header)) != "":
		// The backend checks the credential; Loupe only requires it, and a
		// rate_limit rule with by: header:<name> limits each one.
		pass("api_credential")
		return
	case p.Auth == rules.APIAuthLoupeKeys && h.apiKeys != nil:
		presented := strings.TrimSpace(r.Header.Get(p.Header))
		if p.Header == "Authorization" {
			presented = strings.TrimSpace(strings.TrimPrefix(presented, "Bearer "))
		}
		addr, _ := netip.AddrFromSlice(h.realIP(r))
		id, res, wait := h.apiKeys.Check(presented, addr)
		switch res {
		case apikeys.Valid:
			pass("api_key", "key:"+id)
			return
		case apikeys.WrongNet:
			refuse("api_key_network", []string{"key:" + id})
			http.Error(w, "this API key is not allowed from your network", http.StatusForbidden)
			return
		case apikeys.OverLimit:
			refuse("api_key_rate", []string{"key:" + id})
			h.serveRateLimited(w, r, wait)
			return
		}
	}
	refuse("api_unauthorized", nil)
	writeAPIUnauthorized(w, p)
}

// APIKeys is the store of Loupe-issued API keys, for the dashboard.
func (h *Handler) APIKeys() *apikeys.Store { return h.apiKeys }

// isPreflight reports a CORS preflight request.
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// writeAPIUnauthorized is the 401 for an API client without a credential,
// shaped like a typical API's own so a client handles it the same way.
func writeAPIUnauthorized(w http.ResponseWriter, p *rules.APIPolicy) {
	challenge := "Bearer"
	if p.Realm != "" {
		challenge += ` realm="` + p.Realm + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Cache-Control", "private, no-store")
	if p.Error == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"clearance_required"}` + "\n"))
		return
	}
	msg := p.Message
	if msg == "" {
		msg = "authentication required"
	}
	http.Error(w, msg, http.StatusUnauthorized)
}
