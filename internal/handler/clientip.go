package handler

import (
	"context"
	"log"
	"net"
	"net/http"

	"github.com/AUPLA-Labs/loupe/internal/clientip"
)

type clientResultKey struct{}

// normalise resolves r's visitor once, from proxy.trusted and
// proxy.client_ip_header, and rewrites the forwarding headers so that
// everything after it (rules, limits, cookies, the backend) sees only
// what Loupe believes: X-Forwarded-Proto is the visitor's scheme, and from
// an untrusted peer no forwarding header survives.
func (h *Handler) normalise(r *http.Request) *http.Request {
	res := h.resolve(r)
	if res.ViaProxy && res.HeaderMissing {
		h.proxyWarn.Do(func() {
			log.Printf("proxy: a request from trusted proxy %s carried no usable %s; visitors will all look like the proxy. Check proxy.client_ip_header.",
				res.IP, h.client.Header())
		})
	}
	if !res.ViaProxy {
		for _, k := range []string{"X-Forwarded-For", "X-Real-Ip", "Cf-Connecting-Ip"} {
			r.Header.Del(k)
		}
		if h.client != nil {
			r.Header.Del(h.client.Header())
		}
	}
	scheme := "http"
	if res.HTTPS {
		scheme = "https"
	}
	r.Header.Set("X-Forwarded-Proto", scheme)
	return r.WithContext(context.WithValue(r.Context(), clientResultKey{}, res))
}

// resolve works out r's visitor. A Handler built without New (unit tests)
// trusts no proxy.
func (h *Handler) resolve(r *http.Request) clientip.Result {
	if h.client == nil {
		return (&clientip.Resolver{}).Resolve(r)
	}
	return h.client.Resolve(r)
}

// clientOf is what normalise found for r, or a fresh resolution for a
// request that didn't pass through ServeHTTP.
func (h *Handler) clientOf(r *http.Request) clientip.Result {
	if res, ok := r.Context().Value(clientResultKey{}).(clientip.Result); ok {
		return res
	}
	return h.resolve(r)
}

// realIP is the visitor's address, or nil if the socket address is
// unparseable.
func (h *Handler) realIP(r *http.Request) net.IP {
	ip := h.clientOf(r).IP
	if !ip.IsValid() {
		return nil
	}
	return net.IP(ip.AsSlice())
}
