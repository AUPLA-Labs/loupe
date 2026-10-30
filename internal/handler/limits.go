package handler

import (
	"net"
	"net/http"
	"strings"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

// requestLimits is limits from the config, ready for the request path.
type requestLimits struct {
	maxURL      int
	maxParams   int
	maxBody     int64 // 0 = none
	uploadMax   int64 // 0 = none
	uploads     []string
	methods     map[string]bool
	allowHeader string
}

func newRequestLimits(c config.LimitsConfig) *requestLimits {
	l := &requestLimits{maxURL: c.MaxURLBytes, maxParams: c.MaxQueryParams, maxBody: c.MaxBodyBytes,
		uploadMax: c.UploadMaxBodyBytes, uploads: c.UploadPaths, methods: map[string]bool{}}
	for _, m := range c.AllowedMethods {
		l.methods[m] = true
	}
	l.allowHeader = strings.Join(c.AllowedMethods, ", ")
	return l
}

// bodyLimit is the largest body a request to the canonical path p may
// carry, 0 for no limit.
func (l *requestLimits) bodyLimit(p string) int64 {
	for _, u := range l.uploads {
		if strings.HasPrefix(p, u) {
			return l.uploadMax
		}
	}
	return l.maxBody
}

// enforceLimits refuses a request over the configured limits before any
// other work, and reports whether it answered. A body under the limit is
// still capped as it is read, so one longer than it declared stops there and
// the proxy answers 413. Loopback and private addresses are exempt.
func (h *Handler) enforceLimits(w http.ResponseWriter, r *http.Request, ip net.IP) bool {
	l := h.limits
	if l == nil || isPrivateIP(ip) {
		return false
	}
	var reason string
	var status int
	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	switch {
	case !l.methods[r.Method]:
		reason, status = "limit_method", http.StatusMethodNotAllowed
		w.Header().Set("Allow", l.allowHeader)
	case len(uri) > l.maxURL:
		reason, status = "limit_url", http.StatusRequestURITooLong
	case r.URL.RawQuery != "" && strings.Count(r.URL.RawQuery, "&")+1 > l.maxParams:
		reason, status = "limit_query", http.StatusBadRequest
	default:
		clean, _ := canonicalPath(r)
		if max := l.bodyLimit(clean); max > 0 {
			if r.ContentLength > max {
				reason, status = "limit_body", http.StatusRequestEntityTooLarge
			} else if r.Body != nil && r.Body != http.NoBody {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
		}
	}
	if reason == "" {
		return false
	}
	key := h.ipKey(r)
	h.emitRolled(rollupKey{"BLOCK", reason, key, r.Host, "", ""}, h.newEvent(r, key, 0, "", "BLOCK", reason, 0), false)
	http.Error(w, http.StatusText(status), status)
	return true
}
