package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"strings"
)

// Verdict IDs, after Cloudflare's Ray ID: every request Loupe handles
// gets a random ID that is logged with each event it produces, returned in
// the Loupe-Verdict response header, and shown in the footer of every
// page Loupe serves, so a visitor's screenshot or report can be traced
// to the exact log line.
//
// A verdict that sends the browser on to another Loupe page (pulse,
// challenge, Prism, the unverified page) carries its ID in the redirect as
// "vid", and that page shows it in place of its own: the page's own request
// usually logs nothing, while the verdict that sent the visitor there does.

const verdictHeader = "Loupe-Verdict"

type verdictKey struct{}

func newVerdictID() string {
	var b [8]byte
	rand.Read(b[:]) //nolint:errcheck // crypto/rand never fails on Linux
	return hex.EncodeToString(b[:])
}

// withNewVerdict assigns r its verdict ID and sets the response header.
func withNewVerdict(w http.ResponseWriter, r *http.Request) *http.Request {
	id := newVerdictID()
	w.Header().Set(verdictHeader, id)
	return r.WithContext(context.WithValue(r.Context(), verdictKey{}, id))
}

// verdictID is r's own verdict ID, or "" outside ServeHTTP (unit tests).
func verdictID(r *http.Request) string {
	id, _ := r.Context().Value(verdictKey{}).(string)
	return id
}

// withVerdict appends r's verdict ID to target, a Loupe page URL that
// already has a query string.
func withVerdict(r *http.Request, target string) string {
	id := verdictID(r)
	if id == "" {
		return target
	}
	return target + "&vid=" + id
}

func isVerdictID(s string) bool {
	if len(s) != 16 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// footerData is what the shared page footer shows.
type footerData struct {
	VerdictID string
	ClientIP  string
	T         map[string]template.HTML
}

// footer builds the footer for a page served in response to r. carried is
// true on Loupe's own page routes, which show the verdict ID the
// redirect carried to them, if any; pages served inline (blocked, the
// no-cookies backstop) show the ID of the request they answer.
func (h *Handler) footer(r *http.Request, carried bool) footerData {
	f := footerData{VerdictID: verdictID(r), T: pickLocale(r.Header.Get("Accept-Language")).T}
	if v := r.URL.Query().Get("vid"); carried && isVerdictID(v) {
		f.VerdictID = v
	}
	if ip := h.realIP(r); ip != nil {
		f.ClientIP = ip.String()
	}
	return f
}
