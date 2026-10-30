package handler

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/offender"
)

func testInterstitialHandler(t *testing.T) *Handler {
	t.Helper()
	tpl := mustParseTestTemplate(t, "unverified", `<html><head><meta name="robots" content="noindex"></head><body>unverified {{.Return}}</body></html>`)
	return &Handler{
		unverifiedTpl: tpl,
		offenders:     offender.New(5, time.Minute),
	}
}

func TestServeNoJS_HeadersAndStatus(t *testing.T) {
	h := testInterstitialHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/loupe/no-js", nil)
	w := httptest.NewRecorder()
	h.serveNoJS(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
	if !strings.Contains(w.Body.String(), `content="noindex"`) {
		t.Error("body missing noindex meta tag")
	}
}

func TestServeNoCookies_HeadersAndStatus(t *testing.T) {
	h := testInterstitialHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/loupe/no-cookies", nil)
	w := httptest.NewRecorder()
	h.serveNoCookies(w, r, "/")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
	if !strings.Contains(w.Body.String(), `content="noindex"`) {
		t.Error("body missing noindex meta tag")
	}
}

func TestShouldServeNoCookies_ThresholdBoundary(t *testing.T) {
	h := testInterstitialHandler(t)
	key := "1.2.3.4"
	if h.shouldServeNoCookies(key) {
		t.Fatal("fresh key should not trigger the backstop")
	}
	h.offenders.IncrAnsweredNoClearance(key)
	h.offenders.IncrAnsweredNoClearance(key)
	if h.shouldServeNoCookies(key) {
		t.Fatal("2 answered-without-clearance should not yet trigger the backstop")
	}
	h.offenders.IncrAnsweredNoClearance(key)
	if !h.shouldServeNoCookies(key) {
		t.Fatal("3 answered-without-clearance should trigger the backstop")
	}
}

func mustParseTestTemplate(t *testing.T, name, body string) *template.Template {
	t.Helper()
	tpl, err := template.New(name).Parse(body)
	if err != nil {
		t.Fatalf("parse test template %s: %v", name, err)
	}
	return tpl
}

// The real page renders, with "try again" leading back where the visitor
// was going.
func TestUnverifiedPage_Renders(t *testing.T) {
	tpl, err := parsePage("unverified", "unverified.html")
	if err != nil {
		t.Fatal(err)
	}
	h := testInterstitialHandler(t)
	h.unverifiedTpl = tpl
	w := httptest.NewRecorder()
	h.serveUnverifiable(w, httptest.NewRequest(http.MethodGet, "/loupe/unverified", nil), "", "/blog/post?x=1")
	body := w.Body.String()
	if w.Code != http.StatusForbidden || !strings.Contains(body, "couldn't be verified") ||
		!strings.Contains(body, `href="/blog/post?x=1"`) {
		t.Errorf("status %d body:\n%s", w.Code, body)
	}
}
