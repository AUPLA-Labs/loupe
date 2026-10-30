package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/offender"
	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
)

func testVerdictHandler(t *testing.T) *Handler {
	t.Helper()
	tpl, err := parsePage("unverified", "unverified.html")
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{
		cfg:            &config.Config{},
		noJSPath:       "/loupe/no-js",
		unverifiedPath: "/loupe/unverified",
		unverifiedTpl:  tpl,
		offenders:      offender.New(5, time.Minute),
		pulseRL:        ratelimit.New(10, 10),
	}
}

// Every response carries its verdict ID in a header, and a page Loupe
// renders shows the same ID in its footer along with the hidden IP.
func TestVerdictID_HeaderAndFooter(t *testing.T) {
	h := testVerdictHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/loupe/no-js", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	id := w.Header().Get(verdictHeader)
	if !isVerdictID(id) {
		t.Fatalf("header %s = %q, want 16 lowercase hex", verdictHeader, id)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Verdict ID: <code>"+id+"</code>") {
		t.Error("footer does not show this request's verdict ID")
	}
	if !strings.Contains(body, `<span class="sl-ip">9.9.9.9</span>`) || !strings.Contains(body, "Click to reveal") {
		t.Error("footer missing the click-to-reveal IP")
	}
	if !strings.Contains(body, `Secured by Loupe from <a href="https://auplalabs.com" target="_blank" rel="noopener noreferrer">AUPLA</a>.`) {
		t.Error("footer missing the credit")
	}

	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r)
	if w2.Header().Get(verdictHeader) == id {
		t.Error("two requests got the same verdict ID")
	}
}

// A page a verdict redirected to shows that verdict's ID; anything that
// isn't a well-formed ID, or a page rendered inline, shows its own.
func TestVerdictID_CarriedByRedirect(t *testing.T) {
	h := testVerdictHandler(t)
	carried := "0123456789abcdef"
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/loupe/unverified?return=%2F&vid=" + carried, true},
		{"/loupe/unverified?return=%2F&vid=<script>", false},
		{"/loupe/unverified?return=%2F&vid=0123456789ABCDEF", false},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.RemoteAddr = "9.9.9.9:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		shows := strings.Contains(w.Body.String(), "<code>"+carried+"</code>")
		own := strings.Contains(w.Body.String(), "<code>"+w.Header().Get(verdictHeader)+"</code>")
		if shows != tc.want || own == tc.want {
			t.Errorf("%s: shows carried=%v own=%v", tc.path, shows, own)
		}
	}

	r := withNewVerdict(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/blog?vid="+carried, nil))
	if f := h.footer(r, false); f.VerdictID != verdictID(r) {
		t.Errorf("inline page took the query's ID: %q", f.VerdictID)
	}
	if got := withVerdict(r, "/loupe/pulse?return=%2F"); got != "/loupe/pulse?return=%2F&vid="+verdictID(r) {
		t.Errorf("withVerdict = %q", got)
	}
	if ev := h.newEvent(r, "1.2.3.4", 0, "", "BLOCK", "x", 0); ev.VID != verdictID(r) {
		t.Errorf("event vid = %q, want %q", ev.VID, verdictID(r))
	}
}
