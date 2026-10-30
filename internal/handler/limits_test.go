package handler

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

// limitsFixture is a rules fixture with the given limits and rules.
func limitsFixture(t *testing.T, l config.LimitsConfig, rulesYAML ...string) *rulesFixture {
	t.Helper()
	cfg, err := config.LoadBytes([]byte("backend: http://127.0.0.1:1\nhmac_secret: test-secret-test-secret-test-secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l.MaxURLBytes == 0 {
		l.MaxURLBytes = cfg.Limits.MaxURLBytes
	}
	if l.MaxQueryParams == 0 {
		l.MaxQueryParams = cfg.Limits.MaxQueryParams
	}
	if l.AllowedMethods == nil {
		l.AllowedMethods = cfg.Limits.AllowedMethods
	}
	f := newRulesFixture(t, strings.Join(rulesYAML, ""))
	f.h.limits = newRequestLimits(l)
	return f
}

func TestURLTooLong414(t *testing.T) {
	f := limitsFixture(t, config.LimitsConfig{MaxURLBytes: 100})
	r := chromeNav()
	r.RequestURI = "/" + strings.Repeat("a", 100)
	if w := f.serve(r); w.Code != http.StatusRequestURITooLong {
		t.Fatalf("status %d, want 414", w.Code)
	}
	if evs := f.events("BLOCK", "limit_url"); len(evs) != 1 {
		t.Errorf("limit_url events = %d, want 1", len(evs))
	}
}

func TestTooManyQueryParams400(t *testing.T) {
	f := limitsFixture(t, config.LimitsConfig{MaxQueryParams: 3})
	r := chromeNav()
	r.URL.RawQuery = "a=1&b=2&c=3"
	if w := f.serve(r); w.Code == http.StatusBadRequest {
		t.Fatal("3 parameters refused with a limit of 3")
	}
	r = chromeNav()
	r.URL.RawQuery = "a=1&b=2&c=3&d=4"
	if w := f.serve(r); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
}

func TestMethodNotAllowed405(t *testing.T) {
	f := limitsFixture(t, config.LimitsConfig{})
	r := chromeNav()
	r.Method = "PROPFIND"
	w := f.serve(r)
	if w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Header().Get("Allow"), "POST") {
		t.Fatalf("status %d Allow %q, want 405 listing the allowed methods", w.Code, w.Header().Get("Allow"))
	}
	f = limitsFixture(t, config.LimitsConfig{AllowedMethods: []string{"GET", "PROPFIND"}})
	if w := f.serve(r); w.Code == http.StatusMethodNotAllowed {
		t.Fatal("a configured method was refused")
	}
}

func TestBodyLimit413(t *testing.T) {
	f := limitsFixture(t, config.LimitsConfig{MaxBodyBytes: 10})
	post := func(path string, body string, declared bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		if !declared {
			r.ContentLength = -1 // as a chunked upload
		}
		return f.serve(r)
	}
	if w := post("/form", strings.Repeat("x", 11), true); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared 11 bytes: status %d, want 413", w.Code)
	}
	if evs := f.events("BLOCK", "limit_body"); len(evs) != 1 {
		t.Errorf("limit_body events = %d, want 1", len(evs))
	}
	if w := post("/form", strings.Repeat("x", 10), true); w.Code == http.StatusRequestEntityTooLarge {
		t.Fatal("a body at the limit was refused")
	}
}

// A body that never declared its length is cut off at the limit as it is
// sent on, and the client gets a 413 rather than a 502.
func TestUndeclaredBodyStopsAtLimit(t *testing.T) {
	var got atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Store(n)
	}))
	defer backend.Close()
	// Allow everything, so the request is proxied without a challenge.
	f := limitsFixture(t, config.LimitsConfig{MaxBodyBytes: 1000}, "rules:\n  - {id: all, mode: enforce, action: allow, match: {paths: [{prefix: /}]}}\n")
	u, _ := url.Parse(backend.URL)
	f.h.proxy = f.h.buildProxy(u)
	r := httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("x", 100_000)))
	r.ContentLength = -1
	r.RemoteAddr = "203.0.113.5:1"
	w := f.serve(r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", w.Code)
	}
	if n := got.Load(); n > 1000 {
		t.Fatalf("backend received %d bytes, over the 1000-byte limit", n)
	}
}

func TestUploadPathRaisesBodyLimit(t *testing.T) {
	f := limitsFixture(t, config.LimitsConfig{MaxBodyBytes: 10, UploadPaths: []string{"/upload/"}, UploadMaxBodyBytes: 1000})
	for _, tc := range []struct {
		path string
		size int
		want bool // refused
	}{
		{"/upload/a", 500, false},
		{"/upload/a", 1001, true},
		{"/UPLOAD/a", 500, true}, // upload paths are exact prefixes
		{"/other", 500, true},
		{"/upload/../other", 500, true}, // matched on the canonical path
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", tc.size)))
		r.URL.Path = tc.path
		w := f.serve(r)
		if (w.Code == http.StatusRequestEntityTooLarge) != tc.want {
			t.Errorf("%s with %d bytes: status %d, refused want %v", tc.path, tc.size, w.Code, tc.want)
		}
	}
}

func TestLimitsSparePrivateAddresses(t *testing.T) {
	f := limitsFixture(t, config.LimitsConfig{MaxURLBytes: 10})
	r := chromeNav()
	r.RemoteAddr = "10.0.0.5:1"
	r.RequestURI = "/" + strings.Repeat("a", 50)
	if w := f.serve(r); w.Code == http.StatusRequestURITooLong {
		t.Fatal("a private address was refused by a request limit")
	}
}

// A rule on /admin can't be dodged with encoding, dot segments, repeated
// slashes or case.
func TestRuleMatchesCanonicalPath(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: no-admin
    mode: enforce
    action: block
    match: {paths: [{prefix: /admin}]}
`)
	for _, p := range []string{"/admin", "//admin", "/ADMIN", "/Admin/x", "/a/../admin", "/x/%2e%2e/admin", "/%2561dmin"} {
		r := chromeNav()
		r.URL.Path = p
		if strings.Contains(p, "%") {
			r = httptest.NewRequest("GET", p, nil)
			r.Header = chromeNav().Header
		}
		if w := f.serve(r); w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want the block rule to apply", p, w.Code)
		}
	}
	r := chromeNav()
	r.URL.Path = "/administrators-guide"
	if w := f.serve(r); w.Code == http.StatusForbidden {
		// A prefix is a prefix: this one matches too, as documented.
		t.Log("prefix /admin also covers /administrators-guide")
	}
}

// Go's server already refuses most request-smuggling shapes before Loupe
// sees them; these pin that. What it lets through is resolved the way Caddy
// (also Go) resolves it, and Loupe only listens behind Caddy.
func TestGoServerRejectsSmuggling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		fmt.Fprintf(w, "cl=%d te=%v", r.ContentLength, r.TransferEncoding)
	}))
	defer srv.Close()
	for _, tc := range []struct {
		name, raw string
		status    int
	}{
		{"conflicting Content-Length", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabcde", 400},
		{"negative Content-Length", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", 400},
		{"signed Content-Length", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +3\r\n\r\nabc", 400},
		{"space before colon", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n", 400},
		{"unknown Transfer-Encoding", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: foo\r\n\r\n", 501},
		{"Transfer-Encoding list", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", 501},
		{"two Transfer-Encodings", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n", 501},
		// Passed through, resolved per RFC 9112: Transfer-Encoding wins.
		{"Transfer-Encoding and Content-Length", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", 200},
	} {
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(tc.raw)) //nolint:errcheck
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if resp.StatusCode != tc.status {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.status)
		}
	}
}
