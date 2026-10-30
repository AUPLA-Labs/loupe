package handler

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
)

// A visitor talking to Loupe directly can't pass forged forwarding headers
// on to the backend, or get a Secure cookie by claiming HTTPS.
func TestUntrustedPeerHeadersStripped(t *testing.T) {
	var got http.Header
	f := newRulesFixtureWith(t, `
rules:
  - id: let-in
    mode: enforce
    action: allow
    match: {ips: ["203.0.113.9"]}
`, "", func(r *http.Request) { got = r.Header.Clone() })
	r := fromIP("203.0.113.9")
	r.Header.Set("CF-Connecting-IP", "10.0.0.1")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Forwarded-Proto", "https")
	w := f.serve(r)
	if got == nil {
		t.Fatalf("status %d: request never reached the backend", w.Code)
	}
	for k, want := range map[string]string{
		"X-Real-Ip": "203.0.113.9", "X-Forwarded-For": "203.0.113.9",
		"X-Forwarded-Proto": "http", "Cf-Connecting-Ip": "",
	} {
		if v := strings.Join(got.Values(k), ","); v != want {
			t.Errorf("backend saw %s %q, want %q", k, v, want)
		}
	}

	// An uncleared navigation from the same visitor: whatever cookies the
	// challenge sets must not be Secure.
	r = fromIP("203.0.113.10")
	r.Header.Set("X-Forwarded-Proto", "https")
	for _, c := range f.serve(r).Result().Cookies() {
		if c.Secure {
			t.Errorf("cookie %s is Secure over plain HTTP", c.Name)
		}
	}
}

func TestForgedPrivateAddressDoesNotSkipRules(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: block-net
    mode: enforce
    action: block
    match: {ips: ["203.0.113.0/24"]}
`)
	r := fromIP("203.0.113.9")
	r.Header.Set("CF-Connecting-IP", "10.0.0.1")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	if w := f.serve(r); w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403: a forged private address skipped the rules", w.Code)
	}
}

// Behind a trusted proxy the visitor is the rightmost untrusted hop, not
// whatever the visitor wrote at the front of X-Forwarded-For.
func TestTrustedProxyAddressUsed(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: block-one
    mode: enforce
    action: block
    match: {ips: ["198.51.100.4"]}
`)
	r := fromIP("127.0.0.1")
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 198.51.100.4")
	if w := f.serve(r); w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 for the proxied visitor 198.51.100.4", w.Code)
	}
}

func TestHeaderMissingLoggedOnce(t *testing.T) {
	f := newRulesFixtureWith(t, "", "proxy:\n  client_ip_header: CF-Connecting-IP\n", nil)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f.serve(fromIP("127.0.0.1"))
	f.serve(fromIP("127.0.0.1"))
	if n := strings.Count(buf.String(), "proxy.client_ip_header"); n != 1 {
		t.Errorf("warning logged %d times, want once:\n%s", n, buf.String())
	}
}
