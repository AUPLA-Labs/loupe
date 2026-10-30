package clientip

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func resolver(t *testing.T, trusted []string, header string) *Resolver {
	t.Helper()
	r, err := New(trusted, header)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolve(t *testing.T) {
	loop := []string{"loopback"}
	cases := []struct {
		name    string
		trusted []string
		header  string // "" = X-Forwarded-For
		peer    string
		tls     bool
		headers map[string]string
		ip      string
		https   bool
		via     bool
		missing bool
	}{
		{name: "untrusted peer ignores headers", trusted: loop, peer: "203.0.113.9:1",
			headers: map[string]string{"X-Forwarded-For": "10.0.0.1", "X-Forwarded-Proto": "https"},
			ip:      "203.0.113.9"},
		{name: "untrusted peer over TLS", trusted: loop, peer: "203.0.113.9:1", tls: true,
			ip: "203.0.113.9", https: true},
		{name: "trusted proxy", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.4"},
			ip:      "198.51.100.4", via: true},
		{name: "rightmost untrusted wins", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "10.0.0.1, 198.51.100.4"},
			ip:      "198.51.100.4", via: true},
		{name: "trusted hops skipped", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.4, 127.0.0.1"},
			ip:      "198.51.100.4", via: true},
		{name: "port stripped", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.4:5678"},
			ip:      "198.51.100.4", via: true},
		{name: "bracketed IPv6 with port", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "[2001:db8::1]:443"},
			ip:      "2001:db8::1", via: true},
		{name: "garbage left of the client is never reached", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "garbage, 198.51.100.4"},
			ip:      "198.51.100.4", via: true},
		{name: "garbage nearest the proxy", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.4, garbage"},
			ip:      "127.0.0.1", via: true, missing: true},
		{name: "no header from trusted proxy", trusted: loop, peer: "127.0.0.1:1",
			ip: "127.0.0.1", via: true, missing: true},
		{name: "all hops trusted", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "127.0.0.2, 127.0.0.3"},
			ip:      "127.0.0.2", via: true},
		{name: "proto from trusted proxy, first value", trusted: loop, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.4", "X-Forwarded-Proto": "HTTPS, http"},
			ip:      "198.51.100.4", https: true, via: true},
		{name: "single-value header", trusted: loop, header: "CF-Connecting-IP", peer: "127.0.0.1:1",
			headers: map[string]string{"CF-Connecting-IP": "198.51.100.4", "X-Forwarded-For": "10.0.0.1"},
			ip:      "198.51.100.4", via: true},
		{name: "trust nobody", trusted: []string{}, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.4"},
			ip:      "127.0.0.1"},
		{name: "cloudflare preset", trusted: []string{"loopback", "cloudflare"}, peer: "127.0.0.1:1",
			headers: map[string]string{"X-Forwarded-For": "198.51.100.4, 173.245.48.1"},
			ip:      "198.51.100.4", via: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header
			if header == "" {
				header = "X-Forwarded-For"
			}
			target := "http://example.com/"
			if tc.tls {
				target = "https://example.com/"
			}
			req := httptest.NewRequest("GET", target, nil)
			req.RemoteAddr = tc.peer
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			got := resolver(t, tc.trusted, header).Resolve(req)
			want := Result{IP: netip.MustParseAddr(tc.ip), HTTPS: tc.https, ViaProxy: tc.via, HeaderMissing: tc.missing}
			if got != want {
				t.Errorf("Resolve = %+v, want %+v", got, want)
			}
		})
	}
}

// A visitor's forged line comes first; the proxy's own line is appended
// after it, and only that one counts.
func TestResolveMultipleHeaderLines(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header["X-Forwarded-For"] = []string{"10.0.0.1", "198.51.100.4"}
	if got := resolver(t, []string{"loopback"}, "X-Forwarded-For").Resolve(req).IP; got != netip.MustParseAddr("198.51.100.4") {
		t.Errorf("IP = %v, want 198.51.100.4", got)
	}
}

func TestResolveMappedPeer(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::ffff:127.0.0.1]:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	got := resolver(t, []string{"loopback"}, "X-Forwarded-For").Resolve(req)
	if !got.ViaProxy || got.IP != netip.MustParseAddr("198.51.100.4") {
		t.Errorf("Resolve = %+v, want 198.51.100.4 via proxy", got)
	}
}

func TestResolveUnparseablePeer(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "@"
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	if got := resolver(t, []string{"loopback"}, "X-Forwarded-For").Resolve(req); got.ViaProxy || got.IP.IsValid() {
		t.Errorf("Resolve = %+v, want no IP and no proxy", got)
	}
}

func TestParseTrusted(t *testing.T) {
	p, err := ParseTrusted([]string{"private"})
	if err != nil || len(p) != 4 {
		t.Errorf("private = %v (%v), want 4 prefixes", p, err)
	}
	p, err = ParseTrusted([]string{"cloudflare"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"173.245.48.0/20", "2606:4700::/32"} {
		if !contains(p, netip.MustParsePrefix(want)) {
			t.Errorf("cloudflare lacks %s", want)
		}
	}
	p, err = ParseTrusted([]string{"198.51.100.7", "2001:db8::/32"})
	if err != nil || len(p) != 2 || p[0] != netip.MustParsePrefix("198.51.100.7/32") {
		t.Errorf("bare IP = %v (%v), want 198.51.100.7/32 first", p, err)
	}
	for _, bad := range []string{"foo", "203.0.113.1/24", ""} {
		if _, err := ParseTrusted([]string{bad}); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func contains(ps []netip.Prefix, p netip.Prefix) bool {
	for _, q := range ps {
		if q == p {
			return true
		}
	}
	return false
}

func TestNewRejectsBadHeader(t *testing.T) {
	for _, h := range []string{"", "X Forwarded", "Connection", "host"} {
		if _, err := New([]string{"loopback"}, h); err == nil {
			t.Errorf("header %q: no error", h)
		}
	}
	r := resolver(t, nil, "cf-connecting-ip")
	if r.Header() != "Cf-Connecting-Ip" {
		t.Errorf("Header = %q, want canonical", r.Header())
	}
}
