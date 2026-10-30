package handler

import (
	"net"
	"testing"
)

func TestClientKey(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4 keys on the full address", "1.2.3.4", "1.2.3.4"},
		{"ipv4-mapped ipv6 normalises to v4", "::ffff:1.2.3.4", "1.2.3.4"},
		{"ipv6 keys on the /64 prefix", "2a06:98c0:3600::103", "2a06:98c0:3600::/64"},
		{"ipv6 with a full interface id", "2a06:98c0:3600:0:aaaa:bbbb:cccc:dddd", "2a06:98c0:3600::/64"},
		{"ipv6 loopback", "::1", "::/64"},
	}
	for _, c := range cases {
		got := clientKey(net.ParseIP(c.in))
		if got != c.want {
			t.Errorf("%s: clientKey(%s) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestClientKeyNilIsEmpty(t *testing.T) {
	if got := clientKey(nil); got != "" {
		t.Errorf("clientKey(nil) = %q, want empty string", got)
	}
}

func TestClientKeyCollapsesIPv6Rotation(t *testing.T) {
	// RFC 4941 privacy extensions rotate the interface identifier every few
	// hours. Keying on the full address would invalidate a real user's
	// clearance cookie mid-session, and would hand an attacker 2^64 free
	// identities against the offender tracker and rate limiters.
	before := clientKey(net.ParseIP("2001:db8:abcd:1234:1111:2222:3333:4444"))
	after := clientKey(net.ParseIP("2001:db8:abcd:1234:9999:8888:7777:6666"))
	if before != after {
		t.Errorf("addresses in the same /64 produced different keys: %q vs %q", before, after)
	}
}

func TestClientKeySeparatesDifferentIPv6Prefixes(t *testing.T) {
	a := clientKey(net.ParseIP("2001:db8:abcd:1234::1"))
	b := clientKey(net.ParseIP("2001:db8:abcd:9999::1"))
	if a == b {
		t.Errorf("different /64 prefixes collapsed to the same key: %q", a)
	}
}
