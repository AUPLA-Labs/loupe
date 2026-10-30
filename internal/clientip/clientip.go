// Package clientip works out who a request really came from. Forwarding
// headers (the client-IP header and X-Forwarded-Proto) are believed only
// when the connection comes from a proxy the operator trusts; from anyone
// else they could name any address, including a private one that skips
// every rule.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Result is what Resolve found out about a request.
type Result struct {
	IP            netip.Addr // the visitor; invalid only if the socket address is unparseable
	HTTPS         bool       // the visitor used HTTPS
	ViaProxy      bool       // the connection came from a trusted proxy
	HeaderMissing bool       // ...which sent no usable client-IP header
}

// Resolver applies proxy.trusted and proxy.client_ip_header.
type Resolver struct {
	trusted []netip.Prefix
	header  string
}

// notForwarding are headers that can't carry a client address: hop-by-hop
// ones a proxy strips, and Host.
var notForwarding = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Host": true,
}

// New builds a Resolver. trusted holds CIDRs, bare addresses or preset
// names (loopback, private, cloudflare); header names the header a trusted
// proxy puts the visitor's address in.
func New(trusted []string, header string) (*Resolver, error) {
	prefixes, err := ParseTrusted(trusted)
	if err != nil {
		return nil, err
	}
	if !isToken(header) {
		return nil, fmt.Errorf("proxy.client_ip_header %q is not a header name", header)
	}
	header = http.CanonicalHeaderKey(header)
	if notForwarding[header] {
		return nil, fmt.Errorf("proxy.client_ip_header can't be %s", header)
	}
	return &Resolver{trusted: prefixes, header: header}, nil
}

// ParseTrusted expands proxy.trusted into prefixes.
func ParseTrusted(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range entries {
		if cidrs, ok := presets[e]; ok {
			for _, c := range cidrs {
				out = append(out, netip.MustParsePrefix(c))
			}
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("proxy.trusted: %q is not an address, a CIDR or one of loopback, private, cloudflare", e)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("proxy.trusted: %q has host bits set (did you mean %s?)", e, p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}

// Header is the client-IP header, in canonical form.
func (rs *Resolver) Header() string { return rs.header }

// Trusts reports whether a is one of the trusted proxies.
func (rs *Resolver) Trusts(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range rs.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Resolve works out r's visitor. From an untrusted peer that is the peer
// itself. From a trusted one it is read from the client-IP header right to
// left (several header lines count as one list), skipping trusted hops:
// entries further left were written by whoever the proxy heard from, and
// only the first untrusted one is vouched for.
func (rs *Resolver) Resolve(r *http.Request) Result {
	peer := parseAddr(r.RemoteAddr)
	res := Result{IP: peer, HTTPS: r.TLS != nil}
	if !peer.IsValid() || !rs.Trusts(peer) {
		return res
	}
	res.ViaProxy = true
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	res.HTTPS = res.HTTPS || strings.EqualFold(strings.TrimSpace(proto), "https")

	hops := strings.Split(strings.Join(r.Header.Values(rs.header), ","), ",")
	var leftmost netip.Addr
	for i := len(hops) - 1; i >= 0; i-- {
		a := parseAddr(strings.TrimSpace(hops[i]))
		if !a.IsValid() {
			break
		}
		if !rs.Trusts(a) {
			res.IP = a
			return res
		}
		leftmost = a
	}
	if leftmost.IsValid() {
		res.IP = leftmost
	} else {
		res.HeaderMissing = true
	}
	return res
}

// parseAddr reads an address with or without a port or IPv6 brackets.
func parseAddr(s string) netip.Addr {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.WithZone("").Unmap()
}

// isToken reports whether s is a valid header name (RFC 9110 token).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c > '~' || c <= ' ' || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, c) {
			return false
		}
	}
	return true
}
