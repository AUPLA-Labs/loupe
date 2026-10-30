package admin

// admin.allow: the console answers only connections from these networks,
// judged by the socket's address. A forwarded header never counts here: the
// point is to keep the console off the internet even when it listens on
// every interface.

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/AUPLA-Labs/loupe/internal/clientip"
)

type allowList struct {
	names    string // as configured, for the refusal page
	prefixes []netip.Prefix
}

// SetAllow limits the console to the given addresses, CIDRs and presets
// (see admin.allow). Until it is called, every peer is let through.
func (s *Server) SetAllow(allow []string) error {
	p, err := clientip.ParseTrusted(allow)
	if err != nil {
		return err
	}
	s.allowed.Store(&allowList{names: strings.Join(allow, ", "), prefixes: p})
	return nil
}

func (l *allowList) has(ip netip.Addr) bool {
	for _, p := range l.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) withAllow(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := s.allowed.Load()
		if l == nil {
			next.ServeHTTP(w, r)
			return
		}
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !l.has(ap.Addr().Unmap()) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "This console only accepts connections from %s. Add your network to admin.allow in Loupe's config.yaml.\n", l.names)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ifaceAddr is one address and the interface it is on.
type ifaceAddr struct {
	iface string
	addr  netip.Addr
}

// interfaceAddrs lists the addresses of this machine's interfaces that are
// up; a variable for tests.
var interfaceAddrs = func() ([]ifaceAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []ifaceAddr
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					out = append(out, ifaceAddr{i.Name, ip.Unmap()})
				}
			}
		}
	}
	return out, nil
}

// bridgePrefixes name the interfaces of containers and VMs on this machine,
// whose addresses nobody on the network can reach.
var bridgePrefixes = []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "vxlan", "podman", "lxcbr", "lxdbr"}

// lanHosts is where a wildcard listener can be reached from this machine's
// network: its private IPv4 addresses (private IPv6 only when it has none),
// then 127.0.0.1.
func lanHosts() []string {
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil
	}
	var v4, v6 []string
	loop := ""
	for _, a := range addrs {
		if slices.ContainsFunc(bridgePrefixes, func(p string) bool { return strings.HasPrefix(a.iface, p) }) {
			continue
		}
		switch {
		case a.addr.IsLoopback():
			if a.addr.Is4() {
				loop = a.addr.String()
			}
		case a.addr.IsPrivate() && a.addr.Is4():
			v4 = append(v4, a.addr.String())
		case a.addr.IsPrivate():
			v6 = append(v6, a.addr.String())
		}
	}
	hosts := v4
	if len(hosts) == 0 {
		hosts = v6
	}
	if loop != "" {
		hosts = append(hosts, loop)
	}
	return hosts
}
