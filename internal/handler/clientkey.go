package handler

import "net"

// clientKey normalises an IP address into the key used for every piece of
// per-client state in Loupe: the offender tracker, the rate limiters, the
// proof challenges (and the Lumen check inside them), the Prism token, and
// the clearance cookie.
//
// IPv4 keys on the full address. IPv6 keys on the /64 prefix, for two reasons
// that point the same way:
//
//   - RFC 4941 privacy extensions rotate the interface identifier every few
//     hours, so keying on the full address silently invalidates a real user's
//     clearance mid-session and re-challenges them.
//   - A /64 is the smallest routable allocation an end site receives, so an
//     attacker keyed on /128 has 2^64 free identities against every counter.
func clientKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
