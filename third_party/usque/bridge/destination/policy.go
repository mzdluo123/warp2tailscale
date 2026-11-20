package destination

import "net/netip"

// Exclude IPv4 special-purpose ranges, IPv6 transition mechanisms, documentation,
// and unallocated IPv6 space. Mapped addresses and zones are ambiguous at policy boundaries.
var excluded = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.175.48.0/24", "2620:4f:8000::/48", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()
var publicV6 = netip.MustParsePrefix("2000::/3")

func Allowed(dst netip.AddrPort) bool {
	a := dst.Addr()
	if dst.Port() == 0 || !a.IsGlobalUnicast() || a.Zone() != "" || a.IsPrivate() || a.Is6() && !publicV6.Contains(a) {
		return false
	}
	for _, p := range excluded {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
