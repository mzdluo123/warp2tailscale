package policy

import (
	"net/netip"
	"testing"
)

func TestDestination(t *testing.T) {
	for _, s := range []string{"100.64.0.1", "127.0.0.1", "0.9.9.9", "198.18.0.1", "::ffff:1.1.1.1", "64:ff9b::808:808", "fe80::1", "fd7a:115c:a1e0::1", "2002:0a00:0001::", "2001:db8::1", "10.0.0.1", "224.0.0.1"} {
		if Allowed(netip.AddrPortFrom(netip.MustParseAddr(s), 53)) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !Allowed(netip.AddrPortFrom(netip.MustParseAddr(s), 53)) {
			t.Fatal(s)
		}
	}
}
