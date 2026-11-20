package exit_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipfragment"
	"tailscale.com/net/packet"
)

func TestJoinUDPFragments(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		var h packet.Header = &packet.UDP4Header{IP4Header: packet.IP4Header{Src: netip.MustParseAddr("100.64.0.1"), Dst: netip.MustParseAddr("203.0.113.1")}, SrcPort: 2345, DstPort: 5432}
		hs := 20
		if v6 {
			h = &packet.UDP6Header{IP6Header: packet.IP6Header{Src: netip.MustParseAddr("fd7a:115c:a1e0::1"), Dst: netip.MustParseAddr("2001:db8::1")}, SrcPort: 2345, DstPort: 5432}
			hs = 40
		}
		want := packet.Generate(h, bytes.Repeat([]byte("payload"), 330))
		makeFrag := func(offset, end int, more bool) []byte {
			f := append([]byte(nil), want[:hs]...)
			if v6 {
				f[6] = 44
				f = append(f, 17, 0, 0, 0, 0, 0, 0, 4)
				binary.BigEndian.PutUint16(f[42:44], uint16(offset))
				if more {
					f[43] |= 1
				}
				binary.BigEndian.PutUint16(f[4:6], uint16(8+end-offset))
			} else {
				h := header.IPv4(f)
				flags := uint8(0)
				if more {
					flags = header.IPv4FlagMoreFragments
				}
				h.SetFlagsFragmentOffset(flags, uint16(offset))
				h.SetTotalLength(uint16(hs + end - offset))
				h.SetChecksum(0)
				h.SetChecksum(^h.CalculateChecksum())
			}
			return append(f, want[hs+offset:hs+end]...)
		}
		cache := ipfragment.New()
		if p := cache.Join(makeFrag(1200, len(want)-hs, false)); p != nil {
			t.Fatal("delivered incomplete datagram")
		}
		got := cache.Join(makeFrag(0, 1200, true))
		cache.Close()
		if cache.Join(makeFrag(0, 1200, true)) != nil {
			t.Fatal("closed reassembler accepted a fragment")
		}
		cache.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("IPv6=%v reassembled %d bytes, want %d", v6, len(got), len(want))
		}
	}
}
