// Package ipfragment normalizes fragmented UDP and ICMP before firewall and NAT
// lookup. It uses gVisor's bounded reassembler and overlapping-fragment checks.
package ipfragment

import (
	"encoding/binary"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/fragmentation"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Reassembler struct{ cache *fragmentation.Fragmentation }

func New() *Reassembler {
	return &Reassembler{fragmentation.NewFragmentation(8, 4<<20, 3<<20, 30*time.Second, tcpip.NewStdClock(), nil)}
}
func (r *Reassembler) Close() { r.cache.Release() }

// Protocol identifies fragmented IP without reading a port from a later fragment.
func Protocol(p []byte) (uint8, bool) {
	if len(p) >= 20 && p[0]>>4 == 4 && binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return p[9], true
	}
	if len(p) >= 48 && p[0]>>4 == 6 && p[6] == 44 {
		return p[40], true
	}
	return 0, false
}

// Join returns nil until all validated fragments have arrived. The network
// header and protocol are taken from offset zero, including on out-of-order input.
func (r *Reassembler) Join(p []byte) []byte {
	proto, ok := Protocol(p)
	if !ok {
		return nil
	}
	var id fragmentation.FragmentID
	var offset, hlen, total int
	var more bool
	ipv6 := p[0]>>4 == 6
	if ipv6 {
		if proto != 17 && proto != 58 {
			return nil
		}
		total = 40 + int(binary.BigEndian.Uint16(p[4:6]))
		hlen = 48
		if p[41] != 0 || p[43]&6 != 0 {
			return nil
		}
		offset = int(binary.BigEndian.Uint16(p[42:44]) & 0xfff8)
		more = p[43]&1 != 0
		id = fragmentation.FragmentID{Source: tcpip.AddrFromSlice(p[8:24]), Destination: tcpip.AddrFromSlice(p[24:40]), ID: binary.BigEndian.Uint32(p[44:48])}
	} else {
		if proto != 17 && proto != 1 {
			return nil
		}
		h := header.IPv4(p)
		hlen = int(h.HeaderLength())
		total = int(h.TotalLength())
		if hlen < 20 || hlen > len(p) || !h.IsChecksumValid() {
			return nil
		}
		offset = int(h.FragmentOffset())
		more = h.More()
		id = fragmentation.FragmentID{Source: h.SourceAddress(), Destination: h.DestinationAddress(), ID: uint32(h.ID()), Protocol: proto}
	}
	end := offset + total - hlen
	if total <= hlen || total > len(p) || end > 65535 || more && (total-hlen)%8 != 0 {
		return nil
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p[:total])})
	defer pkt.DecRef()
	pkt.NetworkHeader().Consume(hlen)
	joined, next, ready, err := r.cache.Process(id, uint16(offset), uint16(end-1), more, proto, pkt)
	if err != nil || !ready {
		return nil
	}
	defer joined.DecRef()
	h := joined.NetworkHeader().Slice()
	if ipv6 {
		h = h[:40]
	}
	if joined.Data().Size()+len(h) > 65535 && !ipv6 {
		return nil
	}
	out := make([]byte, len(h)+joined.Data().Size())
	copy(out, h)
	data := joined.Data().AsRange()
	copy(out[len(h):], data.ToSlice())
	if ipv6 {
		out[6] = next
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	} else {
		h := header.IPv4(out)
		h.SetTotalLength(uint16(len(out)))
		h.SetFlagsFragmentOffset(0, 0)
		h.SetChecksum(0)
		h.SetChecksum(^h.CalculateChecksum())
	}
	return out
}
