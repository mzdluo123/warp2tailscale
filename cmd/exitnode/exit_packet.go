package main

import (
	"encoding/binary"
	"net/netip"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

func (cfg config) exitPacketHandler(forward func(netip.Addr, netip.Addr, []byte, bool) bool) func(*packet.Parsed) bool {
	allowUDP, allowICMP := cfg.Policy.UDP == "all", cfg.Policy.ICMP
	blockQUIC := cfg.Policy.BlockQUIC443
	return func(p *packet.Parsed) bool {
		switch p.IPProto {
		case ipproto.UDP:
			if !allowUDP {
				return false
			}
			if blockQUIC && p.Dst.Port() == 443 && isQUICClientLongHeader(udpPayload(p)) {
				return true // Consume the packet without forwarding it to WARP.
			}
		case ipproto.ICMPv4, ipproto.ICMPv6:
			if !allowICMP {
				return false
			}
		default:
			return false
		}
		forward(p.Src.Addr(), p.Dst.Addr(), p.Buffer(), p.SourceFragmented)
		return true
	}
}

// udpPayload is bounded by both the UDP and IP lengths. Parsed.Transport can
// include bytes beyond the IP datagram, and Parsed.Payload ignores UDP length.
func udpPayload(p *packet.Parsed) []byte {
	const udpHeaderLen = 8
	udp, ip := p.Transport(), p.Buffer()
	var ipLen int
	if p.IPVersion == 4 {
		ipLen = int(binary.BigEndian.Uint16(ip[2:4]))
	} else {
		ipLen = 40 + int(binary.BigEndian.Uint16(ip[4:6]))
	}
	transportLen := ipLen - (len(ip) - len(udp))
	if transportLen < udpHeaderLen {
		return nil
	}
	n := int(binary.BigEndian.Uint16(udp[4:6]))
	if n < udpHeaderLen || n > transportLen {
		return nil
	}
	return udp[udpHeaderLen:n]
}

// isQUICClientLongHeader recognizes QUIC v1/v2 Initial, 0-RTT and Handshake
// packets. Short headers cannot be distinguished reliably from ordinary UDP.
func isQUICClientLongHeader(b []byte) bool {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return false
	}
	// The fixed bit may be greased (RFC 9287). Match the version and framing.
	packetType := (b[0] >> 4) & 3
	var initial, retry bool
	switch quic.Version(binary.BigEndian.Uint32(b[1:5])) {
	case quic.Version1:
		initial, retry = packetType == 0, packetType == 3
	case quic.Version2:
		initial, retry = packetType == 1, packetType == 0
	default:
		return false
	}
	if retry || (initial && len(b) < 1200) {
		return false
	}

	const maxConnIDLen = 20
	dstLen := int(b[5])
	if dstLen > maxConnIDLen || len(b) < 7+dstLen {
		return false
	}
	srcLen := int(b[6+dstLen])
	headerLen := 7 + dstLen + srcLen
	if srcLen > maxConnIDLen || len(b) < headerLen {
		return false
	}
	b = b[headerLen:]
	if initial {
		tokenLen, n, err := quicvarint.Parse(b)
		if err != nil || tokenLen > uint64(len(b)-n) {
			return false
		}
		b = b[n+int(tokenLen):]
	}
	length, n, err := quicvarint.Parse(b)
	// The protected packet number and ciphertext must fit in this datagram
	// and include the 16-byte header-protection sample, at offset 4.
	return err == nil && length >= 20 && length <= uint64(len(b)-n)
}
