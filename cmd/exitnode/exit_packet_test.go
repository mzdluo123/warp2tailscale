package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"tailscale.com/net/packet"
)

func TestExitQUIC443(t *testing.T) {
	v1 := testQUICLongHeader(0xc0, quic.Version1, true)
	v2 := testQUICLongHeader(0xd0, quic.Version2, true)
	for _, tc := range []struct {
		name     string
		settings string
		v6       bool
		port     uint16
		payload  []byte
		mutate   func([]byte)
		consume  bool
		forward  bool
	}{
		{name: "default blocks v1 IPv4", port: 443, payload: v1, consume: true},
		{name: "default blocks v2 IPv6", v6: true, port: 443, payload: v2, consume: true},
		{name: "explicitly enabled", settings: "udp: all\n  block_quic_443: true\n", port: 443, payload: v1, consume: true},
		{name: "disabled", settings: "udp: all\n  block_quic_443: false\n", port: 443, payload: v1, consume: true, forward: true},
		{name: "non QUIC on 443", port: 443, payload: []byte("UDP payload"), consume: true, forward: true},
		{name: "other destination port", port: 8443, payload: v1, consume: true, forward: true},
		{name: "dns only", settings: "udp: dns-only\n", port: 443, payload: v1},
		{name: "outside UDP length", port: 443, payload: v1, mutate: func(b []byte) {
			binary.BigEndian.PutUint16(b[24:26], 8)
		}, consume: true, forward: true},
		{name: "outside IP length", port: 443, payload: v1, mutate: func(b []byte) {
			binary.BigEndian.PutUint16(b[2:4], 28)
		}, consume: true, forward: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := tc.settings
			if settings == "" {
				settings = "udp: all\n"
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("policy:\n  "+settings), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := load(path)
			if err != nil {
				t.Fatal(err)
			}
			b := testExitUDP(tc.payload, tc.port, tc.v6)
			if tc.mutate != nil {
				tc.mutate(b)
			}
			var p packet.Parsed
			p.Decode(b)
			forwarded := false
			handle := cfg.exitPacketHandler(func(netip.Addr, netip.Addr, []byte, bool) bool {
				forwarded = true
				return true
			})
			if consumed := handle(&p); consumed != tc.consume || forwarded != tc.forward {
				t.Fatalf("consumed=%t forwarded=%t; want consumed=%t forwarded=%t", consumed, forwarded, tc.consume, tc.forward)
			}
		})
	}
}

func TestQUICClientLongHeader(t *testing.T) {
	v1 := testQUICLongHeader(0xc0, quic.Version1, true)
	v2 := testQUICLongHeader(0x90, quic.Version2, true)
	for _, tc := range []struct {
		name string
		data []byte
		want bool
	}{
		{"v2 Initial with greased bit", v2, true},
		{"v1 0-RTT", testQUICLongHeader(0xd0, quic.Version1, false), true},
		{"v2 Handshake", testQUICLongHeader(0xf0, quic.Version2, false), true},
		{"v1 Retry", testQUICLongHeader(0xf0, quic.Version1, false), false},
		{"v2 Retry", testQUICLongHeader(0xc0, quic.Version2, false), false},
		{"empty", nil, false},
		{"short header", append([]byte{0x40}, v1[1:]...), false},
		{"unknown version", testQUICLongHeader(0xc0, 0x12345678, true), false},
		{"undersized Initial", v1[:1199], false},
		{"truncated CID", []byte{0xe0, 0, 0, 0, 1, 8, 0}, false},
		{"truncated length", []byte{0xe0, 0, 0, 0, 1, 0, 0, 0xff}, false},
		{"length beyond datagram", testQUICLongHeader(0xe0, quic.Version1, false)[:27], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isQUICClientLongHeader(tc.data); got != tc.want {
				t.Fatalf("detected QUIC=%t, want %t", got, tc.want)
			}
		})
	}
}

func testQUICLongHeader(first byte, version quic.Version, initial bool) []byte {
	b := binary.BigEndian.AppendUint32([]byte{first}, uint32(version))
	b = append(b, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0) // destination and source CIDs
	if initial {
		b = append(b, 1, 0xab) // token
		b = quicvarint.Append(b, uint64(1200-len(b)-2))
		return append(b, make([]byte, 1200-len(b))...)
	}
	return append(append(b, 20), make([]byte, 20)...)
}

func testExitUDP(payload []byte, port uint16, v6 bool) []byte {
	if v6 {
		return packet.Generate(&packet.UDP6Header{
			IP6Header: packet.IP6Header{Src: netip.MustParseAddr("fd7a:115c:a1e0::9"), Dst: netip.MustParseAddr("2001:db8::9")},
			SrcPort:   443, DstPort: port,
		}, payload)
	}
	return packet.Generate(&packet.UDP4Header{
		IP4Header: packet.IP4Header{Src: netip.MustParseAddr("100.64.0.9"), Dst: netip.MustParseAddr("203.0.113.9")},
		SrcPort:   443, DstPort: port,
	}, payload)
}
