// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/util/eventbus/eventbustest"
)

func injectedTCP(b testing.TB, ipv6 bool, segments int) (*stack.PacketBuffer, []byte, int) {
	b.Helper()
	var h packet.Header = &packet.IP4Header{IPProto: ipproto.TCP, Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("192.0.2.2")}
	gso := stack.GSOTCPv4
	if ipv6 {
		h = &packet.IP6Header{IPProto: ipproto.TCP, Src: netip.MustParseAddr("2001:db8::1"), Dst: netip.MustParseAddr("2001:db8::2")}
		gso = stack.GSOTCPv6
	}
	tcp := make([]byte, 20+segments*1200)
	tcp[12], tcp[13] = 0x50, 0x10 // 20-byte TCP header and ACK.
	binary.BigEndian.PutUint32(tcp[4:8], 123)
	for i := 20; i < len(tcp); i++ {
		tcp[i] = byte(i % 251)
	}
	raw := packet.Generate(h, tcp)
	payload := raw[h.Len()+20:]
	var views buffer.Buffer
	// Deliberately cross both packet and MSS boundaries in the view list.
	for len(payload) != 0 {
		n := min(631, len(payload))
		views.Append(buffer.NewViewWithData(payload[:n]))
		payload = payload[n:]
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: h.Len() + 20 + 32, Payload: views})
	copy(pkt.TransportHeader().Push(20), tcp[:20])
	copy(pkt.NetworkHeader().Push(h.Len()), raw[:h.Len()])
	copy(pkt.LinkHeader().Push(4), []byte{1, 2, 3, 4}) // not part of the IP packet
	if segments > 1 {
		pkt.GSOOptions = stack.GSO{Type: gso, L3HdrLen: uint16(h.Len()), CsumOffset: 16, MSS: 1200}
	}
	return pkt, raw, h.Len()
}

func TestInjectedScatterPacket(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, segments := range []int{1, 3} {
			t.Run(fmt.Sprintf("IPv6_%t/segments_%d", ipv6, segments), func(t *testing.T) {
				pkt, raw, ipLen := injectedTCP(t, ipv6, segments)
				const offset = 16
				out := make([][]byte, segments)
				for i := range out {
					out[i] = bytes.Repeat([]byte{0xcc}, offset+len(raw))
				}
				sizes := make([]int, len(out))
				var w Wrapper
				n, err := w.injectedRead(tunInjectedRead{packet: pkt}, out, sizes, offset)
				if err != nil || n != segments {
					t.Fatalf("injectedRead: %d segments, %v", n, err)
				}
				for i := range out {
					if !bytes.Equal(out[i][:offset], bytes.Repeat([]byte{0xcc}, offset)) || sizes[i] != ipLen+20+1200 {
						t.Fatalf("segment %d: wrong headroom or size %d", i, sizes[i])
					}
					got := out[i][offset : offset+sizes[i]]
					if segments == 1 {
						if !bytes.Equal(got, raw) {
							t.Fatal("non-GSO packet changed")
						}
						continue
					}
					var p packet.Parsed
					p.Decode(got)
					if p.IPProto != ipproto.TCP || binary.BigEndian.Uint32(got[ipLen+4:]) != uint32(123+i*1200) ||
						!bytes.Equal(p.Payload(), raw[ipLen+20+i*1200:ipLen+20+(i+1)*1200]) {
						t.Fatalf("segment %d: wrong TCP sequence or payload", i)
					}
				}
			})
		}
	}
}

func TestCloseReleasesInjectedPacket(t *testing.T) {
	_, w := newFakeTUN(t.Logf, eventbustest.NewBus(t), false)
	released := 0
	inject := func() {
		t.Helper()
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:   buffer.MakeWithData([]byte{1, 2, 3}),
			OnRelease: func() { released++ },
		})
		if err := w.InjectOutboundPacketBuffer(p); err != nil {
			t.Fatal(err)
		}
	}
	inject() // Waits in the injection queue, with no reader.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	inject() // A late delivery after shutdown must release its reference too.
	if released != 2 {
		t.Fatalf("released %d of 2 packets", released)
	}
}

func BenchmarkExitInjectedPacket(b *testing.B) {
	for _, segments := range []int{1, 8} {
		b.Run(fmt.Sprintf("segments%d", segments), func(b *testing.B) {
			pkt, raw, _ := injectedTCP(b, false, segments)
			defer pkt.DecRef()
			var w Wrapper
			const offset = 16
			out := make([][]byte, segments)
			for i := range out {
				out[i] = make([]byte, offset+len(raw))
			}
			sizes := make([]int, len(out))
			b.SetBytes(int64(segments * 1200))
			b.ReportAllocs()
			for b.Loop() {
				pkt.IncRef()
				n, err := w.injectedRead(tunInjectedRead{packet: pkt}, out, sizes, offset)
				if err != nil || n != segments {
					b.Fatalf("injectedRead: %d segments, %v", n, err)
				}
			}
		})
	}
}
