// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipv6_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func newUDPReceiveStack(t testing.TB, proto tcpip.NetworkProtocolNumber, dst tcpip.Address) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		HandleLocal:        true,
	})
	t.Cleanup(func() {
		s.Close()
		s.Wait()
	})
	link := channel.New(1, 1500, "")
	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	addr := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: dst.WithPrefix()}
	if err := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	return s, link
}

func udpReceivePacket(src, dst tcpip.Address, payloadSize int, withDestinationOptions bool) []byte {
	udpSize := header.UDPMinimumSize + payloadSize
	var packet []byte
	var udpOffset int
	if src.Len() == header.IPv4AddressSize {
		udpOffset = header.IPv4MinimumSize
		packet = make([]byte, udpOffset+udpSize)
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: src, DstAddr: dst})
		ip.SetChecksum(^ip.CalculateChecksum())
	} else {
		udpOffset = header.IPv6MinimumSize
		if withDestinationOptions {
			udpOffset += 8 // Next Header, Hdr Ext Len (0), and six Pad1 options.
		}
		packet = make([]byte, udpOffset+udpSize)
		ip := header.IPv6(packet)
		ip.Encode(&header.IPv6Fields{PayloadLength: uint16(len(packet) - header.IPv6MinimumSize), TransportProtocol: header.UDPProtocolNumber, HopLimit: 64, SrcAddr: src, DstAddr: dst})
		if withDestinationOptions {
			ip.SetNextHeader(uint8(header.IPv6DestinationOptionsExtHdrIdentifier))
			packet[header.IPv6MinimumSize] = uint8(header.UDPProtocolNumber)
		}
	}
	transport := header.UDP(packet[udpOffset:])
	transport.Encode(&header.UDPFields{SrcPort: 1234, DstPort: 4321, Length: uint16(udpSize)})
	// The payload is zero-filled, so it doesn't contribute to the checksum.
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(udpSize))
	transport.SetChecksum(^transport.CalculateChecksum(xsum))
	return packet
}

func BenchmarkUDPReceive(b *testing.B) {
	for _, tc := range []struct {
		name     string
		protocol tcpip.NetworkProtocolNumber
		src, dst tcpip.Address
	}{
		{"IPv4", header.IPv4ProtocolNumber, tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), tcpip.AddrFrom4([4]byte{192, 0, 2, 2})},
		{"IPv6", header.IPv6ProtocolNumber, tcpip.AddrFrom16([16]byte{0: 0x20, 1: 1, 2: 0xd, 3: 0xb8, 15: 1}), tcpip.AddrFrom16([16]byte{0: 0x20, 1: 1, 2: 0xd, 3: 0xb8, 15: 2})},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s, link := newUDPReceiveStack(b, tc.protocol, tc.dst)
			received := 0
			s.SetTransportProtocolHandler(header.UDPProtocolNumber, func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
				received++
				return true
			})
			frame := udpReceivePacket(tc.src, tc.dst, 1400, false)
			b.SetBytes(int64(len(frame)))
			b.ReportAllocs()
			for b.Loop() {
				// Each ingress packet owns a single, unshared chunk.
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
				link.InjectInbound(tc.protocol, pkt)
				pkt.DecRef()
			}
			if received != b.N {
				b.Fatalf("received %d UDP packets, want %d", received, b.N)
			}
		})
	}
}

func TestUDPReceiveIPv6Ownership(t *testing.T) {
	src := tcpip.AddrFrom16([16]byte{0: 0x20, 1: 1, 2: 0xd, 3: 0xb8, 15: 1})
	dst := tcpip.AddrFrom16([16]byte{0: 0x20, 1: 1, 2: 0xd, 3: 0xb8, 15: 2})
	for name, withOptions := range map[string]bool{"fixed header": false, "destination options": true} {
		t.Run(name, func(t *testing.T) {
			const payloadSize = 32
			s, link := newUDPReceiveStack(t, header.IPv6ProtocolNumber, dst)
			received := false
			s.SetTransportProtocolHandler(header.UDPProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
				transport := header.UDP(pkt.TransportHeader().Slice())
				if id.RemoteAddress != src || id.LocalAddress != dst || pkt.Data().Size() != payloadSize || !transport.IsChecksumValid(src, dst, pkt.Data().Checksum()) {
					t.Fatalf("invalid delivered UDP packet: endpoint %+v, payload size %d", id, pkt.Data().Size())
				}
				transport.SetDestinationPort(5432)
				received = true
				return true
			})
			frame := udpReceivePacket(src, dst, payloadSize, withOptions)
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
			defer pkt.DecRef()
			link.InjectInbound(header.IPv6ProtocolNumber, pkt)
			if !received {
				t.Fatal("UDP packet was not delivered")
			}
			if got := header.UDP(pkt.TransportHeader().Slice()).DestinationPort(); got != 4321 {
				t.Fatalf("original UDP destination port = %d, want 4321", got)
			}
		})
	}
}
