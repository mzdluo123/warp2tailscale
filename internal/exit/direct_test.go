package exit

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
)

func TestDirectRejectsNonPublicAndHostAddresses(t *testing.T) {
	ctx := context.Background()
	for _, dst := range []string{"127.0.0.1:443", "100.64.0.1:443", "192.168.1.1:443", "[::1]:443", "[fd00::1]:443"} {
		addr := netip.MustParseAddrPort(dst)
		for _, dial := range []func(context.Context, netip.AddrPort) (net.Conn, error){DialDirectTCP, DialDirectUDP} {
			if conn, err := dial(ctx, addr); err == nil {
				conn.Close()
				t.Errorf("dial accepted %s", dst)
			}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		subnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(subnet.IP)
		if ok && checkDirectDestination(netip.AddrPortFrom(ip.Unmap(), 443)) == nil {
			t.Errorf("accepted host address %s", ip)
		}
	}
}

func TestDirectEchoReply(t *testing.T) {
	for _, req := range []packet.Header{
		packet.ICMP4Header{IP4Header: packet.IP4Header{
			Src: netip.MustParseAddr("100.64.0.2"), Dst: netip.MustParseAddr("1.1.1.1"),
		}, Type: packet.ICMP4EchoRequest},
		packet.ICMP6Header{IP6Header: packet.IP6Header{
			Src: netip.MustParseAddr("fd7a:115c:a1e0::2"), Dst: netip.MustParseAddr("2606:4700:4700::1111"),
		}, Type: packet.ICMP6EchoRequest},
	} {
		// Keep the payload length odd to exercise the last checksum byte.
		payload := []byte{0xaa, 0xbb, 0x00, 0x0f, 1, 2, 3}
		var request, reply packet.Parsed
		wire := packet.Generate(req, payload)
		request.Decode(wire)
		if !request.IsEchoRequest() || echoMessage(&request) == nil {
			t.Fatal("request has an invalid checksum")
		}
		reply.Decode(packet.Generate(echoReplyHeader(&request), request.Payload()))
		if !reply.IsEchoResponse() || echoMessage(&reply) == nil ||
			reply.Src != request.Dst || reply.Dst != request.Src || !bytes.Equal(reply.Payload(), payload) {
			t.Fatalf("wrong echo reply %x", reply.Buffer())
		}
		wire[len(wire)-1] ^= 1
		if echoMessage(&request) != nil {
			t.Fatal("accepted corrupt echo checksum")
		}
		if request.IPVersion == 4 {
			binary.BigEndian.PutUint16(wire[2:4], 23)
		} else {
			binary.BigEndian.PutUint16(wire[4:6], 3)
		}
		request.Decode(wire)
		if echoMessage(&request) != nil {
			t.Fatal("accepted echo whose declared length omitted its header")
		}
	}
}
