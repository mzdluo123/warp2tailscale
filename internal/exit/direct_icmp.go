package exit

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/net/packet"
)

// DirectEcho forwards exit-node echo requests using unprivileged ping sockets.
func DirectEcho(ctx context.Context, deliver func([]byte) error, trace bool) (func(*packet.Parsed) bool, error) {
	for _, v6 := range []bool{false, true} {
		conn, err := listenPing(v6)
		if err != nil {
			return nil, fmt.Errorf("direct ICMP requires permission to open IPv4 and IPv6 ping sockets (or set policy.icmp: false): %w", err)
		}
		conn.Close()
	}

	inFlight := make(chan struct{}, 32)
	return func(p *packet.Parsed) bool {
		if !p.IsEchoRequest() {
			return false
		}
		message := echoMessage(p)
		if message == nil || ctx.Err() != nil {
			return true
		}
		select {
		case inFlight <- struct{}{}:
		default:
			return true
		}

		// The WireGuard receive buffer belongs to the packet hook. Use the
		// generated reply, which owns its payload, in the goroutine below.
		replyHeader := echoReplyHeader(p)
		reply := packet.Generate(replyHeader, message[4:])
		dst := p.Dst.Addr()
		go func() {
			defer func() { <-inFlight }()
			if err := checkDirectDestination(netip.AddrPortFrom(dst, 1)); err != nil {
				return
			}
			echo := reply[replyHeader.Len():]
			err := pingDirect(ctx, dst, int(binary.BigEndian.Uint16(echo[2:4])), echo[4:])
			if err == nil && ctx.Err() == nil {
				err = deliver(reply)
			}
			if err != nil && trace && ctx.Err() == nil {
				log.Printf("egress=direct ICMP dst=%s: %v", dst, err)
			}
		}()
		return true
	}, nil
}

func echoReplyHeader(p *packet.Parsed) packet.Header {
	if p.Dst.Addr().Is6() {
		h := p.ICMP6Header()
		h.ToResponse()
		return h
	}
	h := p.ICMP4Header()
	h.ToResponse()
	return h
}

// echoMessage checks the declared length before extracting the payload. Packet
// buffers can contain trailing bytes beyond the declared IP packet.
func echoMessage(p *packet.Parsed) []byte {
	ip, transport := p.Buffer(), p.Transport()
	length := int(header.IPv4(ip).TotalLength()) - (len(ip) - len(transport))
	initial := uint16(0)
	if p.IPVersion == 6 {
		length = int(header.IPv6(ip).PayloadLength())
		initial = header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber,
			tcpip.AddrFrom16(p.Src.Addr().As16()), tcpip.AddrFrom16(p.Dst.Addr().As16()), uint16(length))
	}
	if length < 8 || length > len(transport) || checksum.Checksum(transport[:length], initial) != 0xffff {
		return nil
	}
	return transport[:length]
}

func listenPing(v6 bool) (*icmp.PacketConn, error) {
	if v6 {
		return icmp.ListenPacket("udp6", "::")
	}
	return icmp.ListenPacket("udp4", "0.0.0.0")
}

func pingDirect(ctx context.Context, dst netip.Addr, seq int, data []byte) error {
	conn, err := listenPing(dst.Is6())
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}

	var request, response icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if dst.Is6() {
		request, response = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	message := icmp.Message{Type: request, Body: &icmp.Echo{Seq: seq, Data: data}}
	wire, err := message.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := conn.WriteTo(wire, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 0))); err != nil {
		return err
	}
	buf := make([]byte, len(wire)+1)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		peer, ok := addr.(*net.UDPAddr)
		if !ok || peer.AddrPort().Addr().Unmap() != dst || n != len(wire) {
			continue
		}
		reply, err := icmp.ParseMessage(response.Protocol(), buf[:n])
		if err != nil || reply.Type != response || reply.Code != 0 {
			continue
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if ok && echo.Seq == seq && bytes.Equal(echo.Data, data) {
			return nil
		}
	}
}
