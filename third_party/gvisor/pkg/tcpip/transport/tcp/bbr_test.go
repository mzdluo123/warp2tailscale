package tcp_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Withhold all data ACKs for the first eight segments. Any observed spacing
// inside this initial window comes from the sender, independent of ACK timing.
func TestBBRPacketPacing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	makeStack := func(last byte) (*stack.Stack, *channel.Endpoint, tcpip.Address) {
		s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
		ep := channel.New(1024, 1280, "")
		ip := tcpip.AddrFrom4([4]byte{192, 0, 2, last})
		if e := s.CreateNIC(1, ep); e != nil {
			t.Fatal(e)
		}
		if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: ip.WithPrefix()}, stack.AddressProperties{}); e != nil {
			t.Fatal(e)
		}
		s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
		return s, ep, ip
	}
	server, a, ip := makeStack(1)
	defer server.Close()
	client, b, _ := makeStack(2)
	defer client.Close()
	cc := tcpip.CongestionControlOption("bbr")
	if e := server.SetTransportProtocolOption(tcp.ProtocolNumber, &cc); e != nil {
		t.Fatal(e)
	}
	addr := tcpip.FullAddress{NIC: 1, Addr: ip, Port: 8080}
	ln, e := gonet.ListenTCP(server, addr, ipv4.ProtocolNumber)
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	elapsed := make(chan time.Duration, 1)
	dataStarted := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	link := func(src, dst *channel.Endpoint, forward bool) {
		defer wg.Done()
		count := 0
		var start time.Time
		for {
			p := src.ReadContext(ctx)
			if p == nil {
				return
			}
			if forward && p.Data().Size() > 0 {
				count++
				if count == 1 {
					start = time.Now()
					close(dataStarted)
				}
				if count == 8 {
					elapsed <- time.Since(start)
					close(release)
				}
			} else if !forward {
				select {
				case <-dataStarted:
					select {
					case <-release:
					case <-ctx.Done():
						p.DecRef()
						return
					}
				default:
				}
			}
			inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: p.ToBuffer()})
			dst.InjectInbound(ipv4.ProtocolNumber, inbound)
			inbound.DecRef()
			p.DecRef()
		}
	}
	wg.Add(2)
	go link(a, b, true)
	go link(b, a, false)
	defer func() { cancel(); wg.Wait() }()
	c, e := gonet.DialContextTCP(ctx, client, addr, ipv4.ProtocolNumber)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	s, e := ln.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	until, _ := ctx.Deadline()
	for _, conn := range []net.Conn{c, s} {
		conn.SetDeadline(until)
	}
	payload := bytes.Repeat([]byte{0x5a}, 32*1024)
	if _, e = s.Write(payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(c, got); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("corrupt payload")
	}
	select {
	case d := <-elapsed:
		if d < 4*time.Millisecond {
			t.Fatalf("eight MSS emitted in %s", d)
		}
		t.Logf("eight data segments before ACK: %s", d)
	default:
		t.Fatal("missing paced flight")
	}
	actual, _, _ := s.(*gonet.TCPConn).TCPMetrics()
	if actual != "bbr" {
		t.Fatal(actual)
	}
}
