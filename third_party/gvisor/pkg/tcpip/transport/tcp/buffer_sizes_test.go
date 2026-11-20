package tcp_test

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"testing"
)

func TestEndpointBufferSelection(t *testing.T) {
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer s.Close()
	var defaults tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &defaults); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ send, recv, wantRecv int }{{8192, 0, defaults.Default}, {65536, 131072, 131072}} {
		if err := tcp.SetBufferSizes(s, tc.send, tc.recv); err != nil {
			t.Fatal(err)
		}
		ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, new(waiter.Queue))
		if err != nil {
			t.Fatal(err)
		}
		tx, rx := ep.SocketOptions().GetSendBufferSize(), ep.SocketOptions().GetReceiveBufferSize()
		ep.Close()
		if tx != int64(tc.send) || rx != int64(tc.wantRecv) {
			t.Fatalf("socket buffers %d/%d, want %d/%d", tx, rx, tc.send, tc.wantRecv)
		}
	}
}
