package tsnet

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/types/nettype"
)

func TestFallbackUDPPriority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url, _ := startControl(t)
	s, local, _ := startServer(t, ctx, url, "udp")
	ln, err := s.Listen("udp", ":5353")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	calls := 0
	unregister := s.RegisterFallbackUDPHandler(func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		calls++
		if dst.Port() != 53 {
			return nil, true
		}
		return func(nettype.ConnPacketConn) {}, true
	})
	src := netip.MustParseAddrPort("100.64.0.2:11000")
	if h, ok := s.getUDPHandlerForFlow(src, netip.AddrPortFrom(local, 5353)); h == nil || !ok || calls != 0 {
		t.Fatal("local listener lost priority")
	}
	dns := netip.MustParseAddrPort("[2606:4700:4700::1111]:53")
	if h, ok := s.getUDPHandlerForFlow(src, dns); h == nil || !ok || calls != 1 {
		t.Fatal("missing DNS handler")
	}
	if h, ok := s.getUDPHandlerForFlow(src, netip.MustParseAddrPort("1.1.1.1:443")); h != nil || !ok {
		t.Fatal("UDP/443 leaked")
	}
	unregister()
	if h, ok := s.getUDPHandlerForFlow(src, dns); h != nil || !ok || calls != 2 {
		t.Fatal("default must reject after unregister")
	}
}
