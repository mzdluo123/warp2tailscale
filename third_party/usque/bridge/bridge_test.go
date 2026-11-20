package bridge

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestDisconnectDuringDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &backend{ctx: ctx}
	for i := 0; i < 3; i++ {
		dev, n, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		gctx, stop := context.WithCancel(ctx)
		g := &generation{ctx: gctx, cancel: stop, network: n, interrupt: dev.(interface{ InterruptPackets() }).InterruptPackets, flows: map[*flow]struct{}{}}
		b.current = g
		dst := netip.MustParseAddrPort("1.1.1.1:53")
		u, err := b.DialUDP(dst)
		if err != nil {
			t.Fatal(err)
		}
		res := make(chan error, 1)
		go func() { _, e := b.DialTCP(ctx, dst); res <- e }()
		// Consumption of a SYN establishes that the dial passed the Ready check.
		buf := make([]byte, 1280)
		if _, err := dev.Read([][]byte{buf}, make([]int, 1), 0); err != nil {
			t.Fatal(err)
		}
		b.down()
		if err := <-res; !errors.Is(err, ErrWarpDown) {
			t.Fatalf("pending dial: %v", err)
		}
		u.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := u.Read(buf); e == nil {
			t.Fatal("old UDP flow alive")
		}
		if _, e := b.DialUDP(dst); !errors.Is(e, ErrWarpDown) {
			t.Fatal(e)
		}
		dev.Close()
	}
}
