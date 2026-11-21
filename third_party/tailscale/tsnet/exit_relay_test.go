// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
)

func TestExitTCPDrainsAfterHalfClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	controlURL, control := startControl(t)
	server := &Server{
		Dir:               t.TempDir(),
		ControlURL:        controlURL,
		Hostname:          "exit",
		Store:             new(mem.Store),
		Ephemeral:         true,
		ExitTCPCC:         "bbr",
		ExitBBRQuiet:      true,
		ExitBBRRateLimit:  256 << 10,
		ExitTCPSendBuffer: 1 << 20,
	}
	defer server.Close()
	addr := netip.MustParseAddrPort("192.0.2.1:8080")
	response := bytes.Repeat([]byte{0x75}, 128<<10)
	server.RegisterFallbackTCPHandler(func(_, dst netip.AddrPort) (func(net.Conn), bool) {
		if dst != addr {
			return nil, false
		}
		return func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(4 * time.Second))
			if _, err := io.Copy(io.Discard, c); err != nil {
				t.Errorf("exit read: %v", err)
				return
			}
			if _, err := c.Write(response); err != nil {
				t.Errorf("exit write: %v", err)
			}
		}, true
	})
	status, err := server.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lc, err := server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	routes := []netip.Prefix{netip.PrefixFrom(addr.Addr(), 32)}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{AdvertiseRoutes: routes}, AdvertiseRoutesSet: true,
	}); err != nil {
		t.Fatal(err)
	}
	control.SetSubnetRoutes(status.Self.PublicKey, routes)

	client, _, _ := startServer(t, ctx, controlURL, "client")
	clientLC, err := client.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientLC.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := clientLC.Ping(ctx, status.TailscaleIPs[0], tailcfg.PingTSMP); err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(ctx, "tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("read %d of %d bytes: %v", len(got), len(response), err)
	}
}
