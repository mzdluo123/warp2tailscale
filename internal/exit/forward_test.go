package exit_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipfragment"
	"tailscale.com/net/packet"
)

// A real gVisor peer with a closed UDP port emits an ICMP error. Check both
// addresses and the quoted UDP tuple after translation back to the client.
func TestForwardedUDPError(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		client, wan, dst, prefix := "100.64.0.9", "198.51.100.1", "203.0.113.9", "100.64.0.1/10"
		if v6 {
			client, wan, dst, prefix = "fd7a:115c:a1e0::9", "2001:db8:1::1", "2001:db8:2::9", "fd7a:115c:a1e0::1/48"
		}
		t.Run(dst, func(t *testing.T) {
			makeDevice := func(ip string) (tun.Device, *netstack.Net) {
				d, n, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, nil, 1280)
				if err != nil {
					t.Fatal(err)
				}
				return d, n
			}
			router, n := makeDevice(wan)
			internet, remote := makeDevice(dst)
			ctx, cancel := context.WithCancel(context.Background())
			var pumps sync.WaitGroup
			defer func() {
				cancel()
				for _, d := range []tun.Device{router, internet} {
					d.(interface{ InterruptPackets() }).InterruptPackets()
				}
				pumps.Wait()
				router.Close()
				internet.Close()
			}()
			result := make(chan []byte, 2)
			f, err := n.EnableForwarding(ctx, []netip.Prefix{netip.MustParsePrefix(prefix)}, func(p []byte) error {
				select {
				case result <- p:
				case <-ctx.Done():
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			connect := func(from, to tun.Device) {
				defer pumps.Done()
				wanFragments := ipfragment.New()
				defer wanFragments.Close()
				buf := make([]byte, 1500)
				sizes := make([]int, 1)
				for {
					if _, err := from.Read([][]byte{buf}, sizes, 0); err != nil {
						return
					}
					if _, frag := ipfragment.Protocol(buf[:sizes[0]]); frag && to == router {
						if p := wanFragments.Join(buf[:sizes[0]]); p != nil {
							n.InjectReassembledWAN(p)
						}
						continue
					}
					if _, err := to.Write([][]byte{buf[:sizes[0]]}, 0); err != nil {
						return
					}
				}
			}
			pumps.Add(2)
			go connect(router, internet)
			go connect(internet, router)
			srcIP, dstIP := netip.MustParseAddr(client), netip.MustParseAddr(dst)
			var h packet.Header = &packet.UDP4Header{IP4Header: packet.IP4Header{Src: srcIP, Dst: dstIP}, SrcPort: 33001, DstPort: 33002}
			if v6 {
				h = &packet.UDP6Header{IP6Header: packet.IP6Header{Src: srcIP, Dst: dstIP}, SrcPort: 33001, DstPort: 33002}
			}
			f.Inject(v6, packet.Generate(h, []byte("closed port")), false)
			select {
			case <-time.After(2 * time.Second):
				t.Fatal("missing return ICMP")
			case p := <-result:
				offset, typ := 20, byte(3)
				if v6 {
					offset, typ = 40, 1
				}
				var outer, inner packet.Parsed
				outer.Decode(p)
				if len(p) < offset+8+offset+8 || outer.Dst.Addr() != srcIP || outer.Src.Addr() != dstIP || p[offset] != typ {
					t.Fatalf("wrong ICMP envelope %x", p)
				}
				quote := p[offset+8:]
				inner.Decode(quote)
				if inner.Src.Addr() != srcIP || inner.Dst.Addr() != dstIP || binary.BigEndian.Uint16(quote[offset:]) != 33001 {
					t.Fatalf("quoted tuple not restored: %x", quote)
				}
			}
			socket, err := remote.ListenUDPAddrPort(netip.AddrPortFrom(dstIP, 33002))
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			socket.SetDeadline(time.Now().Add(2 * time.Second))
			payload := bytes.Repeat([]byte("large datagram"), 190)
			f.Inject(v6, packet.Generate(h, payload), true)
			buf := make([]byte, 4096)
			l, from, err := socket.ReadFrom(buf)
			if err != nil || !bytes.Equal(buf[:l], payload) {
				t.Fatalf("routed large datagram: bytes=%d err=%v", l, err)
			}
			if _, err = socket.WriteTo(payload, from); err != nil {
				t.Fatal(err)
			}
			replies := ipfragment.New()
			defer replies.Close()
			deadline := time.After(2 * time.Second)
			for {
				select {
				case p := <-result:
					if _, frag := ipfragment.Protocol(p); !frag {
						t.Fatalf("wanted IP fragment, got %x", p[:min(48, len(p))])
					}
					joined := replies.Join(p)
					if joined == nil {
						continue
					}
					var received packet.Parsed
					received.Decode(joined)
					if received.Dst != netip.AddrPortFrom(srcIP, 33001) || !bytes.Equal(received.Payload(), payload) {
						t.Fatal("wrong reassembled reply")
					}
					return
				case <-deadline:
					t.Fatal("missing fragmented response")
				}
			}
		})
	}
}
