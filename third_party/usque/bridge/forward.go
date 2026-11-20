package bridge

import (
	"log"
	"net/netip"
	"sync"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/bridge/destination"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipfragment"
)

// Only the two WARP interface addresses may enter or leave the WAN.
type routedDevice struct {
	api.TunnelDevice
	wan                   *ipfragment.Reassembler
	network               *netstack.Net
	local                 [2]netip.Addr
	firstOutboundFragment sync.Once
	firstWANJoin          sync.Once
}

func (d *routedDevice) addressed(p []byte, source bool) bool {
	if len(p) < 20 {
		return false
	}
	switch p[0] >> 4 {
	case 4:
		offset := 16
		if source {
			offset = 12
		}
		return netip.AddrFrom4([4]byte(p[offset:offset+4])) == d.local[0]
	case 6:
		if len(p) < 40 {
			return false
		}
		offset := 24
		if source {
			offset = 8
		}
		return netip.AddrFrom16([16]byte(p[offset:offset+16])) == d.local[1]
	}
	return false
}
func (d *routedDevice) WritePacket(p []byte) error {
	if !d.addressed(p, false) {
		return nil
	}
	if proto, frag := ipfragment.Protocol(p); frag && (proto == 17 || proto == 1 || proto == 58) {
		if joined := d.wan.Join(p); joined != nil {
			d.firstWANJoin.Do(func() { log.Printf("WARP received first reassembled IP datagram size=%d", len(joined)) })
			d.network.InjectReassembledWAN(joined)
		}
		return nil
	}
	return d.TunnelDevice.WritePacket(p)
}
func (d *routedDevice) ReadPacket(p []byte) (int, error) {
	for {
		n, err := d.TunnelDevice.ReadPacket(p)
		if err != nil {
			return n, err
		}
		if d.addressed(p[:n], true) {
			if _, frag := ipfragment.Protocol(p[:n]); frag {
				d.firstOutboundFragment.Do(func() { log.Print("WARP sending fragmented IP datagram") })
			}
			return n, nil
		}
	}
}

func (b *backend) ForwardPacket(src, dst netip.Addr, p []byte, fragmented bool) bool {
	if !destination.Allowed(netip.AddrPortFrom(dst, 1)) || dst == b.local[0] || dst == b.local[1] || src.BitLen() != dst.BitLen() {
		return false
	}
	b.mu.Lock()
	g := b.current
	if g == nil || g.router == nil || g.ctx.Err() != nil {
		b.mu.Unlock()
		return false
	}
	g.dials.Add(1)
	b.mu.Unlock()
	defer g.dials.Done()
	g.router.Inject(src.Is6(), p, fragmented)
	return true
}

func (b *backend) JoinClientFragments(p []byte) []byte {
	b.mu.Lock()
	g := b.current
	if g == nil || g.clientFragments == nil || g.ctx.Err() != nil {
		b.mu.Unlock()
		return nil
	}
	g.dials.Add(1)
	b.mu.Unlock()
	defer g.dials.Done()
	joined := g.clientFragments.Join(p)
	if joined != nil {
		g.firstClientJoin.Do(func() { log.Printf("exit received first reassembled IP datagram size=%d", len(joined)) })
	}
	return joined
}
