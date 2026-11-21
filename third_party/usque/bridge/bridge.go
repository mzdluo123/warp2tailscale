// Package bridge connects application flows to an in-process WARP tunnel.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/bridge/destination"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipfragment"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var ErrWarpDown = errors.New("WARP tunnel unavailable")

type Backend interface {
	ForwardPacket(src, dst netip.Addr, packet []byte, fragmented bool) bool
	JoinClientFragments([]byte) []byte
	Ready() bool
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
	DialUDP(netip.AddrPort) (net.Conn, error)
	Close() error
}
type generation struct {
	clientFragments *ipfragment.Reassembler
	firstClientJoin sync.Once
	router          *netstack.Forwarder
	network         *netstack.Net
	ctx             context.Context
	cancel          context.CancelFunc
	interrupt       func()
	dials           sync.WaitGroup
	flows           map[*flow]struct{}
}
type backend struct {
	mu      sync.Mutex
	local   [2]netip.Addr
	current *generation
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
}
type flow struct {
	net.Conn
	b    *backend
	g    *generation
	once sync.Once
	err  error
}

func (f *flow) Close() error {
	f.once.Do(func() {
		f.err = f.Conn.Close()
		f.b.mu.Lock()
		delete(f.g.flows, f)
		f.b.mu.Unlock()
	})
	return f.err
}
func (f *flow) CloseWrite() error {
	if w, ok := f.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return errors.New("half-close requires TCP")
}
func (f *flow) TCPBufferSizes() (int64, int64) {
	if c, ok := f.Conn.(interface{ TCPBufferSizes() (int64, int64) }); ok {
		return c.TCPBufferSizes()
	}
	return 0, 0
}
func (f *flow) Done() <-chan struct{} { return f.g.ctx.Done() }

func New(parent context.Context, path string) (Backend, error) {
	return NewWithBuffers(parent, path, 0, 0)
}
func NewWithBuffers(parent context.Context, path string, send, receive int) (Backend, error) {
	return NewRouted(parent, path, send, receive, 0, nil, nil)
}

// NewRouted enables generation-scoped IP forwarding when a return path is supplied.
// The return path takes ownership of one reference to each delivered packet.
func NewRouted(parent context.Context, path string, send, receive, queue int, clientRoutes func(context.Context) ([]netip.Prefix, error), deliver func(*stack.PacketBuffer) error) (Backend, error) {
	if queue == 0 {
		queue = 32
	}
	if queue < 1 || queue > 256 {
		return nil, errors.New("invalid WARP packet queue")
	}
	for _, size := range []int{send, receive} {
		if size != 0 && (size < 4096 || size > 64<<20) {
			return nil, errors.New("invalid WARP TCP buffer size")
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
		return nil, errors.New("WARP credentials must be a regular file with mode 0600")
	}
	var cfg config.Config
	if err = json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}
	key, err := cfg.GetEcPrivateKey()
	if err != nil {
		return nil, err
	}
	peer, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		return nil, err
	}
	cert, err := internal.GenerateCert(key, &key.PublicKey)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := api.PrepareTlsConfig(key, peer, cert, internal.ConnectSNI)
	if err != nil {
		return nil, err
	}
	v4, err := netip.ParseAddr(cfg.IPv4)
	if err != nil || !v4.Is4() {
		return nil, errors.New("invalid assigned IPv4")
	}
	v6, err := netip.ParseAddr(cfg.IPv6)
	if err != nil || !v6.Is6() || v6.Is4In6() || v6.Zone() != "" {
		return nil, errors.New("invalid assigned IPv6")
	}
	endpoint, err := netip.ParseAddr(cfg.EndpointV4)
	if err != nil || !endpoint.Is4() {
		return nil, errors.New("invalid MASQUE endpoint_v4")
	}
	ctx, cancel := context.WithCancel(parent)
	b := &backend{local: [2]netip.Addr{v4, v6}, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	var pending *generation // callbacks run serially in MaintainTunnel
	go func() {
		defer close(b.done)
		maintainTunnel(ctx, api.MaintainTunnelConfig{
			TLSConfig:       tlsConfig,
			Endpoint:        net.UDPAddrFromAddrPort(netip.AddrPortFrom(endpoint, 443)),
			MTU:             1280,
			KeepalivePeriod: 30 * time.Second,
			AlwaysReconnect: true,
			ReconnectDelay:  time.Second,
			OpenDevice: func() (api.TunnelDevice, func(), error) {
				dev, n, err := netstack.CreateNetTUNWithQueue([]netip.Addr{v4, v6}, nil, 1280, queue)
				if err != nil {
					return nil, nil, err
				}
				if err := n.SetTCPBufferSizes(send, receive); err != nil {
					dev.Close()
					return nil, nil, err
				}
				gctx, gcancel := context.WithCancel(ctx)
				pending = &generation{network: n, ctx: gctx, cancel: gcancel, interrupt: dev.(interface{ InterruptPackets() }).InterruptPackets, flows: make(map[*flow]struct{})}
				adapter := api.NewNetstackAdapter(dev)
				if deliver != nil {
					clients, err := clientRoutes(gctx)
					if err != nil {
						gcancel()
						dev.Close()
						return nil, nil, err
					}
					router, err := n.EnableForwarding(gctx, clients, deliver)
					if err != nil {
						gcancel()
						dev.Close()
						return nil, nil, err
					}
					pending.router = router
					wan, client := ipfragment.New(), ipfragment.New()
					pending.clientFragments = client
					adapter = &routedDevice{TunnelDevice: adapter, local: b.local, network: n, wan: wan}
					return adapter, func() { wan.Close(); client.Close(); dev.Close() }, nil
				}
				return adapter, func() { dev.Close() }, nil
			}, OnStateChange: func(up bool) {
				if up {
					b.mu.Lock()
					b.current = pending
					b.mu.Unlock()
					log.Print("MASQUE connected ready=true")
				} else {
					b.down()
				}
			}})
	}()
	return b, nil
}
func (b *backend) down() {
	b.mu.Lock()
	g := b.current
	b.current = nil
	if g == nil {
		b.mu.Unlock()
		return
	}
	g.cancel()
	flows := make([]*flow, 0, len(g.flows))
	for f := range g.flows {
		flows = append(flows, f)
	}
	b.mu.Unlock()
	g.interrupt()
	for _, f := range flows {
		f.Close()
	}
	g.dials.Wait()
	log.Printf("MASQUE down ready=false closed=%d", len(flows))
}
func (b *backend) Ready() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current != nil && b.ctx.Err() == nil
}
func (b *backend) Close() error { b.cancel(); <-b.done; return nil }
func (b *backend) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return b.dial(ctx, dst, true)
}
func (b *backend) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	return b.dial(context.Background(), dst, false)
}
func (b *backend) dial(ctx context.Context, dst netip.AddrPort, tcp bool) (net.Conn, error) {
	b.mu.Lock()
	g := b.current
	if g == nil || b.ctx.Err() != nil {
		b.mu.Unlock()
		return nil, ErrWarpDown
	}
	g.dials.Add(1)
	b.mu.Unlock()
	defer g.dials.Done()
	if !destination.Allowed(dst) || dst.Addr() == b.local[0] || dst.Addr() == b.local[1] || (!tcp && dst.Port() != 53) {
		return nil, fmt.Errorf("unsupported destination %v", dst)
	}
	var c net.Conn
	var err error
	if tcp {
		dctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		stop := context.AfterFunc(g.ctx, cancel)
		defer stop()
		c, err = g.network.DialContextTCPAddrPort(dctx, dst)
	} else {
		c, err = g.network.DialUDPAddrPort(netip.AddrPort{}, dst)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if g != b.current || g.ctx.Err() != nil {
		if err == nil {
			c.Close()
		}
		return nil, ErrWarpDown
	}
	if err != nil {
		return nil, err
	}
	f := &flow{Conn: c, b: b, g: g}
	g.flows[f] = struct{}{}
	return f, nil
}
