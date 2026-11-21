package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/Diniboy1123/usque/bridge"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipfragment"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/nettype"

	"warp2tailscale/internal/exit"
	"warp2tailscale/internal/metrics"
	"warp2tailscale/internal/policy"
)

type egress struct {
	dialTCP func(context.Context, netip.AddrPort) (net.Conn, error)
	dialUDP func(context.Context, netip.AddrPort) (net.Conn, error)
	ready   func() bool
	close   func()
}

func configureEgress(ctx context.Context, cfg config, s *tsnet.Server, up <-chan struct{}) (egress, error) {
	if cfg.egressMode() == egressDirect {
		if cfg.Policy.ICMP {
			forward, err := exit.DirectEcho(ctx, s.WriteExitPacket, !cfg.Logging.QuietFlows)
			if err != nil {
				return egress{}, err
			}
			s.ExitPacket = forward
		}
		fragments := ipfragment.New()
		s.NormalizeExitPacket = normalizeExitFragments(fragments.Join, true, cfg.Policy.ICMP)
		return egress{
			dialTCP: exit.DialDirectTCP,
			dialUDP: exit.DialDirectUDP,
			ready:   func() bool { return true },
			close:   fragments.Close,
		}, nil
	}
	if err := os.Setenv("QUIC_GO_HTTP3_DATAGRAM_RING", strconv.FormatBool(cfg.Warp.HTTP3ReceiveRing)); err != nil {
		return egress{}, err
	}
	clientRoutes := func(ctx context.Context) ([]netip.Prefix, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-up:
		}
		v4, v6 := s.TailscaleIPs()
		var routes []netip.Prefix
		for _, ip := range []netip.Addr{v4, v6} {
			if tsaddr.IsTailscaleIP(ip) {
				bits := tsaddr.CGNATRange().Bits()
				if ip.Is6() {
					bits = tsaddr.TailscaleULARange().Bits()
				}
				routes = append(routes, netip.PrefixFrom(ip, bits))
			}
		}
		if len(routes) == 0 {
			return nil, errors.New("no tailnet router addresses")
		}
		return routes, nil
	}
	var deliver func([]byte) error
	if cfg.Policy.UDP == "all" || cfg.Policy.ICMP {
		deliver = s.WriteExitPacket
	}
	warp, e := bridge.NewRouted(ctx, cfg.Warp.ConfigPath, cfg.TCP.Send, cfg.TCP.Receive, cfg.Warp.PacketQueue, clientRoutes, deliver)
	if e != nil {
		return egress{}, e
	}
	if deliver != nil {
		s.NormalizeExitPacket = normalizeExitFragments(warp.JoinClientFragments, cfg.Policy.UDP == "all", cfg.Policy.ICMP)
		s.ExitPacket = func(p *packet.Parsed) bool {
			switch p.IPProto {
			case ipproto.UDP:
				if cfg.Policy.UDP != "all" {
					return false
				}
			case ipproto.ICMPv4, ipproto.ICMPv6:
				if !cfg.Policy.ICMP {
					return false
				}
			default:
				return false
			}
			warp.ForwardPacket(p.Src.Addr(), p.Dst.Addr(), p.Buffer(), p.SourceFragmented)
			return true
		}
	}
	return egress{
		dialTCP: warp.DialTCP,
		dialUDP: func(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
			return warp.DialUDP(dst)
		},
		ready: warp.Ready,
		close: func() { warp.Close() },
	}, nil
}

func normalizeExitFragments(join func([]byte) []byte, udp, icmp bool) func(*packet.Parsed) bool {
	return func(p *packet.Parsed) bool {
		proto, fragmented := ipfragment.Protocol(p.Buffer())
		if !fragmented || !tsaddr.IsTailscaleIP(p.Src.Addr()) || !policy.Allowed(netip.AddrPortFrom(p.Dst.Addr(), 1)) {
			return true
		}
		switch ipproto.Proto(proto) {
		case ipproto.UDP:
			if !udp {
				return true
			}
		case ipproto.ICMPv4, ipproto.ICMPv6:
			if !icmp {
				return true
			}
		default:
			return true
		}
		joined := join(p.Buffer())
		if joined == nil {
			return false
		}
		p.Decode(joined)
		p.SourceFragmented = true
		return true
	}
}

func registerEgressHandlers(ctx context.Context, cfg config, s *tsnet.Server, backend egress) {
	mode := cfg.egressMode()
	traceFlows := !cfg.Logging.QuietFlows
	s.ExitDNSForward = func(ctx context.Context, q []byte, src netip.AddrPort) ([]byte, error) {
		answer, err := exit.PeerDNS(ctx, q, backend.dialTCP)
		if !traceFlows {
			return answer, err
		}
		if err != nil {
			log.Printf("egress=%s peer DNS src=%s: %v", mode, src, err)
		} else {
			log.Printf("egress=%s peer DNS src=%s rcode=%d bytes=%d", mode, src, answer[3]&15, len(answer))
		}
		return answer, err
	}
	var rejected atomic.Uint64
	allow := func(proto string, src, dst netip.AddrPort) bool {
		ready := ctx.Err() == nil && backend.ready()
		ok := ready && policy.Allowed(dst)
		if proto == "udp" {
			ok = ok && (dst.Port() == 53 || mode == egressDirect && cfg.Policy.UDP == "all")
		}
		if !ok && traceFlows {
			log.Printf("reject proto=%s src=%s dst=%s family=%s ready=%t rejects=%d", proto, src, dst, family(dst), ready, rejected.Add(1))
		}
		return ok
	}
	s.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		if !allow("tcp", src, dst) {
			return nil, true
		}
		return func(c net.Conn) {
			defer c.Close()
			u, e := backend.dialTCP(ctx, dst)
			if e != nil {
				if traceFlows {
					log.Printf("egress=%s TCP %s -> %s: %v", mode, src, dst, e)
				}
				return
			}
			defer u.Close()
			if traceFlows {
				log.Printf("egress=%s TCP %s -> %s family=%s ready=%t", mode, src, dst, family(dst), backend.ready())
				metrics.Buffers(c, u, src, dst)
			}
			up, down := exit.Relay(ctx, c, u)
			if traceFlows {
				metrics.TCP(c, src, dst, up, down)
			}
		}, true
	})
	s.RegisterFallbackUDPHandler(func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		if !allow("udp", src, dst) {
			return nil, true
		}
		return func(c nettype.ConnPacketConn) {
			defer c.Close()
			u, e := backend.dialUDP(ctx, dst)
			if e != nil {
				if traceFlows {
					log.Printf("egress=%s UDP %s -> %s: %v", mode, src, dst, e)
				}
				return
			}
			defer u.Close()
			if traceFlows {
				log.Printf("egress=%s UDP %s -> %s family=%s ready=%t", mode, src, dst, family(dst), backend.ready())
			}
			up, down := exit.RelayDatagrams(ctx, c, u)
			if traceFlows {
				log.Printf("egress=%s UDP %s -> %s up=%d down=%d", mode, src, dst, up, down)
			}
		}, true
	})
}

func family(dst netip.AddrPort) string {
	if dst.Addr().Is4() {
		return "IPv4"
	}
	return "IPv6"
}
