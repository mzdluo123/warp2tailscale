package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/bridge"
	"gopkg.in/yaml.v3"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipfragment"
	"tailscale.com/ipn"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/nettype"

	"warp2tailscale/internal/exit"
	"warp2tailscale/internal/metrics"
	"warp2tailscale/internal/policy"
)

type config struct {
	Logging struct {
		QuietFlows bool `yaml:"quiet_flows"`
	}
	Runtime struct {
		MaxProcs int   `yaml:"max_procs"`
		UDPGSO   *bool `yaml:"udp_gso"`
	}
	TCP struct {
		Send          int           `yaml:"send_buffer_bytes"`
		Receive       int           `yaml:"receive_buffer_bytes"`
		ShutdownGrace time.Duration `yaml:"shutdown_grace_period"`
	}
	Tailscale struct {
		Hostname string
		Port     uint16
		StateDir string `yaml:"state_dir"`
	}
	Warp struct {
		ConfigPath       string `yaml:"config_path"`
		Transport        string
		PacketQueue      int  `yaml:"packet_queue_packets"`
		HTTP3ReceiveRing bool `yaml:"http3_receive_ring"`
		MTU              int
		ReconnectDelay   time.Duration `yaml:"reconnect_delay"`
		FailClosed       bool          `yaml:"fail_closed"`
	}
	Congestion struct {
		Type        string
		Profile     string        `yaml:"bbrProfile"`
		InitialCwnd int           `yaml:"initial_cwnd_packets"`
		PacingBurst int           `yaml:"pacing_burst_packets"`
		RateLimit   int64         `yaml:"max_pacing_bytes_per_second"`
		BurstWindow time.Duration `yaml:"pacing_burst_window"`
	}
	Policy struct {
		UDP        string
		ICMP       bool
		IPv4, IPv6 bool
	}
}

func load(path string) (config, error) {
	var cfg config
	f, e := os.Open(path)
	if e != nil {
		return cfg, e
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if e = d.Decode(&cfg); e != nil {
		return cfg, e
	}
	if e = d.Decode(new(any)); e != io.EOF {
		return cfg, errors.New("expected one YAML document")
	}
	return cfg, nil
}
func (cfg config) validate() error {
	if cfg.TCP.ShutdownGrace < 0 {
		return errors.New("tcp.shutdown_grace_period must be nonnegative")
	}
	if cfg.Warp.PacketQueue < 0 || cfg.Warp.PacketQueue > 256 {
		return errors.New("WARP packet queue must be 0..256")
	}
	if cfg.Runtime.MaxProcs < 0 {
		return errors.New("runtime.max_procs must be nonnegative")
	}
	if iw := cfg.Congestion.InitialCwnd; iw != 0 && (iw < 4 || iw > 128) {
		return errors.New("BBR initial cwnd must be 4..128 packets or 0 for default")
	}
	if burst := cfg.Congestion.PacingBurst; burst < 0 || burst > 32 {
		return errors.New("BBR pacing burst must be 1..32 packets or 0 for default")
	}
	if cfg.Congestion.RateLimit < 0 {
		return errors.New("negative max pacing rate")
	}
	if window := cfg.Congestion.BurstWindow; window < 0 || window > 10*time.Millisecond {
		return errors.New("BBR pacing burst window must be 0..10ms")
	}
	for _, size := range []int{cfg.TCP.Send, cfg.TCP.Receive} {
		if size != 0 && (size < 4096 || size > 64<<20) {
			return fmt.Errorf("TCP buffer must be 0 or 4096..67108864 bytes (got %d)", size)
		}
	}
	if cfg.Tailscale.Hostname == "" || cfg.Tailscale.StateDir == "" || cfg.Warp.ConfigPath == "" || cfg.Warp.Transport != "masque-h3" || cfg.Warp.MTU != 1280 || cfg.Warp.ReconnectDelay != time.Second || !cfg.Warp.FailClosed || (cfg.Policy.UDP != "dns-only" && cfg.Policy.UDP != "all") || !cfg.Policy.IPv4 || !cfg.Policy.IPv6 || cfg.Congestion.Profile != "standard" || cfg.Congestion.Type != "bbr" && cfg.Congestion.Type != "cubic" && cfg.Congestion.Type != "reno" {
		return errors.New("unsupported configuration; see config.example.yaml")
	}
	return nil
}
func run(ctx context.Context, cfg config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.Runtime.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.Runtime.MaxProcs)
	}
	if cfg.Runtime.UDPGSO != nil {
		// Both libraries probe each socket and handle unsupported interfaces.
		// Apply the process setting before either transport opens its sockets.
		disable := strconv.FormatBool(!*cfg.Runtime.UDPGSO)
		for _, key := range []string{"TS_DEBUG_DISABLE_UDP_GSO", "QUIC_GO_DISABLE_GSO"} {
			if err := os.Setenv(key, disable); err != nil {
				return err
			}
		}
	}
	if err := os.Setenv("QUIC_GO_HTTP3_DATAGRAM_RING", strconv.FormatBool(cfg.Warp.HTTP3ReceiveRing)); err != nil {
		return err
	}
	traceFlows := !cfg.Logging.QuietFlows
	s := &tsnet.Server{ExitBBRQuiet: cfg.Logging.QuietFlows, Hostname: cfg.Tailscale.Hostname, Port: cfg.Tailscale.Port, Dir: cfg.Tailscale.StateDir, AuthKey: os.Getenv("TS_AUTHKEY"), ExitTCPCC: cfg.Congestion.Type, ExitBBRInitialCwnd: cfg.Congestion.InitialCwnd, ExitBBRPacingBurst: cfg.Congestion.PacingBurst, ExitBBRBurstWindow: cfg.Congestion.BurstWindow, ExitBBRRateLimit: cfg.Congestion.RateLimit, ExitTCPSendBuffer: cfg.TCP.Send, ExitTCPReceiveBuffer: cfg.TCP.Receive}
	up := make(chan struct{})
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
	// Keep both TCP legs alive until the Tailnet stack has issued its resets.
	flowCtx, stopFlows := context.WithCancel(context.WithoutCancel(ctx))
	defer stopFlows()
	warp, e := bridge.NewRouted(flowCtx, cfg.Warp.ConfigPath, cfg.TCP.Send, cfg.TCP.Receive, cfg.Warp.PacketQueue, clientRoutes, deliver)
	if e != nil {
		return e
	}
	if deliver != nil {
		s.NormalizeExitPacket = func(p *packet.Parsed) bool {
			proto, frag := ipfragment.Protocol(p.Buffer())
			if !frag || !tsaddr.IsTailscaleIP(p.Src.Addr()) || !policy.Allowed(netip.AddrPortFrom(p.Dst.Addr(), 1)) {
				return true
			}
			if !(proto == 17 && cfg.Policy.UDP == "all" || (proto == 1 || proto == 58) && cfg.Policy.ICMP) {
				return true
			}
			joined := warp.JoinClientFragments(p.Buffer())
			if joined == nil {
				return false
			}
			p.Decode(joined)
			p.SourceFragmented = true
			return true
		}
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
	s.ExitDNSForward = func(ctx context.Context, q []byte, src netip.AddrPort) ([]byte, error) {
		answer, err := exit.PeerDNS(ctx, q, warp.DialTCP)
		if !traceFlows {
			return answer, err
		}
		if err != nil {
			log.Printf("WARP peer DNS src=%s: %v", src, err)
		} else {
			log.Printf("WARP peer DNS src=%s rcode=%d bytes=%d", src, answer[3]&15, len(answer))
		}
		return answer, err
	}
	defer s.Close()
	defer warp.Close()
	defer func() {
		if ctx.Err() != nil {
			count := s.BeginExitTCPShutdown()
			grace := cfg.TCP.ShutdownGrace
			if grace == 0 {
				grace = 2 * time.Second
			}
			log.Printf("shutting down TCP: aborting %d endpoints, allowing %s for delivery", count, grace)
			// Keep servicing peer ACKs and new SYNs during this window as well.
			time.Sleep(grace)
		}
		stopFlows()
	}()
	var rejected atomic.Uint64
	allow := func(proto string, src, dst netip.AddrPort) bool {
		ready := warp.Ready()
		ok := ready && policy.Allowed(dst) && (proto == "tcp" || dst.Port() == 53)
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
			u, e := warp.DialTCP(flowCtx, dst)
			if e != nil {
				if traceFlows {
					log.Printf("WARP TCP %s -> %s: %v", src, dst, e)
				}
				return
			}
			defer u.Close()
			if traceFlows {
				log.Printf("WARP TCP %s -> %s family=%s ready=%t", src, dst, family(dst), warp.Ready())
				metrics.Buffers(c, u, src, dst)
			}
			up, down := exit.Relay(flowCtx, c, u)
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
			u, e := warp.DialUDP(dst)
			if e != nil {
				if traceFlows {
					log.Printf("WARP UDP %s -> %s: %v", src, dst, e)
				}
				return
			}
			defer u.Close()
			if traceFlows {
				log.Printf("WARP UDP %s -> %s family=%s ready=%t", src, dst, family(dst), warp.Ready())
			}
			up, down := exit.DNS(c, u)
			if traceFlows {
				log.Printf("DNS %s -> %s up=%d down=%d", src, dst, up, down)
			}
		}, true
	})
	if _, e = s.Up(ctx); e != nil {
		return e
	}
	close(up)
	lc, e := s.LocalClient()
	if e != nil {
		return e
	}
	_, e = lc.EditPrefs(ctx, &ipn.MaskedPrefs{AdvertiseRoutesSet: true, Prefs: ipn.Prefs{AdvertiseRoutes: tsaddr.ExitRoutes()}})
	if e != nil {
		return fmt.Errorf("advertise exit routes: %w", e)
	}
	watchTestCC(ctx, s)
	log.Printf("advertised exit routes hostname=%s cc=%s", cfg.Tailscale.Hostname, cfg.Congestion.Type)
	<-ctx.Done()
	return nil
}
func family(dst netip.AddrPort) string {
	if dst.Addr().Is4() {
		return "IPv4"
	}
	return "IPv6"
}
func main() {
	path := flag.String("config", "config.example.yaml", "YAML configuration")
	cc := flag.String("cc", "", "client-facing TCP congestion control: bbr, cubic, reno")
	send := flag.Int("tcp-send-buffer", 0, "per-connection send buffer bytes on both TCP stacks (0 = native defaults)")
	receive := flag.Int("tcp-receive-buffer", 0, "per-connection receive buffer bytes on both TCP stacks (0 = native defaults)")
	iw := flag.Int("bbr-initial-cwnd", 0, "BBR initial window in MSS (default 32)")
	burst := flag.Int("bbr-pacing-burst", 0, "BBR maximum pacing quantum in MSS (default 1)")
	flag.Parse()
	cfg, err := load(*path)
	if err != nil {
		log.Fatal(err)
	}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "bbr-initial-cwnd":
			cfg.Congestion.InitialCwnd = *iw
		case "bbr-pacing-burst":
			cfg.Congestion.PacingBurst = *burst
		case "cc":
			cfg.Congestion.Type = *cc
		case "tcp-send-buffer":
			cfg.TCP.Send = *send
		case "tcp-receive-buffer":
			cfg.TCP.Receive = *receive
		}
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if e := run(ctx, cfg); e != nil {
		log.Fatal(e)
	}
}
