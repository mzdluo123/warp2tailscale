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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/bridge"
	"gopkg.in/yaml.v3"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"

	"warp2tailscale/internal/exit"
	"warp2tailscale/internal/metrics"
	"warp2tailscale/internal/policy"
)

type config struct {
	TCP struct {
		Send    int `yaml:"send_buffer_bytes"`
		Receive int `yaml:"receive_buffer_bytes"`
	}
	Tailscale struct {
		Hostname string
		StateDir string `yaml:"state_dir"`
	}
	Warp struct {
		ConfigPath     string `yaml:"config_path"`
		Transport      string
		MTU            int
		ReconnectDelay time.Duration `yaml:"reconnect_delay"`
		FailClosed     bool          `yaml:"fail_closed"`
	}
	Congestion struct {
		Type        string
		Profile     string `yaml:"bbrProfile"`
		InitialCwnd int    `yaml:"initial_cwnd_packets"`
		PacingBurst int    `yaml:"pacing_burst_packets"`
	}
	Policy struct {
		UDP        string
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
	if iw := cfg.Congestion.InitialCwnd; iw != 0 && (iw < 4 || iw > 128) {
		return errors.New("BBR initial cwnd must be 4..128 packets or 0 for default")
	}
	if burst := cfg.Congestion.PacingBurst; burst < 0 || burst > 16 {
		return errors.New("BBR pacing burst must be 1..16 packets or 0 for default")
	}
	for _, size := range []int{cfg.TCP.Send, cfg.TCP.Receive} {
		if size != 0 && (size < 4096 || size > 64<<20) {
			return fmt.Errorf("TCP buffer must be 0 or 4096..67108864 bytes (got %d)", size)
		}
	}
	if cfg.Tailscale.Hostname == "" || cfg.Tailscale.StateDir == "" || cfg.Warp.ConfigPath == "" || cfg.Warp.Transport != "masque-h3" || cfg.Warp.MTU != 1280 || cfg.Warp.ReconnectDelay != time.Second || !cfg.Warp.FailClosed || cfg.Policy.UDP != "dns-only" || !cfg.Policy.IPv4 || !cfg.Policy.IPv6 || cfg.Congestion.Profile != "standard" || cfg.Congestion.Type != "bbr" && cfg.Congestion.Type != "cubic" && cfg.Congestion.Type != "reno" {
		return errors.New("unsupported configuration; see config.example.yaml")
	}
	return nil
}
func run(ctx context.Context, cfg config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	warp, e := bridge.NewWithBuffers(ctx, cfg.Warp.ConfigPath, cfg.TCP.Send, cfg.TCP.Receive)
	if e != nil {
		return e
	}
	s := &tsnet.Server{Hostname: cfg.Tailscale.Hostname, Dir: cfg.Tailscale.StateDir, AuthKey: os.Getenv("TS_AUTHKEY"), ExitTCPCC: cfg.Congestion.Type, ExitBBRInitialCwnd: cfg.Congestion.InitialCwnd, ExitBBRPacingBurst: cfg.Congestion.PacingBurst, ExitTCPSendBuffer: cfg.TCP.Send, ExitTCPReceiveBuffer: cfg.TCP.Receive}
	s.ExitDNSForward = func(ctx context.Context, q []byte, src netip.AddrPort) ([]byte, error) {
		answer, err := exit.PeerDNS(ctx, q, warp.DialTCP)
		if err != nil {
			log.Printf("WARP peer DNS src=%s: %v", src, err)
		} else {
			log.Printf("WARP peer DNS src=%s rcode=%d bytes=%d", src, answer[3]&15, len(answer))
		}
		return answer, err
	}
	defer s.Close()
	defer warp.Close()
	var rejected atomic.Uint64
	allow := func(proto string, src, dst netip.AddrPort) bool {
		ready := warp.Ready()
		ok := ready && policy.Allowed(dst) && (proto == "tcp" || dst.Port() == 53)
		if !ok {
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
			u, e := warp.DialTCP(ctx, dst)
			if e != nil {
				log.Printf("WARP TCP %s -> %s: %v", src, dst, e)
				return
			}
			defer u.Close()
			log.Printf("WARP TCP %s -> %s family=%s ready=%t", src, dst, family(dst), warp.Ready())
			metrics.Buffers(c, u, src, dst)
			up, down := exit.Relay(ctx, c, u)
			metrics.TCP(c, src, dst, up, down)
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
				log.Printf("WARP UDP %s -> %s: %v", src, dst, e)
				return
			}
			defer u.Close()
			log.Printf("WARP UDP %s -> %s family=%s ready=%t", src, dst, family(dst), warp.Ready())
			up, down := exit.DNS(c, u)
			log.Printf("DNS %s -> %s up=%d down=%d", src, dst, up, down)
		}, true
	})
	if _, e = s.Up(ctx); e != nil {
		return e
	}
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
