//go:build mvptest && unix

package main

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"tailscale.com/tsnet"
)

type probeConnKey struct{}

// Acceptance-only 8 MiB download on the node's Tailnet address. Restrict it
// to the specified peer; this measurement has no WARP or Internet upstream.
func startInnerProbe(ctx context.Context, s *tsnet.Server) {
	peer, err := netip.ParseAddr(os.Getenv("MVP_INNER_PROBE_PEER"))
	if err != nil {
		return
	}
	ip, _ := s.TailscaleIPs()
	ln, err := s.Listen("tcp4", netip.AddrPortFrom(ip, 18080).String())
	if err != nil {
		log.Printf("inner probe: %v", err)
		return
	}
	payload := bytes.Repeat([]byte{0x57}, 8<<20)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, probeConnKey{}, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, err := netip.ParseAddrPort(r.RemoteAddr)
			if err != nil || addr.Addr() != peer || r.Method != "GET" || r.URL.Path != "/download" {
				http.NotFound(w, r)
				return
			}
			c := r.Context().Value(probeConnKey{}).(net.Conn)
			w.Header().Set("Content-Length", "8388608")
			n, err := w.Write(payload)
			if m, ok := c.(interface {
				TCPMetrics() (string, time.Duration, uint64)
				TCPBufferSizes() (int64, int64)
			}); ok {
				cc, rtt, retr := m.TCPMetrics()
				tx, rx := m.TCPBufferSizes()
				log.Printf("inner_probe src=%s dst=%s bytes=%d cc=%s send=%d receive=%d rtt=%s retransmits=%d err=%v", c.LocalAddr(), addr, n, cc, tx, rx, rtt, retr, err)
			}
		})}
	go func() { <-ctx.Done(); srv.Close() }()
	go srv.Serve(ln)
}
