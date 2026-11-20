//go:build mvptest && unix

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tailscale.com/tsnet"
)

// Change the default for future endpoints while keeping the WARP session alive.
func watchTestCC(ctx context.Context, s *tsnet.Server) {
	startInnerProbe(ctx, s)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	go func() {
		defer signal.Stop(sig)
		cc := s.ExitTCPCC
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				if cc == "bbr" {
					cc = "cubic"
				} else {
					cc = "bbr"
				}
				err := s.SetTestExitCC(cc)
				log.Printf("test: new TCP endpoints cc=%s err=%v", cc, err)
			}
		}
	}()
}
