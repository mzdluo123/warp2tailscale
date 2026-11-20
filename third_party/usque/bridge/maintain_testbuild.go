//go:build mvptest && unix

package bridge

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Diniboy1123/usque/api"
)

// USR1 closes the live CONNECT-IP session. USR2 permits the next handshake.
// This hook exists only in explicit acceptance builds.
func maintainTunnel(ctx context.Context, cfg api.MaintainTunnelConfig) {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(sig)
	for ctx.Err() == nil {
		session, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); api.MaintainTunnel(session, cfg) }()
	active:
		for {
			select {
			case <-ctx.Done():
				cancel()
				<-done
				return
			case <-done:
				cancel()
				return
			case s := <-sig:
				if s == syscall.SIGUSR1 {
					break active
				}
			}
		}
		cancel()
		<-done
		log.Print("test: MASQUE reconnect suspended")
	paused:
		for {
			select {
			case <-ctx.Done():
				return
			case s := <-sig:
				if s == syscall.SIGUSR2 {
					break paused
				}
			}
		}
	}
}
