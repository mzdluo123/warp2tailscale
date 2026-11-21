package exit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"warp2tailscale/internal/policy"
)

var directDialer = net.Dialer{Timeout: 12 * time.Second}

func DialDirectTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return dialDirect(ctx, "tcp", dst)
}

func DialDirectUDP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return dialDirect(ctx, "udp", dst)
}

func dialDirect(ctx context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
	if err := checkDirectDestination(dst); err != nil {
		return nil, err
	}
	// The destination is numeric. The host chooses the route and source IP.
	return directDialer.DialContext(ctx, network, dst.String())
}

func checkDirectDestination(dst netip.AddrPort) error {
	if !policy.Allowed(dst) {
		return fmt.Errorf("unsupported destination %v", dst)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("list host addresses: %w", err)
	}
	for _, addr := range addrs {
		if subnet, ok := addr.(*net.IPNet); ok && subnet.IP.Equal(dst.Addr().AsSlice()) {
			return fmt.Errorf("destination %v is assigned to the host", dst)
		}
	}
	return nil
}
