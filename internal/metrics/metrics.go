package metrics

import (
	"log"
	"net"
	"net/netip"
	"time"
)

func TCP(c net.Conn, src, dst netip.AddrPort, up, down int64) {
	if endpoint, ok := c.(interface {
		TCPMetrics() (string, time.Duration, uint64)
	}); ok {
		cc, rtt, retrans := endpoint.TCPMetrics()
		log.Printf("TCP %s -> %s up=%d down=%d cc=%s rtt=%s retransmits=%d", src, dst, up, down, cc, rtt, retrans)
	}
}

// Buffers records actual socket capacities after both handshakes.
func Buffers(client, upstream net.Conn, src, dst netip.AddrPort) {
	type sizes interface{ TCPBufferSizes() (int64, int64) }
	a, aok := client.(sizes)
	b, bok := upstream.(sizes)
	if aok && bok {
		as, ar := a.TCPBufferSizes()
		bs, br := b.TCPBufferSizes()
		log.Printf("TCP %s -> %s client_send=%d client_receive=%d warp_send=%d warp_receive=%d", src, dst, as, ar, bs, br)
	}
}
