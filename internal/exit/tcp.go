package exit

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

var relayBuffers = sync.Pool{New: func() any { return new([32 << 10]byte) }}

// Relay preserves TCP half-close while bounding the lifetime of a stalled peer.
func Relay(ctx context.Context, a, b net.Conn) (int64, int64) {
	deadline := time.Now().Add(time.Hour)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	copyHalf := func(dst, src net.Conn, ch chan<- int64) {
		buf := relayBuffers.Get().(*[32 << 10]byte)
		n, err := io.CopyBuffer(dst, src, buf[:])
		relayBuffers.Put(buf)
		if err == nil {
			if w, ok := dst.(interface{ CloseWrite() error }); ok {
				err = w.CloseWrite()
			}
		}
		if err != nil {
			a.Close()
			b.Close()
		}
		ch <- n
	}
	up, down := make(chan int64, 1), make(chan int64, 1)
	go copyHalf(b, a, up)
	go copyHalf(a, b, down)
	// A clean EOF on the upstream alone does not distinguish FIN from tunnel loss.
	done := make(chan struct{})
	defer close(done)
	var lost <-chan struct{}
	if f, ok := b.(interface{ Done() <-chan struct{} }); ok {
		lost = f.Done()
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-lost:
		case <-done:
			return
		}
		a.Close()
		b.Close()
	}()
	return <-up, <-down
}
