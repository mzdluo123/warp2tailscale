package exit

import (
	"context"
	"net"
	"sync"
	"time"
)

// RelayDatagrams forwards a complete datagram per write. Traffic in either direction
// extends the shared idle timeout.
func RelayDatagrams(ctx context.Context, a, b net.Conn) (int64, int64) {
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()

	var mu sync.Mutex
	touch := func() {
		mu.Lock()
		defer mu.Unlock()
		t := time.Now().Add(30 * time.Second)
		a.SetDeadline(t)
		b.SetDeadline(t)
	}
	touch()
	pump := func(dst, src net.Conn, ch chan<- int64) {
		buf := make([]byte, 65535)
		var total int64
		for {
			n, e := src.Read(buf)
			if e != nil {
				break
			}
			touch()
			m, e := dst.Write(buf[:n])
			total += int64(m)
			if e != nil || m != n {
				break
			}
		}
		closeBoth()
		ch <- total
	}
	up, down := make(chan int64, 1), make(chan int64, 1)
	go pump(b, a, up)
	go pump(a, b, down)
	return <-up, <-down
}
