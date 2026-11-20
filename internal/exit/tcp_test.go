package exit

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A server that waits for request EOF before replying checks both half-closes.
func TestRelayHalfClose(t *testing.T) {
	pair := func() (*net.TCPConn, *net.TCPConn) {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		left, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		right, err := listener.AcceptTCP()
		if err != nil {
			left.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { left.Close(); right.Close() })
		return left, right
	}
	client, a := pair()
	b, server := pair()
	end := time.Now().Add(3 * time.Second)
	client.SetDeadline(end)
	server.SetDeadline(end)
	ctx, cancel := context.WithDeadline(context.Background(), end)
	defer cancel()
	result := make(chan [2]int64, 1)
	go func() { up, down := Relay(ctx, a, b); result <- [2]int64{up, down} }()
	if _, err := io.WriteString(client, "request"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	read := func(conn net.Conn, want string) {
		got, err := io.ReadAll(conn)
		if err != nil || string(got) != want {
			t.Fatalf("read %q, err=%v; want %q", got, err, want)
		}
	}
	read(server, "request")
	if _, err := io.WriteString(server, "response"); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	read(client, "response")
	select {
	case n := <-result:
		if n != [2]int64{7, 8} {
			t.Fatal(n)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
