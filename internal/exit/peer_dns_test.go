package exit

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestPeerDNS(t *testing.T) {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 345, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}},
	}
	q, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, mismatch := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		answer, err := PeerDNS(ctx, q, func(_ context.Context, addr netip.AddrPort) (net.Conn, error) {
			if addr.String() != "1.1.1.1:53" {
				t.Fatal(addr)
			}
			c, upstream := net.Pipe()
			go func() {
				defer upstream.Close()
				frame := make([]byte, 2+len(q))
				if _, err := io.ReadFull(upstream, frame); err != nil || int(binary.BigEndian.Uint16(frame)) != len(q) {
					return
				}
				frame[4] |= 0x80
				if mismatch {
					frame[3]++
				}
				upstream.Write(frame)
			}()
			return c, nil
		})
		cancel()
		if mismatch && err == nil || !mismatch && (err != nil || len(answer) != len(q)) {
			t.Fatalf("mismatch=%v len=%d err=%v", mismatch, len(answer), err)
		}
	}
	down := errors.New("WARP unavailable")
	_, err = PeerDNS(context.Background(), q, func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, down })
	if !errors.Is(err, down) {
		t.Fatalf("unexpected error with WARP down: %v", err)
	}
}
