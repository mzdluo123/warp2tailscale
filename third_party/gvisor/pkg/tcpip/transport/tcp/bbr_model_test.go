package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestBBRModel(t *testing.T) {
	clock := faketime.NewManualClock()
	st := stack.New(stack.Options{Clock: clock})
	defer st.Close()
	s := &sender{ep: &Endpoint{stack: st}}
	s.MaxPayloadSize = 1000
	b := newBBR(s)
	if s.SndCwnd != 32 {
		t.Fatal(s.SndCwnd)
	}
	tick := func(d time.Duration) {
		snap := deliverySnapshot{bytes: b.delivered, lastACK: clock.NowMonotonic(), sent: clock.NowMonotonic()}
		clock.Advance(d)
		s.SndNxt += 1000
		s.SndUna = s.SndNxt
		b.ack(1000, time.Millisecond, &snap)
	}
	for i := 0; i < 4; i++ {
		tick(time.Millisecond)
	}
	if b.mode != "DRAIN" || b.bw != 1e6 {
		t.Fatalf("%s %f", b.mode, b.bw)
	}
	tick(time.Millisecond)
	if b.mode != "PROBE_BW" {
		t.Fatal(b.mode)
	}
	tick(time.Millisecond)
	if b.rate != 750000 {
		t.Fatal(b.rate)
	}
	tick(10 * time.Second)
	if b.mode != "PROBE_RTT" || s.SndCwnd != 4 {
		t.Fatal(b.mode, s.SndCwnd)
	}
	tick(199 * time.Millisecond)
	if b.mode != "PROBE_RTT" {
		t.Fatal(b.mode)
	}
	tick(time.Millisecond)
	if b.mode != "PROBE_BW" {
		t.Fatal(b.mode)
	}
}
