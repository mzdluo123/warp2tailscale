package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestBBRBoundedQuantum(t *testing.T) {
	clock := faketime.NewManualClock()
	st := stack.New(stack.Options{Clock: clock, TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	defer st.Close()
	if err := ConfigureBBR(st, BBRSettings{InitialCwnd: 64, PacingBurst: 4}); err != nil {
		t.Fatal(err)
	}
	s := &sender{ep: &Endpoint{stack: st, protocol: protocolFromStack(st)}}
	s.MaxPayloadSize = 1000
	b := newBBR(s)
	if s.SndCwnd != 64 {
		t.Fatal(s.SndCwnd)
	}
	b.rate = 1e6
	// With four MSS serialized at 1 MB/s the next wakeup must pay 4 ms.
	s.pacingTimer.init(clock, func() {})
	for i := 0; i <= 4; i++ {
		b.nextSend = clock.NowMonotonic().Add(time.Duration(i) * time.Millisecond)
		if got := b.sendBudget(); got != (4-i)*1000 {
			t.Fatalf("after %d MSS: budget=%v", i, got)
		}
	}
	if !s.pacingTimer.enabled() || s.pacingTimer.target.Sub(clock.NowMonotonic()) != 4*time.Millisecond {
		t.Fatal("missing pacing debt")
	}
	s.pacingTimer.cleanup()
}

func TestBBRTimeAndRateLimits(t *testing.T) {
	clock := faketime.NewManualClock()
	st := stack.New(stack.Options{Clock: clock, TransportProtocols: []stack.TransportProtocolFactory{NewProtocol}})
	defer st.Close()
	cfg := BBRSettings{InitialCwnd: 32, PacingBurst: 32, BurstWindow: 2 * time.Millisecond, RateLimit: 1000000}
	if err := ConfigureBBR(st, cfg); err != nil {
		t.Fatal(err)
	}
	s := &sender{ep: &Endpoint{stack: st, protocol: protocolFromStack(st)}}
	s.MaxPayloadSize = 1400
	b := newBBR(s)
	if b.rate != 1000000 {
		t.Fatal("startup pacing cap", b.rate)
	}
	if got := b.sendBudget(); got != 2800 {
		t.Fatal("unexpected GSO payload budget", got)
	}
	b.nextSend = clock.NowMonotonic().Add(1800 * time.Microsecond)
	if got := b.sendBudget(); got != 1400 {
		t.Fatal("failed to deduct existing pacing debt", got)
	}
}
