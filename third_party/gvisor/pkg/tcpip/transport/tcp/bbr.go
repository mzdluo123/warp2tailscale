// BBRv1 standard for the userspace TCP sender. Rates are payload bytes/second.
package tcp

import (
	"fmt"
	"log"
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// BBRSettings controls the initial window and maximum pacing quantum in MSS.
type BBRSettings struct {
	InitialCwnd, PacingBurst int
	BurstWindow              time.Duration
	RateLimit                int64
	Quiet                    bool // Skip per-flow diagnostic logging on the ACK path.
}

// ConfigureBBR sets defaults for future senders on this stack only.
func ConfigureBBR(st *stack.Stack, cfg BBRSettings) error {
	if cfg.InitialCwnd == 0 {
		cfg.InitialCwnd = 32
	}
	if cfg.PacingBurst == 0 {
		cfg.PacingBurst = 1
	}
	if cfg.InitialCwnd < 4 || cfg.InitialCwnd > 128 || cfg.PacingBurst < 1 || cfg.PacingBurst > 32 || cfg.BurstWindow < 0 || cfg.BurstWindow > 10*time.Millisecond || cfg.RateLimit < 0 {
		return fmt.Errorf("invalid BBR initial cwnd %d or pacing burst %d", cfg.InitialCwnd, cfg.PacingBurst)
	}
	p := protocolFromStack(st)
	p.mu.Lock()
	p.bbrSettings = cfg
	p.mu.Unlock()
	return nil
}

func (cfg BBRSettings) limitRate(rate float64) float64 {
	if cfg.RateLimit > 0 {
		return min(rate, float64(cfg.RateLimit))
	}
	return rate
}

type deliverySnapshot struct {
	bytes         uint64
	sent, lastACK tcpip.MonotonicTime
	sendElapsed   time.Duration
	valid         bool
}
type bbrController struct {
	settings                            BBRSettings
	s                                   *sender
	mode                                string
	nextRound                           seqnum.Value
	round, flat, cycle                  int
	peak                                [10]float64 // round-indexed max delivery rate
	bw, full, rate                      float64
	minRTT                              time.Duration
	minStamp, phaseStart, probeUntil    tcpip.MonotonicTime
	lastACK, firstSent                  tcpip.MonotonicTime
	nextSend, lastSent, lastLog         tcpip.MonotonicTime
	sentData                            bool
	delivered, acks, retransmits, waits uint64
	gap                                 time.Duration
}

var probeGains = [8]float64{1.25, .75, 1, 1, 1, 1, 1, 1}

func newBBR(s *sender) *bbrController {
	now := s.ep.stack.Clock().NowMonotonic()
	cfg := BBRSettings{InitialCwnd: 32, PacingBurst: 1}
	if p := s.ep.protocol; p != nil {
		p.mu.RLock()
		if p.bbrSettings.InitialCwnd != 0 {
			cfg = p.bbrSettings
		}
		p.mu.RUnlock()
	}
	s.SndCwnd = cfg.InitialCwnd
	return &bbrController{settings: cfg, s: s, mode: "STARTUP", minStamp: now, nextRound: s.SndNxt, lastACK: now, firstSent: now, rate: cfg.limitRate(2.885 * float64(cfg.InitialCwnd*s.MaxPayloadSize) / .1)}
}
func (b *bbrController) HandleLossDetected()       { b.s.Ssthresh = max(4, b.s.SndCwnd) }
func (b *bbrController) HandleRTOExpired()         { b.HandleLossDetected() }
func (b *bbrController) PostRecovery()             {}
func (b *bbrController) Update(int, time.Duration) {} // ack() also samples cumulative ACKs during recovery.
func (b *bbrController) ack(n int, rtt time.Duration, snap *deliverySnapshot) {
	now := b.s.ep.stack.Clock().NowMonotonic()
	previous := b.mode
	b.acks++
	b.delivered += uint64(n)
	newRound := b.nextRound.LessThan(b.s.SndUna)
	if newRound {
		b.nextRound = b.s.SndNxt
		b.round++
		slot := b.round % len(b.peak)
		expiredPeak := b.peak[slot]
		b.peak[slot] = 0
		if expiredPeak == b.bw {
			b.bw = 0
			for _, rate := range b.peak {
				b.bw = max(b.bw, rate)
			}
		}
	}
	if snap != nil {
		b.firstSent = snap.sent
		interval := max(now.Sub(snap.lastACK), snap.sendElapsed)
		if interval > 0 {
			sample := float64(b.delivered-snap.bytes) / interval.Seconds()
			slot := b.round % len(b.peak)
			b.peak[slot] = max(b.peak[slot], sample)
			b.bw = max(b.bw, sample)
		}
	}
	b.lastACK = now
	expired := now.Sub(b.minStamp) >= 10*time.Second
	if rtt > 0 && (b.minRTT == 0 || rtt < b.minRTT || expired) {
		b.minRTT = rtt
		b.minStamp = now
	}
	if b.bw == 0 || b.minRTT == 0 {
		return
	}
	mss := b.s.MaxPayloadSize
	bdp := b.settings.limitRate(b.bw) * b.minRTT.Seconds() / float64(mss)
	if expired && b.mode != "PROBE_RTT" {
		b.mode = "PROBE_RTT"
		b.probeUntil = tcpip.MonotonicTime{}
	}
	if b.mode == "STARTUP" && newRound {
		if b.bw >= b.full*1.25 {
			b.full = b.bw
			b.flat = 0
		} else {
			b.flat++
		}
		if b.flat >= 3 {
			b.mode = "DRAIN"
		}
	}
	if previous == "DRAIN" && b.mode == "DRAIN" && float64(b.s.Outstanding) <= bdp {
		b.mode = "PROBE_BW"
		b.cycle = 0
		b.phaseStart = now
	}
	gain := 1.
	target := max(4, int(math.Ceil(2*bdp)))
	switch b.mode {
	case "STARTUP":
		gain = 2.885
		if b.s.SndCwnd < target || b.delivered < uint64(b.settings.InitialCwnd*mss) {
			b.s.SndCwnd += max(1, (n+mss-1)/mss)
		}
	case "DRAIN":
		gain = 1 / 2.885
		b.s.SndCwnd = target
	case "PROBE_BW":
		if now.Sub(b.phaseStart) >= b.minRTT {
			b.cycle = (b.cycle + 1) % len(probeGains)
			b.phaseStart = now
		}
		gain = probeGains[b.cycle]
		b.s.SndCwnd = target
	case "PROBE_RTT":
		b.s.SndCwnd = 4
		if b.s.Outstanding <= 4 && b.probeUntil == (tcpip.MonotonicTime{}) {
			b.probeUntil = now.Add(200 * time.Millisecond)
		}
		if b.probeUntil != (tcpip.MonotonicTime{}) && !now.Before(b.probeUntil) && newRound {
			b.minStamp = now
			b.mode = "PROBE_BW"
			b.phaseStart = now
			b.s.SndCwnd = target
		}
	}
	rate := max(1., b.bw*gain)
	if b.mode == "STARTUP" {
		rate = max(rate, b.rate)
	}
	b.rate = b.settings.limitRate(rate)
	if !b.settings.Quiet && (previous != b.mode || b.acks == 1 || now.Sub(b.lastLog) >= time.Second) {
		log.Printf("flow=%v cc=bbr initial_cwnd=%d burst_mss=%d mode=%s min_rtt=%s btlbw_Bps=%.0f pacing_rate_Bps=%.0f cwnd=%d bytes_in_flight=%d acks=%d retransmits=%d paced_waits=%d last_send_gap=%s", b.s.ep.TransportEndpointInfo.ID, b.settings.InitialCwnd, b.settings.PacingBurst, b.mode, b.minRTT, b.bw, b.rate, b.s.SndCwnd, b.s.SndUna.Size(b.s.SndNxt), b.acks, b.retransmits, b.waits, b.gap)
		b.lastLog = now
	}
}
