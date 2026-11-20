package tcp

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func (b *bbrController) canSend() bool {
	delay := b.nextSend.Sub(b.s.ep.stack.Clock().NowMonotonic())
	// Allow a bounded quantum, then repay the entire serialization time.
	// Idle connections cannot accumulate credits beyond one quantum.
	allowance := time.Duration(float64(time.Second) * float64((b.settings.PacingBurst-1)*b.s.MaxPayloadSize) / b.rate)
	if delay <= allowance {
		return true
	}
	if !b.s.pacingTimer.enabled() {
		b.s.pacingTimer.enable(delay)
		b.waits++
	}
	return false
}
func (s *sender) pacingExpired() tcpip.Error {
	if !s.pacingTimer.isUninitialized() && s.pacingTimer.checkExpiration() && s.ep.EndpointState().connected() {
		s.sendData()
	}
	return nil
}
func (b *bbrController) onSend(seg *segment) {
	now := seg.xmitTime
	if b.s.Outstanding == 0 {
		b.firstSent = now
		b.lastACK = now
	}
	if seg.xmitCount == 0 {
		seg.delivery = deliverySnapshot{bytes: b.delivered, lastACK: b.lastACK, sendElapsed: now.Sub(b.firstSent), sent: now, valid: true}
	} else {
		b.retransmits++
	}
	// ACK sampling compares the ACK clock and send clock to resist ACK compression.

	if b.sentData {
		b.gap = now.Sub(b.lastSent)
	}
	b.sentData = true
	b.lastSent = now
	base := now
	if b.settings.PacingBurst > 1 && b.nextSend.After(base) {
		base = b.nextSend
	}
	b.nextSend = base.Add(time.Duration(float64(time.Second) * float64(max(1, seg.payloadSize())) / b.rate))
}
