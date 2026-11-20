package tcp

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// SetBufferSizes fixes per-endpoint send and receive capacity before the
// first handshake. Zero preserves that stack's native defaults and autotuning.
func SetBufferSizes(st *stack.Stack, send, receive int) error {
	for _, size := range []int{send, receive} {
		if size != 0 && (size < MinBufferSize || size > 64<<20) {
			return fmt.Errorf("TCP buffer %d outside [4096, 67108864] bytes", size)
		}
	}
	if send != 0 {
		opt := tcpip.TCPSendBufferSizeRangeOption{Min: send, Default: send, Max: send}
		if err := st.SetTransportProtocolOption(ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("TCP send buffer: %v", err)
		}
	}
	if receive != 0 {
		opt := tcpip.TCPReceiveBufferSizeRangeOption{Min: receive, Default: receive, Max: receive}
		if err := st.SetTransportProtocolOption(ProtocolNumber, &opt); err != nil {
			return fmt.Errorf("TCP receive buffer: %v", err)
		}
	}
	return nil
}
