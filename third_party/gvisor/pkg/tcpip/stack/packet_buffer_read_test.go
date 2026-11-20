// SPDX-License-Identifier: Apache-2.0

package stack_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestPacketDataReadAcrossViews(t *testing.T) {
	data := buffer.MakeWithData([]byte("hdrabc"))
	tail := buffer.MakeWithData([]byte("defg"))
	data.Merge(&tail)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: data})
	defer pkt.DecRef()
	pkt.NetworkHeader().Consume(3)

	var peek bytes.Buffer
	if n, err := pkt.Data().ReadTo(&peek, true); err != nil || n != 7 || peek.String() != "abcdefg" {
		t.Fatalf("peek = %q, %d, %v", peek.String(), n, err)
	}
	buf := make([]byte, 4)
	dst := tcpip.SliceWriter(buf)
	if n, err := pkt.Data().ReadTo(&dst, false); n != 4 || !errors.Is(err, io.ErrShortWrite) || string(buf) != "abcd" {
		t.Fatalf("partial read = %q, %d, %v", buf, n, err)
	}
	var remaining bytes.Buffer
	if n, err := pkt.Data().ReadTo(&remaining, false); n != 3 || err != nil || remaining.String() != "efg" {
		t.Fatalf("remaining = %q, %d, %v", remaining.String(), n, err)
	}
}
