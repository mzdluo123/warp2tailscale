package quic

import (
	"context"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatagramQueuePeekAndPop(t *testing.T) {
	var queued []struct{}
	queue := newDatagramQueue(func() { queued = append(queued, struct{}{}) }, utils.DefaultLogger)
	require.Nil(t, queue.Peek())
	require.Empty(t, queued)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}))
	require.Len(t, queued, 1)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	// calling peek again returns the same datagram
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueSendQueueLength(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		for range maxDatagramSendQueueLen {
			require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
		}
		errChan := make(chan error, 1)
		go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

		synctest.Wait()

		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		// peeking doesn't remove the datagram from the queue...
		require.NotNil(t, queue.Peek())
		synctest.Wait()
		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		// ...but popping does
		queue.Pop()
		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
		// pop all the remaining datagrams
		for range maxDatagramSendQueueLen - 1 {
			queue.Pop()
		}
		f := queue.Peek()
		require.NotNil(t, f)
		require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, f)
	})
}

func TestDatagramQueueReceive(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// receive frames that were received earlier
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
}

func TestReceivedDatagramOwnsPayload(t *testing.T) {
	parser := wire.NewFrameParser(true, false, false)
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	packet := []byte("one")
	for _, payload := range []string{"one", "two"} {
		copy(packet, payload)
		frame, _, err := parser.ParseDatagramFrame(0x30, packet, protocol.Version1)
		require.NoError(t, err)
		queue.HandleDatagramFrame(frame)
	}
	clear(packet)
	for _, want := range []string{"one", "two"} {
		got, err := queue.Receive(t.Context())
		require.NoError(t, err)
		require.Equal(t, want, string(got))
	}
}

func TestDatagramQueueReceiveBlocking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		// block until a new frame is received
		type result struct {
			data []byte
			err  error
		}
		resultChan := make(chan result, 1)
		go func() {
			data, err := queue.Receive(context.Background())
			resultChan <- result{data, err}
		}()

		synctest.Wait()

		select {
		case <-resultChan:
			t.Fatal("expected to not receive result")
		default:
		}
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
		synctest.Wait()
		select {
		case result := <-resultChan:
			require.NoError(t, result.err)
			require.Equal(t, []byte("foobar"), result.data)
		default:
			t.Fatal("should have received a datagram frame")
		}

		// unblock when the context is canceled
		ctx, cancel := context.WithCancel(context.Background())
		errChan := make(chan error, 1)
		go func() {
			_, err := queue.Receive(ctx)
			errChan <- err
		}()

		synctest.Wait()
		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		cancel()
		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, context.Canceled)
		default:
			t.Fatal("should have received a context canceled error")
		}
	})
}

func TestDatagramQueueClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		for range maxDatagramSendQueueLen {
			require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
		}
		errChan1 := make(chan error, 1)
		go func() { errChan1 <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
		errChan2 := make(chan error, 1)
		go func() {
			_, err := queue.Receive(context.Background())
			errChan2 <- err
		}()

		queue.CloseWithError(assert.AnError)
		synctest.Wait()

		select {
		case err := <-errChan1:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("should have received an error")
		}

		select {
		case err := <-errChan2:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("should have received an error")
		}
	})
}

func TestSendDatagramParts(t *testing.T) {
	c := &Conn{
		peerParams:    &wire.TransportParameters{MaxDatagramFrameSize: 64},
		datagramQueue: newDatagramQueue(func() {}, utils.DefaultLogger),
		version:       protocol.Version1,
	}
	c.currentMTUEstimate.Store(8)
	quarterStreamID, contextID, payload := []byte{0x40, 0x40}, []byte{0}, []byte("hello")
	require.NoError(t, c.SendDatagramParts(quarterStreamID, contextID, payload))
	clear(quarterStreamID)
	contextID[0] = 1
	clear(payload)
	frame := c.datagramQueue.Peek()
	require.NotNil(t, frame)
	require.True(t, frame.DataLenPresent)
	require.Equal(t, []byte("\x40\x40\x00hello"), frame.Data)
	c.datagramQueue.Pop()

	var tooLarge *DatagramTooLargeError
	require.ErrorAs(t, c.SendDatagramParts(quarterStreamID, contextID, []byte("longer")), &tooLarge)
	require.EqualValues(t, 8, tooLarge.MaxDatagramPayloadSize)
	require.Nil(t, c.datagramQueue.Peek())

	c.currentMTUEstimate.Store(64)
	c.peerParams.MaxDatagramFrameSize = 9
	require.ErrorAs(t, c.SendDatagramParts(quarterStreamID, contextID, payload), &tooLarge)
	require.EqualValues(t, 7, tooLarge.MaxDatagramPayloadSize)
	require.Nil(t, c.datagramQueue.Peek())
}

func BenchmarkSendDatagramParts(b *testing.B) {
	quarterStreamID, contextID, payload := []byte{0x40, 0x40}, []byte{0}, make([]byte, 1280)
	run := func(b *testing.B, send func(*Conn) error) {
		c := &Conn{
			peerParams:    &wire.TransportParameters{MaxDatagramFrameSize: wire.MaxDatagramSize},
			datagramQueue: newDatagramQueue(func() {}, utils.DefaultLogger),
			version:       protocol.Version1,
		}
		c.currentMTUEstimate.Store(1400)
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		for b.Loop() {
			if err := send(c); err != nil {
				b.Fatal(err)
			}
			c.datagramQueue.Pop()
		}
	}
	b.Run("staged", func(b *testing.B) {
		run(b, func(c *Conn) error {
			ipDatagram := append(make([]byte, 0, len(contextID)+len(payload)), contextID...)
			ipDatagram = append(ipDatagram, payload...)
			httpDatagram := append(make([]byte, 0, 8+len(ipDatagram)), quarterStreamID...)
			httpDatagram = append(httpDatagram, ipDatagram...)
			return c.SendDatagram(httpDatagram)
		})
	})
	b.Run("parts", func(b *testing.B) {
		run(b, func(c *Conn) error {
			return c.SendDatagramParts(quarterStreamID, contextID, payload)
		})
	})
}

func BenchmarkParseEnqueueReceiveDatagram(b *testing.B) {
	packet := make([]byte, 1200)
	parser := wire.NewFrameParser(true, false, false)
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	ctx := b.Context()
	b.SetBytes(int64(len(packet)))
	b.ReportAllocs()
	for b.Loop() {
		frame, _, err := parser.ParseDatagramFrame(0x30, packet, protocol.Version1)
		if err != nil {
			b.Fatal(err)
		}
		queue.HandleDatagramFrame(frame)
		if _, err := queue.Receive(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
