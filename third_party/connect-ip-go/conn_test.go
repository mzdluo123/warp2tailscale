package connectip

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

var ipv6Header = []byte{
	0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
	0x00, 0x20, 59, 64, // Payload Length, Next Header, Hop Limit
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
	0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48, // Destination IP
}

type mockStream struct {
	reading      []byte
	toRead       <-chan []byte
	datagrams    <-chan []byte
	sendDatagram func(prefix, payload []byte) error
}

var _ http3Stream = &mockStream{}

func (m *mockStream) StreamID() quic.StreamID { panic("implement me") }
func (m *mockStream) Read(p []byte) (int, error) {
	if m.reading == nil {
		m.reading = <-m.toRead
	}
	n := copy(p, m.reading)
	m.reading = m.reading[n:]
	return n, nil
}
func (m *mockStream) CancelRead(quic.StreamErrorCode)   {}
func (m *mockStream) Write(p []byte) (n int, err error) { return len(p), nil }
func (m *mockStream) Close() error                      { return nil }
func (m *mockStream) CancelWrite(quic.StreamErrorCode)  {}
func (m *mockStream) Context() context.Context          { return context.Background() }
func (m *mockStream) SetWriteDeadline(time.Time) error  { return nil }
func (m *mockStream) SetReadDeadline(time.Time) error   { return nil }
func (m *mockStream) SetDeadline(time.Time) error       { return nil }
func (m *mockStream) SendDatagramWithPrefix(prefix, payload []byte) error {
	if m.sendDatagram != nil {
		return m.sendDatagram(prefix, payload)
	}
	return nil
}
func (m *mockStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-m.datagrams:
		if !ok {
			return nil, io.EOF
		}
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestReadPacketSlice(t *testing.T) {
	// Use a two-byte encoding of Context ID 0 to test the payload offset.
	datagram := append([]byte{0x40, 0}, ipv6Header...)
	datagrams := make(chan []byte, 5)
	datagrams <- append([]byte{1}, ipv6Header...) // unsupported Context ID
	datagrams <- []byte{0, 0x60}                  // invalid IPv6 packet
	datagrams <- datagram
	datagrams <- append([]byte{0}, ipv6Header...)
	datagrams <- []byte{0x40} // incomplete Context ID
	close(datagrams)
	c := &Conn{str: &mockStream{datagrams: datagrams}}

	packet, err := c.ReadPacketSlice(true)
	require.NoError(t, err)
	require.Equal(t, ipv6Header, packet)
	require.Same(t, &datagram[2], &packet[0])

	// The copying API still validates the full packet before truncating it.
	var small [20]byte
	n, err := c.ReadPacket(small[:], true)
	require.NoError(t, err)
	require.Equal(t, len(small), n)
	require.Equal(t, ipv6Header[:n], small[:])
	require.Equal(t, ipv6Header, packet)

	_, err = c.ReadPacketSlice(true)
	require.ErrorContains(t, err, "connect-ip: malformed datagram")
}

func TestWritePacketDatagramFraming(t *testing.T) {
	ipv4Packet := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	for _, tc := range []struct {
		name      string
		packet    []byte
		hopOffset int
	}{
		{name: "IPv4", packet: ipv4Packet, hopOffset: 8},
		{name: "IPv6", packet: append([]byte(nil), ipv6Header...), hopOffset: 7},
		{name: "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := &Conn{str: &mockStream{sendDatagram: func(prefix, payload []byte) error {
				calls++
				if len(tc.packet) == 0 {
					require.Empty(t, prefix)
					require.Empty(t, payload)
					return nil
				}
				require.Equal(t, []byte{0}, prefix)
				require.Len(t, payload, len(tc.packet))
				require.Same(t, &tc.packet[0], &payload[0])
				require.Equal(t, byte(63), payload[tc.hopOffset])
				if tc.hopOffset == 8 {
					require.Equal(t, uint16(0x6bc6), binary.BigEndian.Uint16(payload[10:12]))
				}
				return nil
			}}}
			icmp, err := c.WritePacket(tc.packet)
			require.NoError(t, err)
			require.Nil(t, icmp)
			require.Equal(t, 1, calls)
		})
	}
}

func TestIncomingDatagrams(t *testing.T) {
	t.Run("empty packets", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}, false),
			"connect-ip: empty packet",
		)
	})

	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data, false),
			"connect-ip: unknown IP versions: 5",
		)
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data[:ipv4.HeaderLen-1], false),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header[:ipv6.HeaderLen-1], false),
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("invalid source address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 11),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data, false),
			"connect-ip: datagram source address not allowed: 192.168.0.11",
		)
	})

	t.Run("invalid destination address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3")},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data, false))

		// 10.1.2.4 is outside the range of allowed addresses
		hdr.Dst = net.IPv4(10, 1, 2, 4)
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data, false),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.4 (protocol: 0)",
		)
	})

	t.Run("invalid IP protocol", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.NoError(t, conn.AssignAddresses(ctx, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute(ctx, []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
			Protocol: 42,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data, false))

		hdr.Protocol = 41
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data, false),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.3 (protocol: 41)",
		)

		// ICMP is always allowed
		hdr.Protocol = ipProtoICMP
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data, false))
	})

	t.Run("packet from assigned address", func(t *testing.T) {
		readChan := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{toRead: readChan})

		hdr := &ipv4.Header{
			Src:      net.IPv4(159, 70, 42, 98),
			Dst:      net.IPv4(192, 168, 0, 10),
			Len:      20,
			Checksum: 89,
		}
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.Error(t, conn.handleIncomingProxiedPacket(data, false), "connect-ip: datagram destination address")

		// now assign 192.168.0.11 to this connection
		readChan <- (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(nil)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = conn.LocalPrefixes(ctx)
		require.NoError(t, err)
		// after processing the address assignment, this is a valid packet
		require.NoError(t, conn.handleIncomingProxiedPacket(data, false))
	})
}

func FuzzIncomingDatagram(f *testing.F) {
	conn := newProxiedConn(&mockStream{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(f, conn.AssignAddresses(ctx, []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::0/64"),
	}))
	require.NoError(f, conn.AdvertiseRoute(ctx, []IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff"), IPProtocol: 42},
	}))

	ipv4Header, err := (&ipv4.Header{
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(159, 70, 42, 98),
		Len:      20,
		Checksum: 89,
	}).Marshal()
	require.NoError(f, err)

	f.Add(ipv4Header)
	f.Add(ipv6Header)

	f.Fuzz(func(t *testing.T, data []byte) {
		conn.handleIncomingProxiedPacket(data, false)
	})
}

func TestSendingDatagrams(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		err := preparePacket(data)
		require.ErrorContains(t, err, "connect-ip: unknown IP versions: 5")
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		err = preparePacket(data[:ipv4.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv4 packet too short")
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		err := preparePacket(ipv6Header[:ipv6.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv6 packet too short")
	})
}

func TestSendLargeDatagrams(t *testing.T) {
	str := &mockStream{sendDatagram: func([]byte, []byte) error { return &quic.DatagramTooLargeError{} }}
	conn := newProxiedConn(str)
	data, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(5, 6, 7, 8),
		Protocol: 17,
	}).Marshal()
	require.NoError(t, err)
	icmp, err := conn.WritePacket(data)
	require.NoError(t, err)
	require.NotNil(t, icmp)
}
