package exit

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// PeerDNS sends a complete wire query over a dedicated WARP TCP connection.
// TCP preserves full DNSSEC and EDNS answers for the client's DoH transport.
func PeerDNS(ctx context.Context, q []byte, dial func(context.Context, netip.AddrPort) (net.Conn, error)) ([]byte, error) {
	if len(q) < 12 || len(q) > 65535 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil, errors.New("expected one DNS question")
	}
	var query dnsmessage.Parser
	h, err := query.Start(q)
	if err != nil || h.Response || h.OpCode != 0 {
		return nil, errors.New("invalid DNS query")
	}
	question, err := query.Question()
	if err != nil {
		return nil, err
	}
	c, err := dial(ctx, netip.MustParseAddrPort("1.1.1.1:53"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if n, err := c.Write(msg); err != nil {
		return nil, err
	} else if n != len(msg) {
		return nil, io.ErrShortWrite
	}
	if _, err := io.ReadFull(c, msg[:2]); err != nil {
		return nil, err
	}
	answer := make([]byte, binary.BigEndian.Uint16(msg[:2]))
	if _, err := io.ReadFull(c, answer); err != nil {
		return nil, err
	}
	var reply dnsmessage.Parser
	rh, err := reply.Start(answer)
	if err != nil || !rh.Response || rh.ID != h.ID {
		return nil, errors.New("invalid upstream DNS response")
	}
	rq, err := reply.Question()
	if err != nil || rq != question {
		return nil, errors.New("unexpected upstream DNS question")
	}
	return answer, nil
}
