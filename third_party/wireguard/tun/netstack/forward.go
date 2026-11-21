package netstack

import (
	"context"
	"fmt"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Forwarder provides the client-facing interface of an in-memory IP router.
// The existing TUN remains the WAN, and owns the WARP-assigned addresses.
type Forwarder struct{ client *channel.Endpoint }

// EnableForwarding delivers routed replies by transferring one packet reference
// to deliver, which must release it even if delivery fails.
func (n *Net) EnableForwarding(ctx context.Context, prefixes []netip.Prefix, deliver func(*stack.PacketBuffer) error) (*Forwarder, error) {
	const clientNIC = 2
	client := channel.New(128, uint32(n.mtu), "")
	if err := n.stack.CreateNIC(clientNIC, client); err != nil {
		return nil, fmt.Errorf("create client NIC: %v", err)
	}
	for _, prefix := range prefixes {
		addr := tcpip.AddrFromSlice(prefix.Masked().Addr().AsSlice())
		subnet := tcpip.AddressWithPrefix{Address: addr, PrefixLen: prefix.Bits()}.Subnet()
		ipv6 := prefix.Addr().Is6()
		proto := header.IPv4ProtocolNumber
		router := prefix.Addr()
		filter := stack.EmptyFilter4()
		if ipv6 {
			proto = header.IPv6ProtocolNumber
			filter = stack.EmptyFilter6()
		}
		// A local source on the client interface is needed for TTL/MTU errors.
		if err := n.stack.AddProtocolAddress(clientNIC, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(router.AsSlice()).WithPrefix()}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("router address: %v", err)
		}
		n.stack.AddRoute(tcpip.Route{Destination: subnet, NIC: clientNIC})
		table := n.stack.IPTables().GetTable(stack.NATID, ipv6)
		filter.Src = addr
		mask := subnet.Mask()
		filter.SrcMask = tcpip.AddrFromSlice(mask.AsSlice())
		filter.Dst, filter.DstMask, filter.DstInvert = filter.Src, filter.SrcMask, true
		table.BuiltinChains[stack.Postrouting] = len(table.Rules)
		table.Rules = append(table.Rules, stack.Rule{Filter: filter, Target: &stack.MasqueradeTarget{NetworkProtocol: proto}}, table.Rules[table.Underflows[stack.Postrouting]])
		table.Underflows[stack.Postrouting] = len(table.Rules) - 1
		n.stack.IPTables().ReplaceTable(stack.NATID, table, ipv6)
		if err := n.stack.SetForwardingDefaultAndAllNICs(proto, true); err != nil {
			return nil, fmt.Errorf("enable forwarding: %v", err)
		}
	}
	go func() {
		defer client.Close()
		for {
			pkt := client.ReadContext(ctx)
			if pkt == nil {
				return
			}
			if ctx.Err() != nil {
				pkt.DecRef()
				return
			}
			_ = deliver(pkt)
		}
	}()
	return &Forwarder{client}, nil
}

func (f *Forwarder) Inject(ipv6 bool, data []byte, sourceFragmented bool) {
	injectIP(f.client, ipv6, data, sourceFragmented)
}
func (n *Net) InjectReassembledWAN(data []byte) {
	injectIP(n.ep, data[0]>>4 == 6, data, true)
}
func injectIP(ep *channel.Endpoint, ipv6 bool, data []byte, sourceFragmented bool) {
	proto := header.IPv4ProtocolNumber
	if ipv6 {
		proto = header.IPv6ProtocolNumber
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	pkt.NetworkPacketInfo.SourceFragmented = sourceFragmented
	ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

// copyPacket copies from the first network header, skipping reserved headroom.
func copyPacket(dst []byte, pkt *stack.PacketBuffer) int {
	views, skip := pkt.AsViewList()
	n := 0
	for v := views.Front(); v != nil && n < len(dst); v = v.Next() {
		data := v.AsSlice()
		if skip >= len(data) {
			skip -= len(data)
			continue
		}
		n += copy(dst[n:], data[skip:])
		skip = 0
	}
	return n
}
