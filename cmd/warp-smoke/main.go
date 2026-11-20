package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/Diniboy1123/usque/bridge"
	"golang.org/x/net/dns/dnsmessage"
)

func trace(ctx context.Context, b bridge.Backend, ip netip.Addr) error {
	dst := netip.AddrPortFrom(ip, 443)
	log.Printf("TCP dst=%s bits=%d", dst, ip.BitLen())
	c, e := b.DialTCP(ctx, dst)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	t := tls.Client(c, &tls.Config{ServerName: "one.one.one.one", MinVersion: tls.VersionTLS12})
	if _, e = io.WriteString(t, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n"); e != nil {
		return e
	}
	r, e := http.ReadResponse(bufio.NewReader(t), nil)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	data, e := io.ReadAll(io.LimitReader(r.Body, 8192))
	if e != nil {
		return e
	}
	values := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = v
		}
	}
	addr, e := netip.ParseAddr(values["ip"])
	if r.StatusCode != 200 || e != nil || addr.BitLen() != ip.BitLen() || values["warp"] != "on" && values["warp"] != "plus" {
		return fmt.Errorf("trace status=%d egress=%s warp=%q", r.StatusCode, addr, values["warp"])
	}
	log.Printf("TCP success egress=%s warp=%s", addr, values["warp"])
	return nil
}
func dns(b bridge.Backend, ip netip.Addr) error {
	dst := netip.AddrPortFrom(ip, 53)
	log.Printf("UDP dst=%s bits=%d", dst, ip.BitLen())
	c, e := b.DialUDP(dst)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	typ := dnsmessage.TypeA
	if ip.Is6() {
		typ = dnsmessage.TypeAAAA
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x7153, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: typ, Class: dnsmessage.ClassINET}}}
	buf, e := m.Pack()
	if e != nil {
		return e
	}
	if _, e = c.Write(buf); e != nil {
		return e
	}
	buf = make([]byte, 65535)
	n, e := c.Read(buf)
	if e != nil {
		return e
	}
	var reply dnsmessage.Message
	if e = reply.Unpack(buf[:n]); e != nil {
		return e
	}
	if !reply.Response || reply.ID != m.ID || reply.RCode != dnsmessage.RCodeSuccess || len(reply.Questions) != 1 || reply.Questions[0] != m.Questions[0] {
		return errors.New("invalid DNS response")
	}
	for _, ans := range reply.Answers {
		if ans.Header.Type == typ {
			log.Printf("DNS success dst=%s answers=%d", dst, len(reply.Answers))
			return nil
		}
	}
	return errors.New("no DNS answer")
}
func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	b, e := bridge.New(ctx, os.Getenv("WARP_CONFIG"))
	if e != nil {
		return e
	}
	defer b.Close()
	for !b.Ready() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	var result error
	for _, raw := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		ip := netip.MustParseAddr(raw)
		tErr := trace(ctx, b, ip)
		var dErr error
		for attempt := 1; attempt <= 3; attempt++ {
			dErr = dns(b, ip)
			if dErr == nil {
				break
			}
			log.Printf("DNS attempt=%d dst=%s error=%v", attempt, ip, dErr)
		}
		result = errors.Join(result, tErr, dErr)
	}
	b.Close()
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	_, te := b.DialTCP(ctx, dst)
	_, ue := b.DialUDP(dst)
	if !errors.Is(te, bridge.ErrWarpDown) || !errors.Is(ue, bridge.ErrWarpDown) {
		return errors.Join(result, errors.New("accepted flow after shutdown"))
	}
	log.Print("MASQUE down: TCP and UDP rejected")
	return result
}
func main() {
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
