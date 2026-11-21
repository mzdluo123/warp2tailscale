// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && exitbench

package tsnet

import (
	"context"
	"io"
	"net"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

// TestExitSingleCoreTransfer measures a pair of encrypted tsnet endpoints.
// Pin the test binary with taskset to include all its threads in the CPU budget.
func TestExitSingleCoreTransfer(t *testing.T) {
	if runtime.NumCPU() != 1 || runtime.GOMAXPROCS(0) != 1 {
		t.Skip("run pinned to one logical CPU with GOMAXPROCS=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	control, _ := startControl(t)
	server, addr, _ := startServer(t, ctx, control, "receiver")
	client, _, _ := startServer(t, ctx, control, "sender")

	openPair := func(port string) (net.Conn, net.Conn) {
		t.Helper()
		listener, err := server.Listen("tcp", ":"+port)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		sender, err := client.Dial(ctx, "tcp", net.JoinHostPort(addr.String(), port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sender.Close() })
		receiver, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { receiver.Close() })
		deadline, _ := ctx.Deadline()
		for _, conn := range []net.Conn{sender, receiver} {
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
		}
		return sender, receiver
	}

	tx, rx := openPair("8081")
	probe, echo := openPair("8082")
	go io.Copy(echo, echo)
	var token [1]byte
	roundTrip := func() time.Duration {
		t.Helper()
		start := time.Now()
		if _, err := probe.Write(token[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(probe, token[:]); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}

	bulk := func(size int64) <-chan error {
		done := make(chan error, 1)
		read := make(chan error, 1)
		go func() {
			_, err := io.CopyN(io.Discard, rx, size)
			read <- err
		}()
		go func() {
			block := make([]byte, 32<<10)
			for left := size; left > 0; {
				n, err := tx.Write(block[:min(int64(len(block)), left)])
				if err != nil {
					done <- err
					return
				}
				left -= int64(n)
			}
			done <- <-read
		}()
		return done
	}

	cpuTime := func() time.Duration {
		t.Helper()
		var r syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
			t.Fatal(err)
		}
		return time.Duration(r.Utime.Nano() + r.Stime.Nano())
	}
	if err := <-bulk(32 << 20); err != nil {
		t.Fatal(err)
	}
	local, err := client.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	confirmDirect := func() {
		t.Helper()
		for range 20 {
			pong, err := local.Ping(ctx, addr, tailcfg.PingDisco)
			if err != nil {
				t.Fatal(err)
			}
			if pong.Endpoint != "" && pong.PeerRelay == "" && pong.DERPRegionID == 0 {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("no direct UDP path between the test endpoints")
	}
	confirmDirect()
	var idle, loaded []time.Duration
	for range 32 {
		idle = append(idle, roundTrip())
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	const size = 512 << 20
	cpuStart := cpuTime()
	start := time.Now()
	done := bulk(size)
	for {
		select {
		case <-ticker.C:
			loaded = append(loaded, roundTrip())
		case err := <-done:
			elapsed := time.Since(start)
			cpu := cpuTime() - cpuStart
			if err != nil {
				t.Fatal(err)
			}
			confirmDirect()
			if len(loaded) < 10 {
				t.Fatalf("only %d RTT samples", len(loaded))
			}
			slices.Sort(idle)
			slices.Sort(loaded)
			t.Logf("throughput=%.2f MB/s cpu=%.1f%% cpu_ms_per_MiB=%.3f idle_p95=%v loaded_p95=%v samples=%d",
				size/1e6/elapsed.Seconds(), 100*cpu.Seconds()/elapsed.Seconds(),
				cpu.Seconds()*1000/(size/(1<<20)), idle[(95*len(idle)-1)/100], loaded[(95*len(loaded)-1)/100], len(loaded))
			return
		}
	}
}
