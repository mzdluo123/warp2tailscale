package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tsnet"
)

func TestEgressConfiguration(t *testing.T) {
	ctx := context.Background()
	example, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contents := string(example)
	warpSection := contents[strings.Index(contents, "\nwarp:"):strings.Index(contents, "\ncongestion:")]
	direct := strings.Replace(contents, warpSection, "", 1)
	direct = strings.Replace(direct, "mode: warp", "mode: direct", 1)
	// Permission for ICMP sockets depends on the test host.
	direct = strings.Replace(direct, "icmp: true", "icmp: false", 1)
	legacy := strings.Replace(contents, contents[strings.Index(contents, "\negress:"):strings.Index(contents, "\nwarp:")], "", 1)

	for _, tc := range []struct {
		name string
		yaml string
		mode string
	}{
		{"default WARP", legacy, egressWarp},
		{"explicit WARP", contents, egressWarp},
		{"direct without WARP settings", direct, egressDirect},
		{"invalid mode", strings.Replace(direct, "mode: direct", "mode: unknown", 1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := load(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.mode == "" {
				if err := cfg.validate(); err == nil {
					t.Fatal("accepted unknown egress mode")
				}
				return
			}
			if err := cfg.validate(); err != nil {
				t.Fatal(err)
			}
			if mode := cfg.egressMode(); mode != tc.mode {
				t.Fatalf("mode = %q, want %q", mode, tc.mode)
			}
			server := new(tsnet.Server)
			if tc.mode == egressWarp {
				cfg.Warp.ConfigPath = filepath.Join(t.TempDir(), "missing.json")
				t.Setenv("QUIC_GO_HTTP3_DATAGRAM_RING", "false")
				if _, err := configureEgress(ctx, cfg, server, nil); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("WARP startup with missing credentials returned %v", err)
				}
				cfg.Warp.FailClosed = false
				if err := cfg.validate(); err == nil {
					t.Fatal("accepted WARP without fail-closed")
				}
				return
			}
			backend, err := configureEgress(ctx, cfg, server, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer backend.close()
			if !backend.ready() || backend.dialTCP == nil || backend.dialUDP == nil {
				t.Fatal("direct egress is missing its host dialers")
			}
			if server.ExitPacket != nil || server.NormalizeExitPacket == nil {
				t.Fatal("unexpected direct packet hooks for ICMP disabled")
			}
		})
	}
}
