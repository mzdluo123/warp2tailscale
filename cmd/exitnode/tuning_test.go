package main

import (
	"testing"
	"time"
)

func TestTuningConfiguration(t *testing.T) {
	cfg, err := load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, cc := range []string{"bbr", "cubic", "reno"} {
		cfg.Congestion.Type = cc
		cfg.TCP.Send = 4194304
		cfg.TCP.Receive = 2097152
		if err := cfg.validate(); err != nil {
			t.Fatal(cc, err)
		}
	}
	cfg.TCP.Send = 4095
	if err := cfg.validate(); err == nil {
		t.Fatal("accepted undersized send buffer")
	}
	cfg.TCP.Send = 0
	cfg.TCP.Receive = 1 + (64 << 20)
	if err := cfg.validate(); err == nil {
		t.Fatal("accepted oversized receive buffer")
	}
	cfg.TCP.Receive = 0
	cfg.Congestion.Type = "unknown"
	if err := cfg.validate(); err == nil {
		t.Fatal("accepted unsupported CC")
	}
}

func TestRoutingAndPacingConfiguration(t *testing.T) {
	example, err := load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if example.Policy.UDP != "all" || !example.Policy.ICMP {
		t.Fatal("example must enable public UDP and ICMP")
	}
	for _, tc := range []struct {
		name  string
		set   func(*config)
		valid bool
	}{
		{"legacy DNS only", func(c *config) { c.Policy.UDP = "dns-only"; c.Policy.ICMP = false }, true},
		{"unknown UDP policy", func(c *config) { c.Policy.UDP = "other" }, false},
		{"automatic runtime and queue", func(c *config) { c.Runtime.MaxProcs = 0; c.Warp.PacketQueue = 0 }, true},
		{"negative procs", func(c *config) { c.Runtime.MaxProcs = -1 }, false},
		{"oversized WARP queue", func(c *config) { c.Warp.PacketQueue = 257 }, false},
		{"oversized pacing burst", func(c *config) { c.Congestion.PacingBurst = 33 }, false},
		{"oversized burst window", func(c *config) { c.Congestion.BurstWindow = 11 * time.Millisecond }, false},
		{"negative pacing rate", func(c *config) { c.Congestion.RateLimit = -1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := example
			tc.set(&c)
			if err := c.validate(); (err == nil) != tc.valid {
				t.Fatalf("validation error %v, want valid=%v", err, tc.valid)
			}
		})
	}
}
