package main

import "testing"

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
