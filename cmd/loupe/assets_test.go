package main

import (
	"slices"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := config.LoadBytes(exampleConfig("http://127.0.0.1:3000", "127.0.0.1:8080", "0.0.0.0:9090"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backend != "http://127.0.0.1:3000" || cfg.Listen != "127.0.0.1:8080" || cfg.DataDir != "/var/lib/loupe" {
		t.Errorf("backend %q listen %q data_dir %q", cfg.Backend, cfg.Listen, cfg.DataDir)
	}
	if cfg.Admin.Listen != "0.0.0.0:9090" || !slices.Equal(cfg.Admin.Allow, []string{"loopback", "private"}) {
		t.Errorf("admin listen %q allow %v", cfg.Admin.Listen, cfg.Admin.Allow)
	}
	if !slices.Equal(cfg.Proxy.Trusted, []string{"loopback"}) || cfg.Proxy.ClientIPHeader != "X-Forwarded-For" {
		t.Errorf("proxy %+v", cfg.Proxy)
	}
}
