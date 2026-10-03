package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/config"
)

func TestServerWriteBudgetIncludesScanAndRequest(t *testing.T) {
	for _, timeout := range []time.Duration{time.Second, 30 * time.Second, 5 * time.Minute} {
		cfg := config.Defaults()
		cfg.Scan.Timeout = config.Duration(timeout)
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		server := newServer(cfg, http.NewServeMux())
		if server.WriteTimeout <= server.ReadTimeout+timeout {
			t.Fatalf("write budget %s cannot cover request %s and scan %s", server.WriteTimeout, server.ReadTimeout, timeout)
		}
	}
}
