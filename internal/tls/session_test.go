package tls

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// httptest's TLS server supports session resumption out of the box (Go's
// stdlib TLS server issues tickets by default), so we expect Supported.
func TestDetectSessionResumption_HttptestSupportsIt(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tgt := makeTargetForServer(t, srv)
	got := detectSessionResumption(context.Background(), tgt)
	if got != scan.SessionResumptionSupported {
		t.Errorf("resumption: got %q, want supported", got)
	}
}

// A redirect must not be followed (off-host redirects bypass the safehttp
// redirect policy otherwise); the 3xx response still carries TLS state.
func TestDetectSessionResumption_DoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
	}))
	defer srv.Close()

	tgt := makeTargetForServer(t, srv)
	if got := detectSessionResumption(context.Background(), tgt); got != scan.SessionResumptionSupported {
		t.Errorf("resumption: got %q, want supported", got)
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("server hits: got %d, want 2 (no redirect follow)", n)
	}
}

// An endless body must not hold the probe for its whole timeout.
func TestDetectSessionResumption_CapsBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 32<<10)
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	tgt := makeTargetForServer(t, srv)
	start := time.Now()
	got := detectSessionResumption(context.Background(), tgt)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("probe took %s; body cap not applied", elapsed)
	}
	if got != scan.SessionResumptionSupported {
		t.Errorf("resumption: got %q, want supported", got)
	}
}
