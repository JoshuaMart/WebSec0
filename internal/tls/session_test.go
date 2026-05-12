package tls

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
