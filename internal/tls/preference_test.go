package tls

import (
	"context"
	stdtls "crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// Go's stdlib TLS server always picks per its own cipher preference, so
// detectCipherPreference returns Server when probing httptest.
func TestDetectCipherPreference_ServerOnHttptest(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &stdtls.Config{
		MinVersion: stdtls.VersionTLS12,
		MaxVersion: stdtls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	tgt := makeTargetForServer(t, srv)
	got := detectCipherPreference(context.Background(), tgt)
	if got != scan.CipherPreferenceServer {
		t.Errorf("preference: got %q, want server", got)
	}
}

// When the server has no overlap with our probe ciphers, both handshakes
// fail and we report Unknown.
func TestDetectCipherPreference_NoOverlapReturnsUnknown(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &stdtls.Config{
		MinVersion: stdtls.VersionTLS12,
		MaxVersion: stdtls.VersionTLS12,
		// Restrict to a cipher we do NOT include in preferenceProbeSuites.
		CipherSuites: []uint16{stdtls.TLS_RSA_WITH_AES_256_CBC_SHA},
	}
	srv.StartTLS()
	defer srv.Close()

	tgt := makeTargetForServer(t, srv)
	got := detectCipherPreference(context.Background(), tgt)
	if got != scan.CipherPreferenceUnknown {
		t.Errorf("preference: got %q, want unknown", got)
	}
}
