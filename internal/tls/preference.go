package tls

import (
	"context"
	stdtls "crypto/tls"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// preferenceProbeSuites is a stable subset of modern AEAD cipher suites
// most servers will accept on TLS 1.2. We need at least two suites the
// server supports to detect a preference; we ship six to maximise the
// chance of getting a clean comparison without re-doing cipher enum.
var preferenceProbeSuites = []uint16{
	stdtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	stdtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	stdtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	stdtls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	stdtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	stdtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// detectCipherPreference performs two TLS 1.2 handshakes with the same
// cipher set in reversed orders and infers preference from the negotiated
// cipher. Only valid for TLS 1.2 — stdlib does not let us configure TLS
// 1.3 cipher ordering, and any deviation between the two picks proves
// the client list drives the choice.
func detectCipherPreference(ctx context.Context, target *safehttp.Target) scan.CipherPreference {
	forward := preferenceProbeSuites
	reversed := make([]uint16, len(forward))
	for i, s := range forward {
		reversed[len(forward)-1-i] = s
	}

	state1, err := attemptHandshake(ctx, target, handshakeOpts{
		MinVersion:   stdtls.VersionTLS12,
		MaxVersion:   stdtls.VersionTLS12,
		CipherSuites: forward,
	})
	if err != nil {
		return scan.CipherPreferenceUnknown
	}
	state2, err := attemptHandshake(ctx, target, handshakeOpts{
		MinVersion:   stdtls.VersionTLS12,
		MaxVersion:   stdtls.VersionTLS12,
		CipherSuites: reversed,
	})
	if err != nil {
		return scan.CipherPreferenceUnknown
	}
	if state1.CipherSuite == state2.CipherSuite {
		return scan.CipherPreferenceServer
	}
	return scan.CipherPreferenceClient
}
