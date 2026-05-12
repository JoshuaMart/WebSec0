package tls

import (
	"context"
	stdtls "crypto/tls"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// modernProtocols is the closed set of TLS versions the modern probe covers.
// SSLv2 and SSLv3 are handled by their dedicated raw-probe packages.
var modernProtocols = []struct {
	Name    string
	Version uint16
}{
	{"TLS 1.3", stdtls.VersionTLS13},
	{"TLS 1.2", stdtls.VersionTLS12},
	{"TLS 1.1", stdtls.VersionTLS11},
	{"TLS 1.0", stdtls.VersionTLS10},
}

// enumerateProtocols attempts a handshake with each version pinned to a
// single value (MinVersion == MaxVersion). Success → offered.
func enumerateProtocols(ctx context.Context, target *safehttp.Target) []scan.ProtocolSupport {
	out := make([]scan.ProtocolSupport, 0, len(modernProtocols))
	for _, p := range modernProtocols {
		_, err := attemptHandshake(ctx, target, handshakeOpts{
			MinVersion: p.Version,
			MaxVersion: p.Version,
		})
		out = append(out, scan.ProtocolSupport{
			Name:    p.Name,
			Offered: err == nil,
			Probe:   scan.ProbeStdlib,
		})
	}
	return out
}

// versionFromName resolves a protocol display name to its stdlib constant.
func versionFromName(name string) (uint16, bool) {
	for _, p := range modernProtocols {
		if p.Name == name {
			return p.Version, true
		}
	}
	return 0, false
}
