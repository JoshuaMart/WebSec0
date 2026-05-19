package tls

import (
	"context"
	stdtls "crypto/tls"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// modernProtocols is the closed set of TLS versions the modern probe covers,
// ordered best-to-worst. The Probe() loop relies on this ordering: modern
// (low-risk) versions are tested first so their data is captured before a
// legacy ClientHello triggers a WAF block on the scanner IP.
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

// probeVersion runs one protocol-pinned handshake (MinVer=MaxVer=version)
// and, on success, enumerates the offered ciphers for that version. Every
// handshake feeds bd so that the caller can short-circuit the remaining
// versions when a mid-scan ban is detected. The returned ProtocolSupport
// reflects whichever observation was actually made; an aborted enumeration
// inside the cipher loop is not retroactively reflected in support.Offered.
func probeVersion(ctx context.Context, target *safehttp.Target, name string, version uint16, bd *banDetector) (scan.ProtocolSupport, []scan.Cipher) {
	_, err := attemptHandshake(ctx, target, handshakeOpts{
		MinVersion: version,
		MaxVersion: version,
	})
	bd.Record(err)

	// If this very handshake tripped the detector (timeout / dial cancel),
	// the row is indeterminate — we never got a server reply for this
	// version, so reporting "not offered" would be a lie. Surface it as
	// ProbeAborted, the same shape as versions we skip outright.
	if err != nil && bd.Triggered() {
		return scan.ProtocolSupport{Name: name, Offered: false, Probe: scan.ProbeAborted}, nil
	}

	support := scan.ProtocolSupport{
		Name:    name,
		Offered: err == nil,
		Probe:   scan.ProbeStdlib,
	}
	if err != nil {
		return support, nil
	}

	var ciphers []scan.Cipher
	if version == stdtls.VersionTLS13 {
		ciphers = captureTLS13Cipher(ctx, target, bd)
	} else {
		ciphers = enumerateLegacyCiphers(ctx, target, version, name, bd)
	}
	return support, ciphers
}
