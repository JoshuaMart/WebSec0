// Package tls runs the modern TLS probe — protocol enumeration, cipher
// enumeration per legacy protocol, certificate-chain extraction with
// system-root validation, OCSP-stapling presence and presence-based
// weakness heuristics. SSLv2 and SSLv3 are handled by dedicated raw-probe
// packages (internal/sslv2, internal/sslv3).
package tls

import (
	"context"
	stdtls "crypto/tls"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// Probe runs the full modern-TLS probe against target and returns a
// partially-populated TLSReport. The Grade and Scores fields are left
// zero — they are filled in by the scoring engine in Phase 6.
func Probe(ctx context.Context, target *safehttp.Target) *scan.TLSReport {
	// Extract the chain first — the certificate is single-handshake and
	// always informative, so we want it even when a downstream cipher
	// enumeration runs into the scan timeout.
	chain, trust, stapled, ocspStatus := extractChain(ctx, target)

	protocols := enumerateProtocols(ctx, target)
	cipherPref := detectCipherPreference(ctx, target)
	resumption := detectSessionResumption(ctx, target)

	var ciphers []scan.Cipher
	for _, p := range protocols {
		if !p.Offered {
			continue
		}
		v, ok := versionFromName(p.Name)
		if !ok {
			continue
		}
		if v == stdtls.VersionTLS13 {
			ciphers = append(ciphers, captureTLS13Cipher(ctx, target)...)
		} else {
			ciphers = append(ciphers, enumerateLegacyCiphers(ctx, target, v, p.Name)...)
		}
	}

	// Vulnerabilities are intentionally left nil here. The orchestrator
	// calls DeriveWeaknesses once both TLS and headers probes have
	// completed, because Heartbleed and Ticketbleed are fingerprinted
	// from the HTTP `Server:` header that this package does not observe.
	// See WeaknessInput's godoc for the full input contract.
	return &scan.TLSReport{
		Protocols:         protocols,
		Ciphers:           ciphers,
		CipherPreference:  cipherPref,
		CertificateChain:  chain,
		ChainTrust:        trust,
		OCSPStapling:      stapled,
		OCSPStatus:        ocspStatus,
		SessionResumption: resumption,
	}
}
