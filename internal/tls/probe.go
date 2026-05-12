// Package tls runs the modern TLS probe — protocol enumeration, cipher
// enumeration per legacy protocol, certificate-chain extraction with
// system-root validation, OCSP-stapling presence and presence-based
// weakness heuristics. SSLv2 and SSLv3 are handled by dedicated raw-probe
// packages (internal/sslv2, internal/sslv3). See SPEC §4.1 / §6.4.
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
	protocols := enumerateProtocols(ctx, target)

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

	chain, trust, ocsp := extractChain(ctx, target)
	vulns := deriveWeaknesses(protocols, ciphers)

	return &scan.TLSReport{
		Protocols:        protocols,
		Ciphers:          ciphers,
		CertificateChain: chain,
		ChainTrust:       trust,
		OCSPStapling:     ocsp,
		Vulnerabilities:  vulns,
	}
}
