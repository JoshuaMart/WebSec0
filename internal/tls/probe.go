// Package tls runs the modern TLS probe — protocol enumeration, cipher
// enumeration per legacy protocol, certificate-chain extraction with
// system-root validation, OCSP-stapling presence and presence-based
// weakness heuristics. SSLv2 and SSLv3 are handled by dedicated raw-probe
// packages (internal/sslv2, internal/sslv3).
package tls

import (
	"context"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// Probe runs the full modern-TLS probe against target and returns a
// partially-populated TLSReport. The Grade and Scores fields are left
// zero — they are filled in by the scoring engine in Phase 6.
//
// The protocols are walked in best-to-worst order, interleaving protocol
// detection with cipher enumeration per version. A shared banDetector
// flips as soon as a handshake silently times out after a prior success
// (a common WAF IP-ban pattern); remaining legacy versions are then
// marked ProbeAborted instead of being falsely reported as "not offered".
// CipherPreference and SessionResumption — both TLS 1.2+ features — are
// skipped once the detector trips, because each adds an extra handshake on
// what we already know to be a dead path.
func Probe(ctx context.Context, target *safehttp.Target) *scan.TLSReport {
	// extractChain runs first because the certificate is informative even
	// when downstream enumeration ends up partial.
	chain, trust, stapled, ocspStatus := extractChain(ctx, target)

	bd := newBanDetector()
	// extractChain just completed a handshake against the same host. If it
	// succeeded we seed the detector so a single subsequent timeout is
	// enough to short-circuit the rest.
	if len(chain) > 0 {
		bd.Record(nil)
	}

	protocols := make([]scan.ProtocolSupport, 0, len(modernProtocols))
	var ciphers []scan.Cipher
	for _, p := range modernProtocols {
		if bd.Triggered() {
			protocols = append(protocols, scan.ProtocolSupport{
				Name:    p.Name,
				Offered: false,
				Probe:   scan.ProbeAborted,
			})
			continue
		}
		support, vCiphers := probeVersion(ctx, target, p.Name, p.Version, bd)
		protocols = append(protocols, support)
		ciphers = append(ciphers, vCiphers...)
	}

	var cipherPref scan.CipherPreference
	var resumption scan.SessionResumption
	if !bd.Triggered() {
		cipherPref = detectCipherPreference(ctx, target)
		resumption = detectSessionResumption(ctx, target)
	}

	status := scan.TLSScanStatusComplete
	if bd.Triggered() {
		status = scan.TLSScanStatusPartialBlocked
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
		ScanStatus:        status,
	}
}
