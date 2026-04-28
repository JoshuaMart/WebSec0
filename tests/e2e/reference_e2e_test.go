//go:build e2e

package e2e

import (
	"testing"

	"github.com/JoshuaMart/websec0/internal/checks"
	scannertls "github.com/JoshuaMart/websec0/internal/scanner/tls"
)

// TestE2E_APlus runs a full orchestrator scan against three reference
// servers and asserts the scanner does not false-positive on the
// "universally bad" checks: cert validity, broken protocols (SSLv2/v3),
// blacklisted ciphers (NULL, EXPORT, RC4, DES, DH-weak). These are the
// findings that should not appear on any production site, anywhere.
//
// Findings we deliberately do NOT assert here, even though we'd prefer
// they pass:
//
//   - TLS-PROTOCOL-LEGACY-TLS10 / TLS-PROTOCOL-LEGACY-TLS11 — Cloudflare
//     and other large CDNs still accept TLS 1.0/1.1 for back-compat with
//     legacy clients (a deliberate vendor choice, not a misconfiguration).
//   - TLS-PROTOCOL-TLS12-MISSING — sites running 1.3-only on purpose.
//   - TLS-CIPHER-NO-FORWARD-SECRECY — some sites still keep RSA fallback.
//   - TLS-HSTS-MISSING / TLS-REDIRECT-HTTP-TO-HTTPS — apex domains often
//     don't set HSTS; the protected entry point is the www-subdomain.
//   - TLS-CERT-CHAIN-INCOMPLETE — Go's stdlib TLS does AIA chasing and
//     completes incomplete chains at verify time; the wire chain
//     measurement is a separate scanner enhancement.
//   - TLS-OCSP-STAPLING-MISSING — Cloudflare and others have moved to
//     short-lived certs without OCSP stapling.
//
// The intent is that this suite catches *regressions in the scanner*
// (e.g. a refactor that suddenly false-positives RC4 on every host),
// not vendor-policy differences.
func TestE2E_APlus(t *testing.T) {
	hosts := []string{
		"cloudflare.com",
		"github.com",
		"mozilla.org",
	}

	// Universally-bad checks — must never fail on a production site,
	// regardless of vendor choices. If any of these fail, either the
	// vendor has regressed catastrophically or the scanner has a bug.
	mustPass := []string{
		// Cert validity.
		scannertls.IDCertExpired,
		scannertls.IDCertNameMismatch,
		scannertls.IDCertSelfSigned,
		scannertls.IDCertWeakRSA,
		scannertls.IDCertWeakECC,
		scannertls.IDCertWeakSignature,
		// Broken protocols.
		scannertls.IDProtocolLegacySSL2,
		scannertls.IDProtocolLegacySSL3,
		// Blacklisted ciphers.
		scannertls.IDCipherNull,
		scannertls.IDCipherExport,
		scannertls.IDCipherRC4,
		scannertls.IDCipherDES,
		scannertls.IDCipherDHWeak,
	}

	for _, host := range hosts {
		host := host
		t.Run(host, func(t *testing.T) {
			if !reachable(t, host+":443") {
				t.Skipf("%s unreachable", host)
			}

			rep := runFullScan(t, host, false)

			// Hard gate: no critical finding may exist on a reference site.
			if rep.Summary.Counts.Critical > 0 {
				t.Errorf("%s: %d critical finding(s) on a reference target — scanner false positive?",
					host, rep.Summary.Counts.Critical)
				for _, f := range rep.Findings {
					if f.Severity == checks.SeverityCritical && f.Status == checks.StatusFail {
						t.Logf("  CRITICAL FAIL %s: %s", f.ID, f.Title)
					}
				}
			}

			// Soft gate: log high findings for visibility (vendor-policy
			// trade-offs land here — TLS 1.0/1.1, HSTS on apex, …).
			if rep.Summary.Counts.High > 0 {
				t.Logf("%s: %d high-severity finding(s) (informational, not failed):",
					host, rep.Summary.Counts.High)
				for _, f := range rep.Findings {
					if f.Severity == checks.SeverityHigh && f.Status == checks.StatusFail {
						t.Logf("  HIGH %s: %s", f.ID, f.Title)
					}
				}
			}

			// Per-check gate: universally-bad checks must not fail.
			for _, id := range mustPass {
				assertNotFail(t, rep, id)
			}

			// Sanity: a well-configured public site should reach a B+.
			// We do not gate on A+: grade is sensitive to optional
			// finding categories (BIMI, NEL, CT, HSTS preload) where
			// vendors choose trade-offs.
			minScore := 70
			if rep.Summary.Score < minScore {
				t.Errorf("%s: score=%d below minimum %d (grade=%s)",
					host, rep.Summary.Score, minScore, rep.Summary.Grade)
			}
		})
	}
}
