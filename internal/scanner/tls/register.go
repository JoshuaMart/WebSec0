package tls

import (
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// Register adds all TLS checks to r.
// Coverage: phases 6.1 (modern TLS), 6.2 (cert), 6.3 (legacy + ciphers),
// 6.4 (SSLv2/SSLv3), 6.5 (Heartbleed stub), 6.6 (HSTS + redirect).
func Register(r *checks.Registry) {
	// Phase 6.1 — Modern TLS
	r.Register(tls12MissingCheck{})
	r.Register(tls13MissingCheck{})
	r.Register(noFSCheck{})
	r.Register(noH2Check{})
	r.Register(ocspStaplingCheck{})

	// Phase 6.2 — Certificate validation
	r.Register(certExpiredCheck{})
	r.Register(certExpiresSoonCheck{
		id:        IDCertExpiresSoon14d,
		threshold: 14 * 24 * time.Hour,
		severity:  checks.SeverityHigh,
	})
	r.Register(certExpiresSoonCheck{
		id:        IDCertExpiresSoon30d,
		threshold: 30 * 24 * time.Hour,
		severity:  checks.SeverityMedium,
	})
	r.Register(chainIncompleteCheck{})
	r.Register(nameMismatchCheck{})
	r.Register(selfSignedCheck{})
	r.Register(weakRSACheck{})
	r.Register(weakECCCheck{})
	r.Register(weakSignatureCheck{})

	// Phase 6.3 — Legacy protocol probes
	r.Register(tls10Check{})
	r.Register(tls11Check{})

	// Phase 6.3 — Weak cipher suite probes
	r.Register(cipherNullCheck{})
	r.Register(cipherExportCheck{})
	r.Register(cipherRC4Check{})
	r.Register(cipherDESCheck{})
	r.Register(cipher3DESCheck{})
	r.Register(cipherCBCTLS10Check{})
	r.Register(cipherDHWeakCheck{})

	// Phase 6.4 — Raw SSLv2 / SSLv3 probes
	r.Register(ssl2Check{})
	r.Register(ssl3Check{})

	// Phase 6.5 — Heartbleed (stub; active probe deferred until zcrypto added)
	r.Register(heartbleedCheck{})

	// Phase 6.6 — HSTS + redirect
	r.Register(hstsMissingCheck{})
	r.Register(hstsMaxAgeLowCheck{})
	r.Register(hstsNoIncludeSubCheck{})
	r.Register(hstsNoPreloadCheck{})
	r.Register(httpRedirectCheck{})
}
