package tls

import (
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// Register adds every TLS check shipped in Phase 6.1+6.2+6.6 to r.
//
// Phase 6.x deferrals (legacy TLS 1.0/1.1, raw SSLv2/SSLv3, Heartbleed,
// CT/SCT, HSTS preload API) will register additional checks later.
func Register(r *checks.Registry) {
	r.Register(tls12MissingCheck{})
	r.Register(tls13MissingCheck{})
	r.Register(noFSCheck{})
	r.Register(noH2Check{})
	r.Register(ocspStaplingCheck{})

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

	r.Register(hstsMissingCheck{})
	r.Register(hstsMaxAgeLowCheck{})
	r.Register(hstsNoIncludeSubCheck{})

	r.Register(httpRedirectCheck{})
}
