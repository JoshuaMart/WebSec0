package tls

import "github.com/JoshuaMart/websec0/internal/checks"

// Check IDs for the TLS family.
const (
	IDProtocolTLS12Missing    = "TLS-PROTOCOL-TLS12-MISSING"
	IDProtocolTLS13Missing    = "TLS-PROTOCOL-TLS13-MISSING"
	IDCipherNoForwardSecrecy  = "TLS-CIPHER-NO-FORWARD-SECRECY"
	IDALPNNoHTTP2             = "TLS-ALPN-NO-HTTP2"
	IDOCSPStaplingMissing     = "TLS-OCSP-STAPLING-MISSING"
	IDHandshakeFailed         = "TLS-HANDSHAKE-FAILED"
	IDCertExpired             = "TLS-CERT-EXPIRED"
	IDCertExpiresSoon14d      = "TLS-CERT-EXPIRES-SOON-14D"
	IDCertExpiresSoon30d      = "TLS-CERT-EXPIRES-SOON-30D"
	IDCertChainIncomplete     = "TLS-CERT-CHAIN-INCOMPLETE"
	IDCertNameMismatch        = "TLS-CERT-NAME-MISMATCH"
	IDCertSelfSigned          = "TLS-CERT-SELF-SIGNED"
	IDCertWeakRSA             = "TLS-CERT-WEAK-RSA"
	IDCertWeakECC             = "TLS-CERT-WEAK-ECC"
	IDCertWeakSignature       = "TLS-CERT-WEAK-SIGNATURE"
	IDHSTSMissing             = "TLS-HSTS-MISSING"
	IDHSTSMaxAgeLow           = "TLS-HSTS-MAX-AGE-LOW"
	IDHSTSNoIncludeSubDomains = "TLS-HSTS-NO-INCLUDESUBDOMAINS"
	IDRedirectHTTPToHTTPS     = "TLS-REDIRECT-HTTP-TO-HTTPS"
)

// errFinding is the canonical "fetcher exploded" record.
func errFinding(id string, sev checks.Severity, err error) *checks.Finding {
	return &checks.Finding{
		ID:          id,
		Family:      checks.FamilyTLS,
		Severity:    sev,
		Status:      checks.StatusError,
		Title:       "tls: probe error",
		Description: err.Error(),
	}
}

// skippedFinding marks a check as not-applicable (e.g. HTTPS unreachable
// → cert checks all skip).
func skippedFinding(id string, sev checks.Severity, reason string) *checks.Finding {
	return &checks.Finding{
		ID:       id,
		Family:   checks.FamilyTLS,
		Severity: sev,
		Status:   checks.StatusSkipped,
		Title:    "skipped: " + reason,
	}
}

func passFinding(id string, sev checks.Severity, title string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID:       id,
		Family:   checks.FamilyTLS,
		Severity: sev,
		Status:   checks.StatusPass,
		Title:    title,
		Evidence: ev,
	}
}

func failFinding(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID:          id,
		Family:      checks.FamilyTLS,
		Severity:    sev,
		Status:      checks.StatusFail,
		Title:       title,
		Description: desc,
		Evidence:    ev,
	}
}
