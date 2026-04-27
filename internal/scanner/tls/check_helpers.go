package tls

import "github.com/JoshuaMart/websec0/internal/checks"

// Check IDs for the TLS family.
const (
	// Modern TLS / cert / HSTS (phases 6.1, 6.2, 6.6)
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
	IDCertNoCT                = "TLS-CERT-NO-CT"
	IDHSTSMissing             = "TLS-HSTS-MISSING"
	IDHSTSMaxAgeLow           = "TLS-HSTS-MAX-AGE-LOW"
	IDHSTSNoIncludeSubDomains = "TLS-HSTS-NO-INCLUDESUBDOMAINS"
	IDHSTSNoPreload           = "TLS-HSTS-NO-PRELOAD"
	IDRedirectHTTPToHTTPS     = "TLS-REDIRECT-HTTP-TO-HTTPS"

	// Legacy protocols (phase 6.3 + 6.4)
	IDProtocolLegacySSL2  = "TLS-PROTOCOL-LEGACY-SSL2"
	IDProtocolLegacySSL3  = "TLS-PROTOCOL-LEGACY-SSL3"
	IDProtocolLegacyTLS10 = "TLS-PROTOCOL-LEGACY-TLS10"
	IDProtocolLegacyTLS11 = "TLS-PROTOCOL-LEGACY-TLS11"

	// Weak cipher suites (phase 6.3)
	IDCipherNull      = "TLS-CIPHER-NULL"
	IDCipherExport    = "TLS-CIPHER-EXPORT"
	IDCipherRC4       = "TLS-CIPHER-RC4"
	IDCipherDES       = "TLS-CIPHER-DES"
	IDCipherTripleDES = "TLS-CIPHER-3DES"
	IDCipherCBCTLS10  = "TLS-CIPHER-CBC-TLS10"
	IDCipherDHWeak    = "TLS-CIPHER-DH-WEAK"

	// Active vulnerability probe (phase 6.5)
	IDVulnHeartbleed = "TLS-VULN-HEARTBLEED"
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
