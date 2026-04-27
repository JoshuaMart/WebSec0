package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// --- TLS-CERT-EXPIRED -------------------------------------------------

type certExpiredCheck struct{}

func (certExpiredCheck) ID() string                       { return IDCertExpired }
func (certExpiredCheck) Family() checks.Family            { return checks.FamilyTLS }
func (certExpiredCheck) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (certExpiredCheck) Title() string                    { return "Certificate is not expired" }
func (certExpiredCheck) Description() string {
	return "An expired leaf certificate breaks every browser; renew before NotAfter."
}
func (certExpiredCheck) RFCRefs() []string { return []string{"RFC 5280"} }

func (certExpiredCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertExpired, checks.SeverityCritical, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertExpired, checks.SeverityCritical, "no certificate available"), nil
	}
	now := time.Now()
	if now.After(res.Leaf.NotAfter) {
		return failFinding(IDCertExpired, checks.SeverityCritical,
			"certificate expired",
			fmt.Sprintf("NotAfter=%s, now=%s", res.Leaf.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339)),
			map[string]any{"not_after": res.Leaf.NotAfter}), nil
	}
	return passFinding(IDCertExpired, checks.SeverityCritical,
		"certificate is current",
		map[string]any{"not_after": res.Leaf.NotAfter}), nil
}

// --- TLS-CERT-EXPIRES-SOON-{14d,30d} ---------------------------------

type certExpiresSoonCheck struct {
	id        string
	threshold time.Duration
	severity  checks.Severity
}

func (c certExpiresSoonCheck) ID() string                       { return c.id }
func (certExpiresSoonCheck) Family() checks.Family              { return checks.FamilyTLS }
func (c certExpiresSoonCheck) DefaultSeverity() checks.Severity { return c.severity }
func (certExpiresSoonCheck) Title() string                      { return "Certificate has runway" }
func (certExpiresSoonCheck) Description() string {
	return "Certificates renewing inside the threshold window are at risk if automation drops."
}
func (certExpiresSoonCheck) RFCRefs() []string { return []string{"RFC 5280"} }

func (c certExpiresSoonCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(c.id, c.severity, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(c.id, c.severity, "no certificate available"), nil
	}
	now := time.Now()
	if now.After(res.Leaf.NotAfter) {
		// already expired — TLS-CERT-EXPIRED owns that finding
		return skippedFinding(c.id, c.severity, "already expired"), nil
	}
	remaining := res.Leaf.NotAfter.Sub(now)
	ev := map[string]any{
		"not_after":      res.Leaf.NotAfter,
		"days_remaining": int(remaining.Hours() / 24),
	}
	if remaining < c.threshold {
		return failFinding(c.id, c.severity,
			fmt.Sprintf("certificate expires in less than %s", c.threshold),
			fmt.Sprintf("NotAfter=%s", res.Leaf.NotAfter.Format(time.RFC3339)),
			ev), nil
	}
	return passFinding(c.id, c.severity,
		fmt.Sprintf("certificate has > %s of runway", c.threshold), ev), nil
}

// --- TLS-CERT-CHAIN-INCOMPLETE ----------------------------------------

type chainIncompleteCheck struct{}

func (chainIncompleteCheck) ID() string                       { return IDCertChainIncomplete }
func (chainIncompleteCheck) Family() checks.Family            { return checks.FamilyTLS }
func (chainIncompleteCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (chainIncompleteCheck) Title() string                    { return "Certificate chain validates against system roots" }
func (chainIncompleteCheck) Description() string {
	return "Servers must serve every intermediate cert leading to a trusted root (RFC 5280)."
}
func (chainIncompleteCheck) RFCRefs() []string { return []string{"RFC 5280"} }

func (chainIncompleteCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertChainIncomplete, checks.SeverityHigh, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertChainIncomplete, checks.SeverityHigh, "no certificate available"), nil
	}
	if res.SystemVerifyErr == nil {
		return passFinding(IDCertChainIncomplete, checks.SeverityHigh,
			"chain validates against system roots", nil), nil
	}
	if isSelfSigned(res.Leaf) {
		// self-signed has its own check; don't double-count.
		return skippedFinding(IDCertChainIncomplete, checks.SeverityHigh, "self-signed leaf"), nil
	}
	if isHostnameError(res.SystemVerifyErr) {
		// Name-mismatch has its own check.
		return skippedFinding(IDCertChainIncomplete, checks.SeverityHigh, "name mismatch"), nil
	}
	return failFinding(IDCertChainIncomplete, checks.SeverityHigh,
		"certificate chain does not validate",
		res.SystemVerifyErr.Error(), nil), nil
}

// --- TLS-CERT-NAME-MISMATCH -------------------------------------------

type nameMismatchCheck struct{}

func (nameMismatchCheck) ID() string                       { return IDCertNameMismatch }
func (nameMismatchCheck) Family() checks.Family            { return checks.FamilyTLS }
func (nameMismatchCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (nameMismatchCheck) Title() string                    { return "Certificate covers the requested hostname" }
func (nameMismatchCheck) Description() string {
	return "The leaf certificate must cover the connection hostname via subjectAltName."
}
func (nameMismatchCheck) RFCRefs() []string { return []string{"RFC 6125"} }

func (nameMismatchCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertNameMismatch, checks.SeverityHigh, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertNameMismatch, checks.SeverityHigh, "no certificate available"), nil
	}
	if err := res.Leaf.VerifyHostname(t.Hostname); err == nil {
		return passFinding(IDCertNameMismatch, checks.SeverityHigh,
			"hostname matches",
			map[string]any{"sans": res.Leaf.DNSNames}), nil
	}
	return failFinding(IDCertNameMismatch, checks.SeverityHigh,
		"hostname not covered by certificate",
		fmt.Sprintf("Hostname %q not in SANs %v", t.Hostname, res.Leaf.DNSNames),
		map[string]any{"hostname": t.Hostname, "sans": res.Leaf.DNSNames}), nil
}

// --- TLS-CERT-SELF-SIGNED ---------------------------------------------

type selfSignedCheck struct{}

func (selfSignedCheck) ID() string                       { return IDCertSelfSigned }
func (selfSignedCheck) Family() checks.Family            { return checks.FamilyTLS }
func (selfSignedCheck) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (selfSignedCheck) Title() string                    { return "Leaf is signed by a CA, not itself" }
func (selfSignedCheck) Description() string {
	return "Self-signed certificates fail every browser trust store; use a public CA or your private CA."
}
func (selfSignedCheck) RFCRefs() []string { return []string{"RFC 5280"} }

func (selfSignedCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertSelfSigned, checks.SeverityCritical, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertSelfSigned, checks.SeverityCritical, "no certificate available"), nil
	}
	if isSelfSigned(res.Leaf) {
		return failFinding(IDCertSelfSigned, checks.SeverityCritical,
			"certificate is self-signed",
			fmt.Sprintf("Subject=%s Issuer=%s", res.Leaf.Subject, res.Leaf.Issuer),
			map[string]any{
				"subject": res.Leaf.Subject.String(),
				"issuer":  res.Leaf.Issuer.String(),
			}), nil
	}
	return passFinding(IDCertSelfSigned, checks.SeverityCritical,
		"certificate is signed by an external CA",
		map[string]any{"issuer": res.Leaf.Issuer.String()}), nil
}

// --- TLS-CERT-WEAK-RSA / TLS-CERT-WEAK-ECC ----------------------------

type weakRSACheck struct{}

func (weakRSACheck) ID() string                       { return IDCertWeakRSA }
func (weakRSACheck) Family() checks.Family            { return checks.FamilyTLS }
func (weakRSACheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (weakRSACheck) Title() string                    { return "RSA key size meets modern guidance" }
func (weakRSACheck) Description() string {
	return "RSA keys must be at least 2048 bits per CA/Browser Forum baseline §6.1.5."
}
func (weakRSACheck) RFCRefs() []string { return []string{"CA/Browser Forum BR §6.1.5"} }

func (weakRSACheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertWeakRSA, checks.SeverityHigh, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertWeakRSA, checks.SeverityHigh, "no certificate available"), nil
	}
	pk, ok := res.Leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return skippedFinding(IDCertWeakRSA, checks.SeverityHigh, "non-RSA key"), nil
	}
	bits := pk.N.BitLen()
	ev := map[string]any{"bits": bits}
	if bits < 2048 {
		return failFinding(IDCertWeakRSA, checks.SeverityHigh,
			fmt.Sprintf("RSA key is %d bits", bits),
			"At least 2048 bits required.", ev), nil
	}
	return passFinding(IDCertWeakRSA, checks.SeverityHigh,
		fmt.Sprintf("RSA key is %d bits", bits), ev), nil
}

type weakECCCheck struct{}

func (weakECCCheck) ID() string                       { return IDCertWeakECC }
func (weakECCCheck) Family() checks.Family            { return checks.FamilyTLS }
func (weakECCCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (weakECCCheck) Title() string                    { return "ECC key size meets modern guidance" }
func (weakECCCheck) Description() string {
	return "ECDSA keys must be at least 256 bits (P-256 / equivalent)."
}
func (weakECCCheck) RFCRefs() []string { return []string{"CA/Browser Forum BR §6.1.5"} }

func (weakECCCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertWeakECC, checks.SeverityHigh, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertWeakECC, checks.SeverityHigh, "no certificate available"), nil
	}
	switch pk := res.Leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		bits := pk.Params().BitSize
		ev := map[string]any{"bits": bits, "curve": pk.Curve.Params().Name}
		if bits < 256 {
			return failFinding(IDCertWeakECC, checks.SeverityHigh,
				fmt.Sprintf("ECC key is %d bits", bits),
				"At least 256 bits required.", ev), nil
		}
		return passFinding(IDCertWeakECC, checks.SeverityHigh,
			fmt.Sprintf("ECC key is %d bits (%s)", bits, pk.Curve.Params().Name), ev), nil
	case ed25519.PublicKey:
		return passFinding(IDCertWeakECC, checks.SeverityHigh,
			"Ed25519 key (256-bit security)", nil), nil
	default:
		_ = pk // dsa.PublicKey etc. — non-ECC, the RSA check or weak-signature handles them
		return skippedFinding(IDCertWeakECC, checks.SeverityHigh, "non-ECC key"), nil
	}
}

// --- TLS-CERT-WEAK-SIGNATURE ------------------------------------------

type weakSignatureCheck struct{}

func (weakSignatureCheck) ID() string                       { return IDCertWeakSignature }
func (weakSignatureCheck) Family() checks.Family            { return checks.FamilyTLS }
func (weakSignatureCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (weakSignatureCheck) Title() string                    { return "Certificate signed with a strong hash" }
func (weakSignatureCheck) Description() string {
	return "MD5 and SHA-1 signatures are forbidden by every modern browser; use SHA-256 or stronger."
}
func (weakSignatureCheck) RFCRefs() []string { return []string{"CA/Browser Forum BR §6.1.5"} }

func (weakSignatureCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertWeakSignature, checks.SeverityHigh, err), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertWeakSignature, checks.SeverityHigh, "no certificate available"), nil
	}
	sig := res.Leaf.SignatureAlgorithm.String()
	if isWeakSignature(res.Leaf.SignatureAlgorithm) {
		return failFinding(IDCertWeakSignature, checks.SeverityHigh,
			"weak signature algorithm",
			fmt.Sprintf("SignatureAlgorithm=%s", sig),
			map[string]any{"signature_algorithm": sig}), nil
	}
	return passFinding(IDCertWeakSignature, checks.SeverityHigh,
		"strong signature algorithm",
		map[string]any{"signature_algorithm": sig}), nil
}

// --- helpers ----------------------------------------------------------

func isSelfSigned(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	return c.Issuer.String() == c.Subject.String()
}

func isHostnameError(err error) bool {
	var he x509.HostnameError
	return errors.As(err, &he)
}

// isWeakSignature reports whether a is one of the deprecated digests we
// flag as TLS-CERT-WEAK-SIGNATURE. Anything else (including "unknown")
// is considered acceptable here — we never want to false-positive on a
// new algorithm Go adds in the future.
func isWeakSignature(a x509.SignatureAlgorithm) bool {
	switch a { //nolint:exhaustive // intentional deny-list
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// --- TLS-CERT-NO-CT ----------------------------------------------------------

// oidSCTList is the X.509 extension OID for embedded SCTs (RFC 6962 §3.3).
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

type ctCheck struct{}

func (ctCheck) ID() string                       { return IDCertNoCT }
func (ctCheck) Family() checks.Family            { return checks.FamilyTLS }
func (ctCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (ctCheck) Title() string                    { return "Certificate is logged in Certificate Transparency" }
func (ctCheck) Description() string {
	return "Certificate Transparency (RFC 6962) requires CAs to log certificates to public, append-only logs. " +
		"Browsers enforce CT for publicly-trusted certificates. SCTs can be delivered via the TLS handshake " +
		"extension, embedded in the certificate (OID 1.3.6.1.4.1.11129.2.4.2), or via OCSP stapling."
}
func (ctCheck) RFCRefs() []string { return []string{"RFC 6962"} }

func (ctCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCertNoCT, checks.SeverityLow, err), nil
	}
	if !res.AnySucceeded {
		return skippedFinding(IDCertNoCT, checks.SeverityLow, "HTTPS unreachable"), nil
	}
	if res.Leaf == nil {
		return skippedFinding(IDCertNoCT, checks.SeverityLow, "no leaf certificate"), nil
	}

	// Method 1: SCTs delivered via TLS handshake extension (most common for modern CAs).
	for _, v := range []uint16{stdtls.VersionTLS13, stdtls.VersionTLS12} {
		p := res.Probes[v]
		if p != nil && p.Supported && len(p.SCTs) > 0 {
			return passFinding(IDCertNoCT, checks.SeverityLow,
				"SCTs present via TLS handshake extension",
				map[string]any{
					"delivery":  "tls_extension",
					"sct_count": len(p.SCTs),
					"version":   versionString(v),
				}), nil
		}
	}

	// Method 2: SCTs embedded in the certificate as an X.509 extension (OID 1.3.6.1.4.1.11129.2.4.2).
	for _, ext := range res.Leaf.Extensions {
		if ext.Id.Equal(oidSCTList) {
			return passFinding(IDCertNoCT, checks.SeverityLow,
				"SCTs embedded in certificate (X.509 extension)",
				map[string]any{"delivery": "x509_extension"}), nil
		}
	}

	// Method 3: SCTs via OCSP stapling — we don't parse the OCSP response here,
	// but stapling is noted in evidence as a potential (unverified) source.
	ocspNote := ""
	for _, v := range []uint16{stdtls.VersionTLS13, stdtls.VersionTLS12} {
		if p := res.Probes[v]; p != nil && p.OCSPStapled {
			ocspNote = "OCSP response stapled (may carry SCTs, not parsed)"
			break
		}
	}

	ev := map[string]any{
		"tls_extension_scts": 0,
		"x509_embedded_scts": false,
	}
	if ocspNote != "" {
		ev["ocsp_note"] = ocspNote
	}
	return failFinding(IDCertNoCT, checks.SeverityLow,
		"no SCTs found",
		"No Signed Certificate Timestamps were found in the TLS handshake extension or in the certificate's X.509 extension. "+
			"SCTs are required for CA/Browser Forum compliance and enforced by Chrome and Safari.",
		ev), nil
}
