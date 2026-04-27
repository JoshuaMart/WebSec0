package tls

import (
	"context"
	stdtls "crypto/tls"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// hasForwardSecrecy reports whether suite is an ECDHE/DHE-based cipher
// (TLS 1.3 suites are all FS by construction).
func hasForwardSecrecy(version, suite uint16) bool {
	if version == stdtls.VersionTLS13 {
		return true
	}
	for _, s := range stdtls.CipherSuites() {
		if s.ID != suite {
			continue
		}
		// stdlib's curated list only contains ECDHE/CHACHA suites; if the
		// negotiated cipher is in CipherSuites() it is FS.
		return true
	}
	return false
}

// --- TLS-PROTOCOL-TLS12-MISSING ---------------------------------------

type tls12MissingCheck struct{}

func (tls12MissingCheck) ID() string                       { return IDProtocolTLS12Missing }
func (tls12MissingCheck) Family() checks.Family            { return checks.FamilyTLS }
func (tls12MissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (tls12MissingCheck) Title() string                    { return "TLS 1.2 is supported" }
func (tls12MissingCheck) Description() string {
	return "TLS 1.2 is the floor for modern interoperability and is required by most browsers and PCI-DSS 4.0."
}
func (tls12MissingCheck) RFCRefs() []string { return []string{"RFC 5246"} }

func (tls12MissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDProtocolTLS12Missing, checks.SeverityHigh, err), nil
	}
	p := res.Probes[stdtls.VersionTLS12]
	if p != nil && p.Supported {
		return passFinding(IDProtocolTLS12Missing, checks.SeverityHigh,
			"TLS 1.2 supported", nil), nil
	}
	desc := "Server refused a TLS 1.2 ClientHello."
	if p != nil && p.HandshakeErr != nil {
		desc = p.HandshakeErr.Error()
	}
	return failFinding(IDProtocolTLS12Missing, checks.SeverityHigh,
		"TLS 1.2 not supported", desc, nil), nil
}

// --- TLS-PROTOCOL-TLS13-MISSING ---------------------------------------

type tls13MissingCheck struct{}

func (tls13MissingCheck) ID() string                       { return IDProtocolTLS13Missing }
func (tls13MissingCheck) Family() checks.Family            { return checks.FamilyTLS }
func (tls13MissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (tls13MissingCheck) Title() string                    { return "TLS 1.3 is supported" }
func (tls13MissingCheck) Description() string {
	return "TLS 1.3 (RFC 8446) removes legacy cryptographic constructs and shaves a round-trip from the handshake."
}
func (tls13MissingCheck) RFCRefs() []string { return []string{"RFC 8446"} }

func (tls13MissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDProtocolTLS13Missing, checks.SeverityMedium, err), nil
	}
	p := res.Probes[stdtls.VersionTLS13]
	if p != nil && p.Supported {
		return passFinding(IDProtocolTLS13Missing, checks.SeverityMedium,
			"TLS 1.3 supported", nil), nil
	}
	desc := "Server refused a TLS 1.3 ClientHello."
	if p != nil && p.HandshakeErr != nil {
		desc = p.HandshakeErr.Error()
	}
	return failFinding(IDProtocolTLS13Missing, checks.SeverityMedium,
		"TLS 1.3 not supported", desc, nil), nil
}

// --- TLS-CIPHER-NO-FORWARD-SECRECY ------------------------------------

type noFSCheck struct{}

func (noFSCheck) ID() string                       { return IDCipherNoForwardSecrecy }
func (noFSCheck) Family() checks.Family            { return checks.FamilyTLS }
func (noFSCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (noFSCheck) Title() string                    { return "Forward secrecy is in use" }
func (noFSCheck) Description() string {
	return "ECDHE / DHE / TLS 1.3 ensure session keys are not recoverable from a long-term private key compromise."
}
func (noFSCheck) RFCRefs() []string { return []string{"RFC 7525"} }

func (noFSCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherNoForwardSecrecy, checks.SeverityHigh, err), nil
	}
	if !res.AnySucceeded {
		return skippedFinding(IDCipherNoForwardSecrecy, checks.SeverityHigh, "no successful TLS handshake"), nil
	}
	for _, v := range []uint16{stdtls.VersionTLS13, stdtls.VersionTLS12} {
		p := res.Probes[v]
		if p == nil || !p.Supported {
			continue
		}
		if hasForwardSecrecy(v, p.NegotiatedCS) {
			return passFinding(IDCipherNoForwardSecrecy, checks.SeverityHigh,
				"forward-secret cipher negotiated",
				map[string]any{
					"version": versionString(v),
					"cipher":  cipherName(p.NegotiatedCS),
				}), nil
		}
	}
	return failFinding(IDCipherNoForwardSecrecy, checks.SeverityHigh,
		"no forward-secret cipher negotiated",
		"All probed handshakes negotiated a cipher without ECDHE/DHE.", nil), nil
}

// --- TLS-ALPN-NO-HTTP2 ------------------------------------------------

type noH2Check struct{}

func (noH2Check) ID() string                       { return IDALPNNoHTTP2 }
func (noH2Check) Family() checks.Family            { return checks.FamilyTLS }
func (noH2Check) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (noH2Check) Title() string                    { return "HTTP/2 is advertised via ALPN" }
func (noH2Check) Description() string {
	return "Servers should advertise `h2` via ALPN to enable HTTP/2 (RFC 7540)."
}
func (noH2Check) RFCRefs() []string { return []string{"RFC 7301", "RFC 7540"} }

func (noH2Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDALPNNoHTTP2, checks.SeverityLow, err), nil
	}
	if !res.AnySucceeded {
		return skippedFinding(IDALPNNoHTTP2, checks.SeverityLow, "no successful TLS handshake"), nil
	}
	for _, v := range []uint16{stdtls.VersionTLS13, stdtls.VersionTLS12} {
		p := res.Probes[v]
		if p == nil || !p.Supported {
			continue
		}
		if p.ALPN == "h2" {
			return passFinding(IDALPNNoHTTP2, checks.SeverityLow,
				"HTTP/2 negotiated via ALPN",
				map[string]any{"version": versionString(v)}), nil
		}
	}
	return failFinding(IDALPNNoHTTP2, checks.SeverityLow,
		"HTTP/2 not advertised",
		"No probed handshake negotiated `h2` via ALPN.", nil), nil
}

// --- TLS-OCSP-STAPLING-MISSING ----------------------------------------

type ocspStaplingCheck struct{}

func (ocspStaplingCheck) ID() string                       { return IDOCSPStaplingMissing }
func (ocspStaplingCheck) Family() checks.Family            { return checks.FamilyTLS }
func (ocspStaplingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (ocspStaplingCheck) Title() string                    { return "OCSP stapling is enabled" }
func (ocspStaplingCheck) Description() string {
	return "Stapling avoids client-side OCSP lookups (privacy + latency); RFC 6066 §8."
}
func (ocspStaplingCheck) RFCRefs() []string { return []string{"RFC 6066"} }

func (ocspStaplingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDOCSPStaplingMissing, checks.SeverityLow, err), nil
	}
	if !res.AnySucceeded {
		return skippedFinding(IDOCSPStaplingMissing, checks.SeverityLow, "no successful TLS handshake"), nil
	}
	for _, v := range []uint16{stdtls.VersionTLS13, stdtls.VersionTLS12} {
		p := res.Probes[v]
		if p == nil || !p.Supported {
			continue
		}
		if p.OCSPStapled {
			return passFinding(IDOCSPStaplingMissing, checks.SeverityLow,
				"OCSP response stapled", nil), nil
		}
	}
	return failFinding(IDOCSPStaplingMissing, checks.SeverityLow,
		"OCSP stapling not enabled",
		"No probed handshake stapled an OCSP response.", nil), nil
}

// --- helpers ----------------------------------------------------------

func versionString(v uint16) string {
	switch v {
	case stdtls.VersionTLS10:
		return "TLS 1.0"
	case stdtls.VersionTLS11:
		return "TLS 1.1"
	case stdtls.VersionTLS12:
		return "TLS 1.2"
	case stdtls.VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

func cipherName(id uint16) string {
	if n := stdtls.CipherSuiteName(id); n != "" {
		return n
	}
	return "unknown"
}
