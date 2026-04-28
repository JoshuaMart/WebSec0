package tls

import (
	"context"
	"fmt"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// cipherHex formats a cipher suite ID as a 0x-prefixed hex string.
func cipherHex(id uint16) string {
	return fmt.Sprintf("0x%04X", id)
}

// --- TLS-PROTOCOL-LEGACY-SSL2 ------------------------------------------------

type ssl2Check struct{}

func (ssl2Check) ID() string                       { return IDProtocolLegacySSL2 }
func (ssl2Check) Family() checks.Family            { return checks.FamilyTLS }
func (ssl2Check) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (ssl2Check) Title() string                    { return "SSLv2 is disabled" }
func (ssl2Check) Description() string {
	return "SSLv2 (1995) is fundamentally broken: it has no authentication of the server, weak export ciphers, and trivially-crackable key exchange. Any server still accepting SSLv2 connections is critically compromised."
}
func (ssl2Check) RFCRefs() []string { return []string{"RFC 6176"} }

func (ssl2Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDProtocolLegacySSL2, checks.SeverityCritical, err), nil
	}
	if !res.SSL2Supported {
		return passFinding(IDProtocolLegacySSL2, checks.SeverityCritical,
			"SSLv2 not accepted",
			map[string]any{"accepted": false}), nil
	}
	return failFinding(IDProtocolLegacySSL2, checks.SeverityCritical,
		"SSLv2 accepted",
		"The server accepted an SSLv2 ClientHello. SSLv2 is cryptographically broken and was deprecated by RFC 6176. Any modern server must reject SSLv2 entirely.",
		map[string]any{"accepted": true}), nil
}

// --- TLS-PROTOCOL-LEGACY-SSL3 ------------------------------------------------

type ssl3Check struct{}

func (ssl3Check) ID() string                       { return IDProtocolLegacySSL3 }
func (ssl3Check) Family() checks.Family            { return checks.FamilyTLS }
func (ssl3Check) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (ssl3Check) Title() string                    { return "SSLv3 is disabled" }
func (ssl3Check) Description() string {
	return "SSLv3 (1996) is vulnerable to the POODLE attack (CVE-2014-3566), which allows decryption of any chosen byte of the secret. It was formally deprecated by RFC 7568."
}
func (ssl3Check) RFCRefs() []string { return []string{"RFC 7568"} }

func (ssl3Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDProtocolLegacySSL3, checks.SeverityCritical, err), nil
	}
	if !res.SSL3Supported {
		return passFinding(IDProtocolLegacySSL3, checks.SeverityCritical,
			"SSLv3 not accepted",
			map[string]any{"accepted": false}), nil
	}
	return failFinding(IDProtocolLegacySSL3, checks.SeverityCritical,
		"SSLv3 accepted",
		"The server accepted an SSLv3 ClientHello. SSLv3 is vulnerable to POODLE (CVE-2014-3566) and must be disabled. RFC 7568 deprecated it in June 2015.",
		map[string]any{"accepted": true}), nil
}

// --- TLS-PROTOCOL-LEGACY-TLS10 -----------------------------------------------

type tls10Check struct{}

func (tls10Check) ID() string                       { return IDProtocolLegacyTLS10 }
func (tls10Check) Family() checks.Family            { return checks.FamilyTLS }
func (tls10Check) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (tls10Check) Title() string                    { return "TLS 1.0 is disabled" }
func (tls10Check) Description() string {
	return "TLS 1.0 was deprecated by RFC 8996 (March 2021). It is vulnerable to the BEAST attack when used with CBC ciphers, and is no longer compliant with PCI-DSS 4.0 or NIST SP 800-52 Rev. 2."
}
func (tls10Check) RFCRefs() []string { return []string{"RFC 8996"} }

func (tls10Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDProtocolLegacyTLS10, checks.SeverityHigh, err), nil
	}
	if !res.TLS10Supported {
		return passFinding(IDProtocolLegacyTLS10, checks.SeverityHigh,
			"TLS 1.0 not accepted", nil), nil
	}
	ev := map[string]any{"negotiated_cipher": cipherHex(res.TLS10Cipher)}
	return failFinding(IDProtocolLegacyTLS10, checks.SeverityHigh,
		"TLS 1.0 accepted",
		"The server negotiated TLS 1.0. RFC 8996 deprecated TLS 1.0 in March 2021. Disable it and require TLS 1.2 as the minimum.",
		ev), nil
}

// --- TLS-PROTOCOL-LEGACY-TLS11 -----------------------------------------------

type tls11Check struct{}

func (tls11Check) ID() string                       { return IDProtocolLegacyTLS11 }
func (tls11Check) Family() checks.Family            { return checks.FamilyTLS }
func (tls11Check) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (tls11Check) Title() string                    { return "TLS 1.1 is disabled" }
func (tls11Check) Description() string {
	return "TLS 1.1 was deprecated by RFC 8996 (March 2021). While less vulnerable than TLS 1.0, it still lacks the security improvements of TLS 1.2/1.3 and is no longer compliant with modern standards."
}
func (tls11Check) RFCRefs() []string { return []string{"RFC 8996"} }

func (tls11Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDProtocolLegacyTLS11, checks.SeverityHigh, err), nil
	}
	if !res.TLS11Supported {
		return passFinding(IDProtocolLegacyTLS11, checks.SeverityHigh,
			"TLS 1.1 not accepted", nil), nil
	}
	ev := map[string]any{"negotiated_cipher": cipherHex(res.TLS11Cipher)}
	return failFinding(IDProtocolLegacyTLS11, checks.SeverityHigh,
		"TLS 1.1 accepted",
		"The server negotiated TLS 1.1. RFC 8996 deprecated TLS 1.1 in March 2021. Disable it and require TLS 1.2 as the minimum.",
		ev), nil
}

// --- TLS-CIPHER-NULL ---------------------------------------------------------

type cipherNullCheck struct{}

func (cipherNullCheck) ID() string                       { return IDCipherNull }
func (cipherNullCheck) Family() checks.Family            { return checks.FamilyTLS }
func (cipherNullCheck) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (cipherNullCheck) Title() string                    { return "NULL cipher suites are rejected" }
func (cipherNullCheck) Description() string {
	return "NULL cipher suites provide no encryption whatsoever — all traffic is sent in cleartext. A server accepting them offers no more protection than plain HTTP."
}
func (cipherNullCheck) RFCRefs() []string { return []string{"RFC 9325"} }

func (cipherNullCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherNull, checks.SeverityCritical, err), nil
	}
	if !res.NullAccepted {
		return passFinding(IDCipherNull, checks.SeverityCritical,
			"NULL cipher suites not accepted",
			map[string]any{"accepted": false}), nil
	}
	return failFinding(IDCipherNull, checks.SeverityCritical,
		"NULL cipher suite accepted",
		"The server accepted a cipher suite that provides no encryption. Traffic is sent in plaintext.",
		map[string]any{"negotiated_cipher": cipherHex(res.NullCipher)}), nil
}

// --- TLS-CIPHER-EXPORT -------------------------------------------------------

type cipherExportCheck struct{}

func (cipherExportCheck) ID() string                       { return IDCipherExport }
func (cipherExportCheck) Family() checks.Family            { return checks.FamilyTLS }
func (cipherExportCheck) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (cipherExportCheck) Title() string                    { return "EXPORT cipher suites are rejected" }
func (cipherExportCheck) Description() string {
	return "EXPORT cipher suites use artificially weakened key material (40-bit keys) mandated by 1990s US export regulations. They are the basis of the FREAK attack (CVE-2015-0204)."
}
func (cipherExportCheck) RFCRefs() []string { return []string{"RFC 7465"} }

func (cipherExportCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherExport, checks.SeverityCritical, err), nil
	}
	if !res.ExportAccepted {
		return passFinding(IDCipherExport, checks.SeverityCritical,
			"EXPORT cipher suites not accepted",
			map[string]any{"accepted": false}), nil
	}
	return failFinding(IDCipherExport, checks.SeverityCritical,
		"EXPORT cipher suite accepted",
		"The server accepted an EXPORT-grade cipher suite. These use intentionally weak 40-bit keys susceptible to brute-force in under a minute (FREAK, CVE-2015-0204).",
		map[string]any{"negotiated_cipher": cipherHex(res.ExportCipher)}), nil
}

// --- TLS-CIPHER-RC4 ----------------------------------------------------------

type cipherRC4Check struct{}

func (cipherRC4Check) ID() string                       { return IDCipherRC4 }
func (cipherRC4Check) Family() checks.Family            { return checks.FamilyTLS }
func (cipherRC4Check) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (cipherRC4Check) Title() string                    { return "RC4 cipher suites are rejected" }
func (cipherRC4Check) Description() string {
	return "RC4 has multiple cryptographic biases that allow session key recovery given sufficient ciphertext. It was prohibited by RFC 7465 in February 2015."
}
func (cipherRC4Check) RFCRefs() []string { return []string{"RFC 7465"} }

func (cipherRC4Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherRC4, checks.SeverityHigh, err), nil
	}
	if !res.RC4Accepted {
		return passFinding(IDCipherRC4, checks.SeverityHigh,
			"RC4 cipher suites not accepted",
			map[string]any{"accepted": false}), nil
	}
	return failFinding(IDCipherRC4, checks.SeverityHigh,
		"RC4 cipher suite accepted",
		"The server accepted an RC4 cipher suite. RC4 has known statistical biases that allow session decryption. RFC 7465 prohibited RC4 in TLS in February 2015.",
		map[string]any{"negotiated_cipher": cipherHex(res.RC4Cipher)}), nil
}

// --- TLS-CIPHER-DES ----------------------------------------------------------

type cipherDESCheck struct{}

func (cipherDESCheck) ID() string                       { return IDCipherDES }
func (cipherDESCheck) Family() checks.Family            { return checks.FamilyTLS }
func (cipherDESCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (cipherDESCheck) Title() string                    { return "DES cipher suites are rejected" }
func (cipherDESCheck) Description() string {
	return "Single DES uses 56-bit effective key length, exhaustively broken by EFF's DES Cracker in 1998. Any ciphertext encrypted with DES can be decrypted in under 24 hours today."
}
func (cipherDESCheck) RFCRefs() []string { return []string{"RFC 9325"} }

func (cipherDESCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherDES, checks.SeverityHigh, err), nil
	}
	if !res.DESAccepted {
		return passFinding(IDCipherDES, checks.SeverityHigh,
			"DES cipher suites not accepted",
			map[string]any{"accepted": false}), nil
	}
	return failFinding(IDCipherDES, checks.SeverityHigh,
		"DES cipher suite accepted",
		"The server accepted a single-DES cipher suite. DES has only 56-bit keys and is trivially brute-forced with modern hardware.",
		map[string]any{"negotiated_cipher": cipherHex(res.DESCipher)}), nil
}

// --- TLS-CIPHER-3DES ---------------------------------------------------------

type cipher3DESCheck struct{}

func (cipher3DESCheck) ID() string                       { return IDCipherTripleDES }
func (cipher3DESCheck) Family() checks.Family            { return checks.FamilyTLS }
func (cipher3DESCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (cipher3DESCheck) Title() string                    { return "3DES cipher suites are rejected" }
func (cipher3DESCheck) Description() string {
	return "3DES is vulnerable to the Sweet32 birthday attack (CVE-2016-2183) after ~785 GB of ciphertext due to its 64-bit block size. NIST deprecated 3DES in 2017."
}
func (cipher3DESCheck) RFCRefs() []string { return []string{"RFC 9325"} }

func (cipher3DESCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherTripleDES, checks.SeverityMedium, err), nil
	}
	if !res.TripleDESAccepted {
		return passFinding(IDCipherTripleDES, checks.SeverityMedium,
			"3DES cipher suites not accepted",
			map[string]any{"accepted": false}), nil
	}
	return failFinding(IDCipherTripleDES, checks.SeverityMedium,
		"3DES cipher suite accepted",
		"The server accepted a 3DES cipher suite. 3DES is vulnerable to the Sweet32 birthday attack (CVE-2016-2183) given sufficient traffic. Replace with AES-GCM.",
		map[string]any{"negotiated_cipher": cipherHex(res.TripleDESCipher)}), nil
}

// --- TLS-CIPHER-CBC-TLS10 ----------------------------------------------------

type cipherCBCTLS10Check struct{}

func (cipherCBCTLS10Check) ID() string                       { return IDCipherCBCTLS10 }
func (cipherCBCTLS10Check) Family() checks.Family            { return checks.FamilyTLS }
func (cipherCBCTLS10Check) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (cipherCBCTLS10Check) Title() string                    { return "CBC ciphers not accepted under TLS 1.0" }
func (cipherCBCTLS10Check) Description() string {
	return "CBC cipher suites in TLS 1.0 are vulnerable to the BEAST attack (CVE-2011-3389), which allows a man-in-the-middle to recover plaintext bytes. Disabling TLS 1.0 fully mitigates this."
}
func (cipherCBCTLS10Check) RFCRefs() []string { return []string{"RFC 8996"} }

func (cipherCBCTLS10Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherCBCTLS10, checks.SeverityMedium, err), nil
	}
	if !res.CBCInTLS10Accepted {
		return passFinding(IDCipherCBCTLS10, checks.SeverityMedium,
			"CBC ciphers with TLS 1.0 not accepted",
			map[string]any{"accepted": false}), nil
	}
	ev := map[string]any{"negotiated_cipher": cipherHex(res.CBCTLS10Cipher)}
	return failFinding(IDCipherCBCTLS10, checks.SeverityMedium,
		"CBC cipher accepted under TLS 1.0 (BEAST)",
		"The server negotiated a CBC cipher suite over TLS 1.0 — the combination exploited by BEAST (CVE-2011-3389). Disable TLS 1.0 to remove the attack surface.",
		ev), nil
}

// --- TLS-CIPHER-DH-WEAK ------------------------------------------------------

const dhWeakThresholdBits = 2048

type cipherDHWeakCheck struct{}

func (cipherDHWeakCheck) ID() string                       { return IDCipherDHWeak }
func (cipherDHWeakCheck) Family() checks.Family            { return checks.FamilyTLS }
func (cipherDHWeakCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (cipherDHWeakCheck) Title() string                    { return "DHE key exchange uses at least 2048-bit parameters" }
func (cipherDHWeakCheck) Description() string {
	return "DHE key exchange with primes smaller than 2048 bits is vulnerable to the Logjam attack (CVE-2015-4000), which allows a state-level adversary to downgrade and break the key exchange."
}
func (cipherDHWeakCheck) RFCRefs() []string { return []string{"RFC 7919"} }

func (cipherDHWeakCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := LegacyFetch(ctx, t)
	if err != nil {
		return errFinding(IDCipherDHWeak, checks.SeverityHigh, err), nil
	}
	if res.DHKeyBits == 0 {
		return skippedFinding(IDCipherDHWeak, checks.SeverityHigh,
			"server does not offer DHE cipher suites"), nil
	}
	ev := map[string]any{"dh_prime_bits": res.DHKeyBits}
	if res.DHKeyBits >= dhWeakThresholdBits {
		return passFinding(IDCipherDHWeak, checks.SeverityHigh,
			fmt.Sprintf("DHE prime is %d bits (≥ 2048)", res.DHKeyBits), ev), nil
	}
	return failFinding(IDCipherDHWeak, checks.SeverityHigh,
		fmt.Sprintf("DHE prime is only %d bits (< 2048)", res.DHKeyBits),
		fmt.Sprintf("The server's DHE key exchange uses a %d-bit prime. Primes below 2048 bits are vulnerable to Logjam (CVE-2015-4000). Use RFC 7919 named groups or generate a 4096-bit DH group.", res.DHKeyBits),
		ev), nil
}
