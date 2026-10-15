package tls

import (
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

type certificateInfo struct {
	chain           []scan.Certificate
	trust           scan.ChainTrust
	stapled         bool
	ocspStatus      scan.OCSPStatus
	handshakeSCTs   *scan.SCTSummary
	certificateSCTs *scan.CertificateSCTs
}

// IssuerFetcher returns the body served at an AIA caIssuers URL. The
// orchestrator supplies it so the request follows the scan's network policy.
type IssuerFetcher func(ctx context.Context, rawURL string) ([]byte, error)

// AIA completion is bounded: public chains rarely need more than one missing
// intermediate, and each URL comes from a certificate the target controls.
const (
	maxAIAHops       = 2
	maxAIAURLsPerHop = 2
)

// extractChain captures certificates, OCSP and SCTs in one permissive handshake.
func extractChain(ctx context.Context, target *safehttp.Target, fetch IssuerFetcher) certificateInfo {
	state, err := attemptHandshake(ctx, target, handshakeOpts{
		MinVersion: stdtls.VersionTLS10,
		MaxVersion: stdtls.VersionTLS13,
	})
	if err != nil {
		return certificateInfo{chain: []scan.Certificate{}}
	}
	return certificateInfo{
		chain:           mapChain(state.PeerCertificates),
		trust:           validateChain(ctx, state.PeerCertificates, target.Host, fetch),
		stapled:         len(state.OCSPResponse) > 0,
		ocspStatus:      parseOCSPStatus(state.OCSPResponse, state.PeerCertificates),
		handshakeSCTs:   summarizeSCTs(state.SignedCertificateTimestamps),
		certificateSCTs: extractCertificateSCTs(state.PeerCertificates),
	}
}

func mapChain(certs []*x509.Certificate) []scan.Certificate {
	out := make([]scan.Certificate, 0, len(certs))
	now := time.Now()
	for i, c := range certs {
		kind := "Intermediate"
		switch {
		case i == 0:
			kind = "Leaf"
		case c.Subject.String() == c.Issuer.String():
			kind = "Root"
		}
		sum := sha256.Sum256(c.Raw)
		days := int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
		out = append(out, scan.Certificate{
			Step:       i + 1,
			Kind:       kind,
			CommonName: c.Subject.CommonName,
			Issuer:     c.Issuer.CommonName,
			NotBefore:  c.NotBefore,
			NotAfter:   c.NotAfter,
			DaysLeft:   days,
			KeyAlg:     c.PublicKeyAlgorithm.String(),
			SigAlg:     c.SignatureAlgorithm.String(),
			Serial:     "0x" + c.SerialNumber.Text(16),
			SHA256:     formatFingerprint(sum[:]),
			SAN:        sanList(c),
			Revocation: "",
		})
	}
	return out
}

func formatFingerprint(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(b))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func sanList(c *x509.Certificate) []string {
	if len(c.DNSNames) == 0 {
		return []string{"—"}
	}
	return append([]string{}, c.DNSNames...)
}

// validateChain reports whether the served chain validates on its own. A
// chain that validates only with intermediates the server did not send is
// incomplete: browsers usually repair it, but stricter TLS clients reject it.
func validateChain(ctx context.Context, chain []*x509.Certificate, host string, fetch IssuerFetcher) scan.ChainTrust {
	if len(chain) == 0 {
		return scan.ChainTrustNoChain
	}
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	verified, err := verifyLeaf(leaf, host, intermediates)
	if err == nil {
		// Platform verifiers such as macOS may fetch missing intermediates
		// themselves; report the same outcome as the pure-Go verifier.
		if needsUnservedIntermediate(verified, chain) {
			return scan.ChainTrustIncomplete
		}
		return scan.ChainTrustTrusted
	}
	var unknownAuth x509.UnknownAuthorityError
	if fetch != nil && errors.As(err, &unknownAuth) && !isSelfIssued(leaf) &&
		completeViaAIA(ctx, leaf, host, intermediates, fetch) {
		return scan.ChainTrustIncomplete
	}
	return classifyValidationError(err, leaf)
}

func verifyLeaf(leaf *x509.Certificate, host string, intermediates *x509.CertPool) ([][]*x509.Certificate, error) {
	// Nil Roots lets Go use system trust, or the binary's registered fallback.
	return leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
	})
}

// needsUnservedIntermediate reports whether every verified chain relies on
// an intermediate that is neither served nor the trust anchor.
func needsUnservedIntermediate(verified [][]*x509.Certificate, served []*x509.Certificate) bool {
	if len(verified) == 0 {
		return false
	}
	sent := make(map[string]bool, len(served))
	for _, c := range served {
		sent[string(c.Raw)] = true
	}
	for _, path := range verified {
		complete := true
		for i := 1; i < len(path)-1; i++ {
			if !sent[string(path[i].Raw)] {
				complete = false
				break
			}
		}
		if complete {
			return false
		}
	}
	return true
}

// completeViaAIA follows caIssuers URLs from the leaf upwards and reports
// whether the fetched issuers let the leaf validate.
func completeViaAIA(ctx context.Context, leaf *x509.Certificate, host string, intermediates *x509.CertPool, fetch IssuerFetcher) bool {
	current := leaf
	for range maxAIAHops {
		issuer := fetchIssuer(ctx, current, fetch)
		if issuer == nil {
			return false
		}
		intermediates.AddCert(issuer)
		if _, err := verifyLeaf(leaf, host, intermediates); err == nil {
			return true
		}
		if isSelfIssued(issuer) {
			return false
		}
		current = issuer
	}
	return false
}

// fetchIssuer returns the first fetched certificate that signed c.
func fetchIssuer(ctx context.Context, c *x509.Certificate, fetch IssuerFetcher) *x509.Certificate {
	urls := c.IssuingCertificateURL
	if len(urls) > maxAIAURLsPerHop {
		urls = urls[:maxAIAURLsPerHop]
	}
	for _, u := range urls {
		if ctx.Err() != nil {
			return nil
		}
		body, err := fetch(ctx, u)
		if err != nil {
			continue
		}
		for _, candidate := range parseIssuerCertificates(body) {
			if c.CheckSignatureFrom(candidate) == nil {
				return candidate
			}
		}
	}
	return nil
}

// parseIssuerCertificates accepts the DER and PEM encodings CAs publish.
// PKCS#7 bundles are not parsed; those chains stay untrusted.
func parseIssuerCertificates(body []byte) []*x509.Certificate {
	if c, err := x509.ParseCertificate(body); err == nil {
		return []*x509.Certificate{c}
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, body = pem.Decode(body)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

func isSelfIssued(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String()
}

func classifyValidationError(err error, leaf *x509.Certificate) scan.ChainTrust {
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return scan.ChainTrustHostnameMismatch
	}
	var certErr x509.CertificateInvalidError
	if errors.As(err, &certErr) && certErr.Reason == x509.Expired {
		return scan.ChainTrustExpired
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		if isSelfIssued(leaf) {
			return scan.ChainTrustSelfSigned
		}
		return scan.ChainTrustUntrusted
	}
	return scan.ChainTrustUntrusted
}
