package tls

import (
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// extractChain runs one permissive handshake to capture the peer
// certificates, validates the chain against the system root store and
// parses the stapled OCSP response (if any). Failure to handshake yields
// an empty chain and ChainTrustUnknown.
func extractChain(ctx context.Context, target *safehttp.Target) ([]scan.Certificate, scan.ChainTrust, bool, scan.OCSPStatus) {
	state, err := attemptHandshake(ctx, target, handshakeOpts{
		MinVersion: stdtls.VersionTLS10,
		MaxVersion: stdtls.VersionTLS13,
	})
	if err != nil {
		return []scan.Certificate{}, scan.ChainTrustUnknown, false, scan.OCSPStatusUnknown
	}
	chain := mapChain(state.PeerCertificates)
	trust := validateChain(state.PeerCertificates, target.Host)
	stapled := len(state.OCSPResponse) > 0
	ocspStatus := parseOCSPStatus(state.OCSPResponse, state.PeerCertificates)
	return chain, trust, stapled, ocspStatus
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

func validateChain(chain []*x509.Certificate, host string) scan.ChainTrust {
	if len(chain) == 0 {
		return scan.ChainTrustNoChain
	}
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return scan.ChainTrustUntrusted
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err == nil {
		return scan.ChainTrustTrusted
	}
	return classifyValidationError(err, leaf)
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
		if leaf.Subject.String() == leaf.Issuer.String() {
			return scan.ChainTrustSelfSigned
		}
		return scan.ChainTrustUntrusted
	}
	return scan.ChainTrustUntrusted
}
