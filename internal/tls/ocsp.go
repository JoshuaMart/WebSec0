package tls

import (
	"crypto/x509"

	"github.com/JoshuaMart/websec0/internal/scan"
	"golang.org/x/crypto/ocsp"
)

// parseOCSPStatus decodes an OCSP response captured from the TLS handshake.
// The issuer (second certificate in the chain) is required for signature
// validation; when only the leaf is present, ParseResponse runs with a nil
// issuer and skips that check — we still get the certificate status.
func parseOCSPStatus(raw []byte, peers []*x509.Certificate) scan.OCSPStatus {
	if len(raw) == 0 {
		return scan.OCSPStatusUnknown
	}
	var issuer *x509.Certificate
	if len(peers) >= 2 {
		issuer = peers[1]
	}
	resp, err := ocsp.ParseResponse(raw, issuer)
	if err != nil {
		return scan.OCSPStatusParseError
	}
	switch resp.Status {
	case ocsp.Good:
		return scan.OCSPStatusGood
	case ocsp.Revoked:
		return scan.OCSPStatusRevoked
	case ocsp.Unknown:
		return scan.OCSPStatusUnknownRev
	default:
		return scan.OCSPStatusUnknownRev
	}
}
