package tls

import (
	"bytes"
	"crypto/x509"
	"errors"

	"github.com/JoshuaMart/websec0/internal/scan"
	"golang.org/x/crypto/ocsp"
)

// parseOCSPStatus decodes an OCSP response captured from the TLS handshake.
// The issuer (second certificate in the chain) is required for signature
// validation; when only the leaf is present, ParseResponse runs with a nil
// issuer and skips that check — we still get the certificate status.
//
// A non-successful response (tryLater, internalError, …) carries no
// certificate status and is reported as responder_error, not parse_error:
// Apache, for example, staples a synthesized tryLater when its responder is
// unreachable.
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
		var respErr ocsp.ResponseError
		if errors.As(err, &respErr) {
			return scan.OCSPStatusResponderError
		}
		resp = parseIssuerEmbeddedResponse(raw, issuer)
		if resp == nil {
			return scan.OCSPStatusParseError
		}
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

// parseIssuerEmbeddedResponse accepts a response signed directly by the
// issuing CA that also embeds the issuer's own certificate. ParseResponse
// rejects it because it checks the embedded certificate's signature against
// the issuer, and a CA certificate is not signed by itself. The response is
// accepted only when the embedded certificate is byte-identical to the served
// issuer and the response signature verifies against that issuer.
func parseIssuerEmbeddedResponse(raw []byte, issuer *x509.Certificate) *ocsp.Response {
	if issuer == nil {
		return nil
	}
	// With a nil issuer, ParseResponse still verifies the response signature
	// against the embedded certificate; the checks below bind it to the issuer.
	resp, err := ocsp.ParseResponse(raw, nil)
	if err != nil || resp.Certificate == nil || !bytes.Equal(resp.Certificate.Raw, issuer.Raw) {
		return nil
	}
	if resp.CheckSignatureFrom(issuer) != nil {
		return nil
	}
	return resp
}
