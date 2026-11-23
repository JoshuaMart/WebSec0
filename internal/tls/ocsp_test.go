package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/scan"
	"golang.org/x/crypto/ocsp"
)

func TestParseOCSPStatus_EmptyResponse(t *testing.T) {
	if got := parseOCSPStatus(nil, nil); got != scan.OCSPStatusUnknown {
		t.Errorf("nil: got %q, want unknown", got)
	}
}

func TestParseOCSPStatus_GarbageReturnsParseError(t *testing.T) {
	garbage := []byte{0xde, 0xad, 0xbe, 0xef}
	if got := parseOCSPStatus(garbage, nil); got != scan.OCSPStatusParseError {
		t.Errorf("garbage: got %q, want parse_error", got)
	}
}

// ocspPKI is a throwaway root, the intermediate CA it certified, a leaf the
// intermediate issued, and their keys. The issuer must be an intermediate:
// a self-signed issuer verifies its own embedded copy and hides the bug.
type ocspPKI struct {
	ca, leaf *x509.Certificate
	caKey    *ecdsa.PrivateKey
	leafKey  *ecdsa.PrivateKey
}

func newECKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createCert(t testing.TB, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func caTemplate(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
}

func newOCSPPKI(t testing.TB, ocspURLs ...string) ocspPKI {
	t.Helper()
	rootKey, caKey, leafKey := newECKey(t), newECKey(t), newECKey(t)
	root := createCert(t, caTemplate("WebSec0 Test Root", 1), caTemplate("WebSec0 Test Root", 1), &rootKey.PublicKey, rootKey)
	ca := createCert(t, caTemplate("WebSec0 Test CA", 2), root, &caKey.PublicKey, rootKey)
	leaf := createCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "example.test"},
		DNSNames:    []string{"example.test", "127.0.0.1"},
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:  ocspURLs,
	}, ca, &leafKey.PublicKey, caKey)
	return ocspPKI{ca: ca, leaf: leaf, caKey: caKey, leafKey: leafKey}
}

// response builds an OCSP response for p.leaf. embedded is the certificate
// placed in the response's certs field (nil for none); responder names the
// ResponderID; signer signs the response.
func (p ocspPKI) response(t testing.TB, status int, embedded, responder *x509.Certificate, signer crypto.Signer) []byte {
	t.Helper()
	template := ocsp.Response{
		Status:       status,
		SerialNumber: p.leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  embedded,
	}
	if status == ocsp.Revoked {
		template.RevokedAt = time.Now().Add(-2 * time.Hour)
	}
	raw, err := ocsp.CreateResponse(p.ca, responder, template, signer)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseOCSPStatus_Signatures(t *testing.T) {
	p := newOCSPPKI(t, "http://ocsp.example.test")
	chain := []*x509.Certificate{p.leaf, p.ca}

	// Delegated responder certified by the CA.
	delegateKey := newECKey(t)
	delegateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "WebSec0 Test OCSP"},
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	delegate := createCert(t, delegateTemplate, p.ca, &delegateKey.PublicKey, p.caKey)

	// A rogue CA whose self-signed certificate is embedded in its own response.
	rogueKey := newECKey(t)
	rogue := createCert(t, caTemplate("Rogue CA", 9), caTemplate("Rogue CA", 9), &rogueKey.PublicKey, rogueKey)

	// A copy of the CA certificate with the same subject but another key.
	impostorKey := newECKey(t)
	impostor := createCert(t, caTemplate("WebSec0 Test CA", 2), caTemplate("WebSec0 Test CA", 2), &impostorKey.PublicKey, impostorKey)

	tampered := p.response(t, ocsp.Good, p.ca, p.ca, p.caKey)
	parsed, err := ocsp.ParseResponse(tampered, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(tampered, parsed.Signature)
	if at < 0 {
		t.Fatal("signature not found in response")
	}
	tampered[at+len(parsed.Signature)-1] ^= 0xff

	for _, tc := range []struct {
		name  string
		raw   []byte
		peers []*x509.Certificate
		want  scan.OCSPStatus
	}{
		{"issuer signed, no certs", p.response(t, ocsp.Good, nil, p.ca, p.caKey), chain, scan.OCSPStatusGood},
		{"issuer signed, issuer embedded", p.response(t, ocsp.Good, p.ca, p.ca, p.caKey), chain, scan.OCSPStatusGood},
		{"issuer signed, issuer embedded, revoked", p.response(t, ocsp.Revoked, p.ca, p.ca, p.caKey), chain, scan.OCSPStatusRevoked},
		{"issuer signed, issuer embedded, unknown", p.response(t, ocsp.Unknown, p.ca, p.ca, p.caKey), chain, scan.OCSPStatusUnknownRev},
		{"delegated responder embedded", p.response(t, ocsp.Good, delegate, delegate, delegateKey), chain, scan.OCSPStatusGood},
		{"issuer embedded, wrong signing key", p.response(t, ocsp.Good, p.ca, p.ca, rogueKey), chain, scan.OCSPStatusParseError},
		{"issuer embedded, tampered signature", tampered, chain, scan.OCSPStatusParseError},
		{"no certs, wrong signing key", p.response(t, ocsp.Good, nil, p.ca, rogueKey), chain, scan.OCSPStatusParseError},
		{"rogue CA embedded and signing", p.response(t, ocsp.Good, rogue, rogue, rogueKey), chain, scan.OCSPStatusParseError},
		{"same-subject impostor embedded and signing", p.response(t, ocsp.Good, impostor, impostor, impostorKey), chain, scan.OCSPStatusParseError},
		{"leaf only, issuer embedded", p.response(t, ocsp.Good, p.ca, p.ca, p.caKey), chain[:1], scan.OCSPStatusGood},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOCSPStatus(tc.raw, tc.peers); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseOCSPStatus_NonSuccessfulResponse(t *testing.T) {
	p := newOCSPPKI(t, "http://ocsp.example.test")
	for name, raw := range map[string][]byte{
		"tryLater":      ocsp.TryLaterErrorResponse,
		"internalError": ocsp.InternalErrorErrorResponse,
		"malformed":     ocsp.MalformedRequestErrorResponse,
		"unauthorized":  ocsp.UnauthorizedErrorResponse,
	} {
		if got := parseOCSPStatus(raw, []*x509.Certificate{p.leaf, p.ca}); got != scan.OCSPStatusResponderError {
			t.Errorf("%s: got %q, want responder_error", name, got)
		}
	}
}
