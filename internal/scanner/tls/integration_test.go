package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
	scannertls "github.com/JoshuaMart/websec0/internal/scanner/tls"
)

// certKind picks the leaf certificate generated for the test server.
type certKind int

const (
	kindRSA2048    certKind = iota
	kindRSA1024             // weak
	kindECDSAP256
	kindSelfSigned          // RSA leaf where Issuer == Subject
	kindSCTEmbedded         // RSA leaf with CT SCT-list X.509 extension
)

type fixture struct {
	leaf       *x509.Certificate
	leafBytes  []byte
	leafKey    any
	tlsCert    stdtls.Certificate
	hstsHeader string
	notAfter   time.Time
}

func makeFixture(t *testing.T, kind certKind, hostname string, hstsHeader string, notAfter time.Time) *fixture {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{hostname},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if kind == kindSCTEmbedded {
		// Embed a fake CT SCT-list extension (OID 1.3.6.1.4.1.11129.2.4.2).
		oidSCT := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
		fakeSCTValue, _ := asn1.Marshal([]byte("fake_sct"))
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSCT, Value: fakeSCTValue}}
	}

	var (
		priv      any
		pub       any
		certBytes []byte
		err       error
	)
	switch kind {
	case kindRSA2048, kindSelfSigned, kindSCTEmbedded:
		k, perr := rsa.GenerateKey(rand.Reader, 2048)
		if perr != nil {
			t.Fatalf("rsa: %v", perr)
		}
		priv, pub = k, &k.PublicKey
	case kindRSA1024:
		k, perr := rsa.GenerateKey(rand.Reader, 1024) //#nosec G403 -- intentional for test
		if perr != nil {
			t.Fatalf("rsa1024: %v", perr)
		}
		priv, pub = k, &k.PublicKey
	case kindECDSAP256:
		k, perr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if perr != nil {
			t.Fatalf("ecdsa: %v", perr)
		}
		priv, pub = k, &k.PublicKey
	}

	certBytes, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	tlsCert := stdtls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
	}
	return &fixture{
		leaf:       leaf,
		leafBytes:  certBytes,
		leafKey:    priv,
		tlsCert:    tlsCert,
		hstsHeader: hstsHeader,
		notAfter:   notAfter,
	}
}

func startServer(t *testing.T, f *fixture) (*httptest.Server, *checks.Target) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f.hstsHeader != "" {
			w.Header().Set("Strict-Transport-Security", f.hstsHeader)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &stdtls.Config{
		Certificates: []stdtls.Certificate{f.tlsCert},
		MinVersion:   stdtls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "https://")
	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	// Custom client that trusts the per-test fixture and doesn't follow
	// redirects, so HSTS reads see the original response.
	tgt.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &stdtls.Config{InsecureSkipVerify: true}, //#nosec G402 -- test
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return srv, tgt
}

func runReg(t *testing.T, id string, tgt *checks.Target) *checks.Finding {
	t.Helper()
	r := checks.NewRegistry()
	scannertls.Register(r)
	c, ok := r.Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f, err := c.Run(ctx, tgt)
	if err != nil {
		t.Fatalf("%s: Run err = %v", id, err)
	}
	if f == nil {
		t.Fatalf("%s: nil finding", id)
	}
	return f
}

func TestRegisterAddsAllPhase6Checks(t *testing.T) {
	t.Parallel()
	r := checks.NewRegistry()
	scannertls.Register(r)
	for _, id := range []string{
		// Phase 6.1 — modern TLS
		scannertls.IDProtocolTLS12Missing,
		scannertls.IDProtocolTLS13Missing,
		scannertls.IDCipherNoForwardSecrecy,
		scannertls.IDALPNNoHTTP2,
		scannertls.IDOCSPStaplingMissing,
		// Phase 6.2 — certificates
		scannertls.IDCertExpired,
		scannertls.IDCertExpiresSoon14d,
		scannertls.IDCertExpiresSoon30d,
		scannertls.IDCertChainIncomplete,
		scannertls.IDCertNameMismatch,
		scannertls.IDCertSelfSigned,
		scannertls.IDCertWeakRSA,
		scannertls.IDCertWeakECC,
		scannertls.IDCertWeakSignature,
		// Phase 6.3 — legacy protocols
		scannertls.IDProtocolLegacyTLS10,
		scannertls.IDProtocolLegacyTLS11,
		// Phase 6.3 — weak ciphers
		scannertls.IDCipherNull,
		scannertls.IDCipherExport,
		scannertls.IDCipherRC4,
		scannertls.IDCipherDES,
		scannertls.IDCipherTripleDES,
		scannertls.IDCipherCBCTLS10,
		scannertls.IDCipherDHWeak,
		// Phase 6.4 — SSLv2/SSLv3
		scannertls.IDProtocolLegacySSL2,
		scannertls.IDProtocolLegacySSL3,
		// Phase 6.5 — Heartbleed stub
		scannertls.IDVulnHeartbleed,
		// Phase 6.6 — HSTS + redirect
		scannertls.IDHSTSMissing,
		scannertls.IDHSTSMaxAgeLow,
		scannertls.IDHSTSNoIncludeSubDomains,
		scannertls.IDHSTSNoPreload,
		scannertls.IDRedirectHTTPToHTTPS,
	} {
		if _, ok := r.Get(id); !ok {
			t.Errorf("missing %s", id)
		}
	}
}

func TestModernHandshakeReachable(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindRSA2048, "127.0.0.1", "max-age=31536000; includeSubDomains", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)

	if g := runReg(t, scannertls.IDProtocolTLS12Missing, tgt); g.Status != checks.StatusPass {
		t.Errorf("TLS 1.2 = %s, want pass", g.Status)
	}
	if g := runReg(t, scannertls.IDProtocolTLS13Missing, tgt); g.Status != checks.StatusPass {
		t.Errorf("TLS 1.3 = %s, want pass", g.Status)
	}
	if g := runReg(t, scannertls.IDCipherNoForwardSecrecy, tgt); g.Status != checks.StatusPass {
		t.Errorf("FS = %s, want pass", g.Status)
	}
	if g := runReg(t, scannertls.IDALPNNoHTTP2, tgt); g.Status != checks.StatusPass {
		t.Errorf("ALPN h2 = %s, want pass", g.Status)
	}
	// OCSP stapling: the test server doesn't staple → expect fail.
	if g := runReg(t, scannertls.IDOCSPStaplingMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("OCSP = %s, want fail", g.Status)
	}
}

func TestCertExpired(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindRSA2048, "127.0.0.1", "", time.Now().Add(-24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertExpired, tgt); g.Status != checks.StatusFail {
		t.Errorf("EXPIRED = %s, want fail", g.Status)
	}
}

func TestCertExpiresSoon(t *testing.T) {
	t.Parallel()
	// 7 days remaining → fails the 14d check, fails the 30d check
	f := makeFixture(t, kindRSA2048, "127.0.0.1", "", time.Now().Add(7*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertExpiresSoon14d, tgt); g.Status != checks.StatusFail {
		t.Errorf("14d = %s, want fail", g.Status)
	}
	if g := runReg(t, scannertls.IDCertExpiresSoon30d, tgt); g.Status != checks.StatusFail {
		t.Errorf("30d = %s, want fail", g.Status)
	}
}

func TestCertNameMismatch(t *testing.T) {
	t.Parallel()
	// Cert SAN claims wronghost.example, but Target.Hostname is 127.0.0.1.
	f := makeFixture(t, kindRSA2048, "wronghost.example", "", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertNameMismatch, tgt); g.Status != checks.StatusFail {
		t.Errorf("NAME-MISMATCH = %s, want fail", g.Status)
	}
}

func TestSelfSignedDetection(t *testing.T) {
	t.Parallel()
	// Issuer == Subject in our makeFixture template (we use tmpl as both
	// parent and template), so every cert is technically self-signed
	// w.r.t. that comparison. The check fires fail.
	f := makeFixture(t, kindSelfSigned, "127.0.0.1", "", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertSelfSigned, tgt); g.Status != checks.StatusFail {
		t.Errorf("SELF-SIGNED = %s, want fail", g.Status)
	}
}

func TestWeakRSAKey(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindRSA1024, "127.0.0.1", "", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertWeakRSA, tgt); g.Status != checks.StatusFail {
		t.Errorf("WEAK-RSA = %s, want fail", g.Status)
	}
}

func TestECDSAKeyPasses(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindECDSAP256, "127.0.0.1", "", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertWeakECC, tgt); g.Status != checks.StatusPass {
		t.Errorf("WEAK-ECC = %s, want pass", g.Status)
	}
	// RSA check should skip on a non-RSA key.
	if g := runReg(t, scannertls.IDCertWeakRSA, tgt); g.Status != checks.StatusSkipped {
		t.Errorf("WEAK-RSA on ECDSA leaf = %s, want skipped", g.Status)
	}
}

func TestHSTSPresent(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindRSA2048, "127.0.0.1", "max-age=31536000; includeSubDomains", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDHSTSMissing, tgt); g.Status != checks.StatusPass {
		t.Errorf("HSTS-MISSING = %s, want pass", g.Status)
	}
	if g := runReg(t, scannertls.IDHSTSMaxAgeLow, tgt); g.Status != checks.StatusPass {
		t.Errorf("HSTS-MAX-AGE-LOW = %s, want pass", g.Status)
	}
	if g := runReg(t, scannertls.IDHSTSNoIncludeSubDomains, tgt); g.Status != checks.StatusPass {
		t.Errorf("HSTS-NO-INCLUDESUB = %s, want pass", g.Status)
	}
}

func TestHSTSMissingHeader(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindRSA2048, "127.0.0.1", "", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDHSTSMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("HSTS-MISSING = %s, want fail", g.Status)
	}
}

func TestHSTSShortMaxAge(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindRSA2048, "127.0.0.1", "max-age=300", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDHSTSMaxAgeLow, tgt); g.Status != checks.StatusFail {
		t.Errorf("HSTS-MAX-AGE-LOW = %s, want fail", g.Status)
	}
	if g := runReg(t, scannertls.IDHSTSNoIncludeSubDomains, tgt); g.Status != checks.StatusFail {
		t.Errorf("HSTS-NO-INCLUDESUB = %s, want fail", g.Status)
	}
}

// TestCertNoCT_NoSCTs verifies that a certificate without any SCT delivery
// (no TLS extension, no X.509 extension) reports a fail.
func TestCertNoCT_NoSCTs(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindRSA2048, "127.0.0.1", "", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertNoCT, tgt); g.Status != checks.StatusFail {
		t.Errorf("CERT-NO-CT (no SCTs) = %s, want fail", g.Status)
	}
}

// TestCertNoCT_X509Extension verifies that a certificate with the CT SCT-list
// X.509 extension (OID 1.3.6.1.4.1.11129.2.4.2) reports a pass.
func TestCertNoCT_X509Extension(t *testing.T) {
	t.Parallel()
	f := makeFixture(t, kindSCTEmbedded, "127.0.0.1", "", time.Now().Add(90*24*time.Hour))
	_, tgt := startServer(t, f)
	if g := runReg(t, scannertls.IDCertNoCT, tgt); g.Status != checks.StatusPass {
		t.Errorf("CERT-NO-CT (X.509 extension) = %s, want pass", g.Status)
	}
}
