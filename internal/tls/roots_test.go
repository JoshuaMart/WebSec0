package tls

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"go/version"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// Root selection is process-global and cached by crypto/x509.
func TestValidateChainRoots(t *testing.T) {
	const modeEnv = "WEBSEC0_TEST_ROOT_MODE"
	if mode := os.Getenv(modeEnv); mode != "" {
		testRootSelection(t, mode)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"forced_fallback", "missing_system", "empty_system", "system_priority"} {
		t.Run(mode, func(t *testing.T) {
			if mode != "forced_fallback" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") && version.Compare(runtime.Version(), "go1.27") < 0 {
				t.Skip("system root file overrides require Go 1.27 on this OS; covered by Linux CI")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestValidateChainRoots$", "-test.v")
			force := "0"
			if mode == "forced_fallback" {
				force = "1"
			}
			cmd.Env = append(os.Environ(), modeEnv+"="+mode,
				"GODEBUG="+os.Getenv("GODEBUG")+",x509sslcertoverrideplatform=1,x509usefallbackroots="+force)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("root selection subprocess: %v\n%s", err, out)
			}
		})
	}
}

func testRootSelection(t *testing.T, mode string) {
	t.Helper()
	fallbackRoot, fallbackKey := rootTestCertificate(t, nil, nil, "Fallback CA", true, false)
	systemRoot, systemKey := rootTestCertificate(t, nil, nil, "System CA", true, false)
	intermediate, intermediateKey := rootTestCertificate(t, fallbackRoot, fallbackKey, "Intermediate CA", true, false)
	leaf, _ := rootTestCertificate(t, intermediate, intermediateKey, "service.example.test", false, false)
	expired, _ := rootTestCertificate(t, intermediate, intermediateKey, "service.example.test", false, true)
	systemLeaf, _ := rootTestCertificate(t, systemRoot, systemKey, "service.example.test", false, false)
	selfSigned, _ := rootTestCertificate(t, nil, nil, "service.example.test", false, false)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "roots.pem")
	certDir := filepath.Join(dir, "certs")
	if err := os.Mkdir(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if mode != "missing_system" {
		var contents []byte
		if mode != "empty_system" {
			contents = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: systemRoot.Raw})
		}
		if err := os.WriteFile(certFile, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SSL_CERT_FILE", certFile)
	t.Setenv("SSL_CERT_DIR", certDir)
	pool := x509.NewCertPool()
	pool.AddCert(fallbackRoot)
	x509.SetFallbackRoots(pool)

	fallbackTrust, systemTrust := scan.ChainTrustTrusted, scan.ChainTrustUntrusted
	if mode == "system_priority" {
		fallbackTrust, systemTrust = systemTrust, fallbackTrust
	}
	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
		host  string
		want  scan.ChainTrust
	}{
		{"fallback_chain", []*x509.Certificate{leaf, intermediate}, "service.example.test", fallbackTrust},
		{"system_chain", []*x509.Certificate{systemLeaf}, "service.example.test", systemTrust},
		{"missing_intermediate", []*x509.Certificate{leaf}, "service.example.test", scan.ChainTrustUntrusted},
		{"empty_chain", nil, "service.example.test", scan.ChainTrustNoChain},
		{"self_signed", []*x509.Certificate{selfSigned}, "service.example.test", scan.ChainTrustSelfSigned},
		{"expired", []*x509.Certificate{expired, intermediate}, "service.example.test", scan.ChainTrustExpired},
		{"wrong_hostname", []*x509.Certificate{leaf, intermediate}, "other.example.test", scan.ChainTrustHostnameMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateChain(tc.chain, tc.host); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func rootTestCertificate(t *testing.T, parent *x509.Certificate, signer ed25519.PrivateKey, name string, ca, expired bool) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:      ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.DNSNames = []string{name}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if expired {
		template.NotAfter = template.NotBefore.Add(time.Hour)
	}
	if parent == nil {
		parent, signer = template, private
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, private
}
