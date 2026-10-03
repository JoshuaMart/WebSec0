package main

import (
	"context"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

func TestEmbeddedRootsRegistered(t *testing.T) {
	const childEnv = "WEBSEC0_TEST_EMBEDDED_ROOTS"
	if os.Getenv(childEnv) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"forced", "missing_system"} {
			t.Run(mode, func(t *testing.T) {
				if mode == "missing_system" && runtime.GOOS != "linux" {
					t.Skip("automatic fallback without OS roots is covered by Linux CI")
				}
				force := "0"
				if mode == "forced" {
					force = "1"
				}
				dir := t.TempDir()
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestEmbeddedRootsRegistered$", "-test.v")
				cmd.Env = append(os.Environ(), childEnv+"=1",
					"GODEBUG="+os.Getenv("GODEBUG")+",x509sslcertoverrideplatform=1,x509usefallbackroots="+force,
					"SSL_CERT_FILE="+filepath.Join(dir, "missing.pem"), "SSL_CERT_DIR="+dir)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("embedded roots subprocess: %v\n%s", err, out)
				}
			})
		}
		return
	}

	// Build the expected pool without importing fallback in this test:
	// registration must come from the production entry point.
	expected := x509.NewCertPool()
	var sample *x509.Certificate
	for root := range bundle.Roots() {
		cert, err := x509.ParseCertificate(root.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if root.Constraint != nil {
			expected.AddCertWithConstraint(cert, root.Constraint)
		} else {
			expected.AddCert(cert)
			if cert.Subject.CommonName == "ISRG Root X1" {
				sample = cert
			}
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil || !roots.Equal(expected) {
		t.Fatalf("binary did not register the embedded root bundle: %v", err)
	}
	if sample == nil {
		t.Fatal("expected reference root missing from bundle; review bundle update")
	}
	if _, err := sample.Verify(x509.VerifyOptions{
		CurrentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("embedded reference root is not trusted: %v", err)
	}
}
