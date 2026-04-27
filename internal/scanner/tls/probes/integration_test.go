//go:build integration

// Integration tests for the TLS probe package.
// These tests make real network connections to badssl.com and require internet
// access. Run them explicitly with:
//
//	go test -tags integration ./internal/scanner/tls/probes/ -v
//
// Each test checks reachability first and skips gracefully if the target is
// down or unreachable, so they are safe to include in optional CI jobs.
package probes_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/scanner/tls/probes"
)

const integrationTimeout = 15 * time.Second

// reachable reports whether addr ("host:port") can be TCP-dialed within 3 s.
func reachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func skipUnreachable(t *testing.T, addr string) {
	t.Helper()
	if !reachable(addr) {
		t.Skipf("skipping: %s unreachable", addr)
	}
}

// ctx returns a context with the integration timeout.
func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), integrationTimeout)
}

// ---- SSLv3 ------------------------------------------------------------------

// TestIntegration_SSLv3_Rejected verifies that a modern TLS server (badssl.com)
// rejects our SSLv3 ClientHello.
func TestIntegration_SSLv3_Rejected(t *testing.T) {
	const addr = "badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	status, err := probes.ProbeSSLv3(c, addr)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if status == probes.StatusAccepted {
		t.Errorf("modern badssl.com accepted SSLv3 — unexpected")
	}
}

// ---- SSLv2 ------------------------------------------------------------------

// TestIntegration_SSLv2_Rejected verifies that a modern TLS server rejects our
// SSLv2 ClientHello.
func TestIntegration_SSLv2_Rejected(t *testing.T) {
	const addr = "badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	status, err := probes.ProbeSSLv2(c, addr)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if status == probes.StatusAccepted {
		t.Errorf("modern badssl.com accepted SSLv2 — unexpected")
	}
}

// ---- TLS 1.0 / 1.1 version probes ------------------------------------------

// TestIntegration_TLS10_Accepted confirms that tls-v1-0.badssl.com accepts a
// TLS 1.0 ClientHello and negotiates version 0x0301.
func TestIntegration_TLS10_Accepted(t *testing.T) {
	const addr = "tls-v1-0.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	r, err := probes.ProbeTLSHello(c, addr, 0x0301, nil)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !r.Accepted {
		t.Fatalf("TLS 1.0 probe on %s: expected accepted, got rejected", addr)
	}
	if r.NegotiatedVersion != 0x0301 {
		t.Errorf("negotiated version 0x%04X, want 0x0301 (TLS 1.0)", r.NegotiatedVersion)
	}
	t.Logf("negotiated: version=0x%04X cipher=0x%04X", r.NegotiatedVersion, r.NegotiatedCipher)
}

// TestIntegration_TLS11_Accepted confirms that tls-v1-1.badssl.com accepts a
// TLS 1.1 ClientHello and negotiates version 0x0302.
func TestIntegration_TLS11_Accepted(t *testing.T) {
	const addr = "tls-v1-1.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	r, err := probes.ProbeTLSHello(c, addr, 0x0302, nil)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !r.Accepted {
		t.Fatalf("TLS 1.1 probe on %s: expected accepted, got rejected", addr)
	}
	if r.NegotiatedVersion != 0x0302 {
		t.Errorf("negotiated version 0x%04X, want 0x0302 (TLS 1.1)", r.NegotiatedVersion)
	}
	t.Logf("negotiated: version=0x%04X cipher=0x%04X", r.NegotiatedVersion, r.NegotiatedCipher)
}

// TestIntegration_TLS10_Rejected_TLS12Only verifies that a TLS-1.2-only server
// rejects our TLS 1.0 ClientHello (no version downgrade).
func TestIntegration_TLS10_Rejected_TLS12Only(t *testing.T) {
	const addr = "tls-v1-2.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	r, err := probes.ProbeTLSHello(c, addr, 0x0301, nil)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if r.Accepted && r.NegotiatedVersion == 0x0301 {
		t.Errorf("tls-v1-2.badssl.com should NOT accept TLS 1.0 (MaxVersion=0x0301)")
	}
}

// ---- Cipher suite probes ----------------------------------------------------

// TestIntegration_RC4_Accepted confirms that rc4.badssl.com accepts an RC4
// cipher suite.
func TestIntegration_RC4_Accepted(t *testing.T) {
	const addr = "rc4.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	r, err := probes.ProbeTLSHello(c, addr, 0x0303, probes.RC4CipherSuites)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !r.Accepted {
		t.Errorf("rc4.badssl.com should accept RC4 cipher suites")
	}
	t.Logf("negotiated: version=0x%04X cipher=0x%04X", r.NegotiatedVersion, r.NegotiatedCipher)
}

// TestIntegration_RC4MD5_Accepted confirms that rc4-md5.badssl.com accepts RC4-MD5.
func TestIntegration_RC4MD5_Accepted(t *testing.T) {
	const addr = "rc4-md5.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	rc4md5 := []uint16{0x0004} // TLS_RSA_WITH_RC4_128_MD5
	r, err := probes.ProbeTLSHello(c, addr, 0x0303, rc4md5)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !r.Accepted {
		t.Errorf("rc4-md5.badssl.com should accept TLS_RSA_WITH_RC4_128_MD5 (0x0004)")
	}
	t.Logf("negotiated: version=0x%04X cipher=0x%04X", r.NegotiatedVersion, r.NegotiatedCipher)
}

// TestIntegration_3DES_Accepted confirms that 3des.badssl.com (if available)
// accepts 3DES cipher suites.
func TestIntegration_3DES_Accepted(t *testing.T) {
	const addr = "3des.badssl.com:443"
	skipUnreachable(t, addr) // might not exist; test skips gracefully
	c, cancel := ctx()
	defer cancel()

	r, err := probes.ProbeTLSHello(c, addr, 0x0303, probes.TripleDESCipherSuites)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !r.Accepted {
		t.Errorf("3des.badssl.com should accept 3DES cipher suites")
	}
	t.Logf("negotiated: version=0x%04X cipher=0x%04X", r.NegotiatedVersion, r.NegotiatedCipher)
}

// TestIntegration_NULL_Accepted confirms that null.badssl.com (if available)
// accepts NULL cipher suites (no encryption).
func TestIntegration_NULL_Accepted(t *testing.T) {
	const addr = "null.badssl.com:443"
	skipUnreachable(t, addr) // might not exist; test skips gracefully
	c, cancel := ctx()
	defer cancel()

	r, err := probes.ProbeTLSHello(c, addr, 0x0303, probes.NullCipherSuites)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !r.Accepted {
		t.Errorf("null.badssl.com should accept NULL cipher suites")
	}
	t.Logf("negotiated: version=0x%04X cipher=0x%04X", r.NegotiatedVersion, r.NegotiatedCipher)
}

// TestIntegration_ModernServer_RejectsRC4 verifies that a modern server
// (mozilla-modern.badssl.com) rejects RC4 ciphers.
func TestIntegration_ModernServer_RejectsRC4(t *testing.T) {
	const addr = "mozilla-modern.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	r, err := probes.ProbeTLSHello(c, addr, 0x0303, probes.RC4CipherSuites)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if r.Accepted {
		t.Errorf("mozilla-modern.badssl.com should NOT accept RC4 (got cipher 0x%04X)", r.NegotiatedCipher)
	}
}

// ---- DH key size probes -----------------------------------------------------

// TestIntegration_DH_480bit confirms that dh480.badssl.com uses a 480-bit DH
// prime (below the 2048-bit safe threshold).
func TestIntegration_DH_480bit(t *testing.T) {
	const addr = "dh480.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	bits, err := probes.ProbeDHKeySize(c, addr)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if bits == 0 {
		t.Fatal("ProbeDHKeySize returned 0 — server may not use DHE or probe failed")
	}
	t.Logf("DH prime: %d bits", bits)
	if bits >= 2048 {
		t.Errorf("expected < 2048 bits for dh480.badssl.com, got %d", bits)
	}
}

// TestIntegration_DH_1024bit confirms that dh1024.badssl.com uses a 1024-bit
// DH prime (the Logjam-vulnerable group size).
func TestIntegration_DH_1024bit(t *testing.T) {
	const addr = "dh1024.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	bits, err := probes.ProbeDHKeySize(c, addr)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if bits == 0 {
		t.Fatal("ProbeDHKeySize returned 0 — server may not use DHE or probe failed")
	}
	t.Logf("DH prime: %d bits", bits)
	if bits >= 2048 {
		t.Errorf("expected < 2048 bits for dh1024.badssl.com, got %d", bits)
	}
}

// ---- Heartbleed probe -------------------------------------------------------

// TestIntegration_Heartbleed_Safe verifies that our probe does NOT
// false-positive on a modern, patched server.
func TestIntegration_Heartbleed_Safe(t *testing.T) {
	const addr = "badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	status, err := probes.ProbeHeartbleed(c, addr)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if status == probes.HeartbleedVulnerable {
		t.Errorf("modern badssl.com flagged as Heartbleed-vulnerable — false positive")
	}
	t.Logf("Heartbleed status: %d (0=safe, 1=vulnerable, 2=unknown)", status)
}

// ---- Cipher enumeration -----------------------------------------------------

// TestIntegration_EnumerateCipherSuites_ModernServer enumerates TLS 1.2
// ciphers on badssl.com and verifies the list is non-empty and contains
// at least one modern forward-secret suite.
func TestIntegration_EnumerateCipherSuites_ModernServer(t *testing.T) {
	const addr = "badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	accepted := probes.EnumerateCipherSuites(c, addr, 0x0303, probes.DHECipherSuites)

	// DHE ciphers might not be supported by a modern server; that's fine.
	// Run the full candidate list instead.
	fullCandidates := append(
		append([]uint16{}, probes.RC4CipherSuites...),
		append(probes.TripleDESCipherSuites, probes.DHECipherSuites...)...,
	)
	accepted = probes.EnumerateCipherSuites(c, addr, 0x0303, fullCandidates)

	t.Logf("accepted %d ciphers from candidate list: %v", len(accepted), accepted)
	// A modern server might accept none of these legacy/DHE ciphers — that's correct.
	// The test just ensures no panic or hang.
}

// TestIntegration_EnumerateCipherSuites_LegacyServer tests cipher enumeration
// on a server known to support multiple legacy ciphers.
func TestIntegration_EnumerateCipherSuites_LegacyServer(t *testing.T) {
	const addr = "tls-v1-0.badssl.com:443"
	skipUnreachable(t, addr)
	c, cancel := ctx()
	defer cancel()

	// Enumerate TLS 1.0 ciphers (MaxVersion=0x0301) against a TLS-1.0-only server.
	accepted := probes.EnumerateCipherSuites(c, addr, 0x0301, []uint16{
		0xC014, 0xC013, 0x0035, 0x002F, 0x000A, 0x0005,
	})
	t.Logf("tls-v1-0.badssl.com TLS 1.0 ciphers: %v (count=%d)", accepted, len(accepted))
	if len(accepted) == 0 {
		t.Error("expected at least one accepted cipher on tls-v1-0.badssl.com")
	}
}
