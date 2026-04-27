//go:build integration

// Integration tests for the full TLS check family (Phase 6.7).
//
// These tests make real network connections and require internet access.
// Run them with:
//
//	go test -tags integration ./internal/scanner/tls/ -v -run TestFamily
//	go test -tags integration ./internal/scanner/tls/ -v -run TestMilestone2
//
// Each test skips gracefully when the target host is unreachable.
package tls_test

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
	scannertls "github.com/JoshuaMart/websec0/internal/scanner/tls"
)

const familyTimeout = 30 * time.Second

// integrationSkip skips the test if addr ("host:port") is not reachable.
func integrationSkip(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Skipf("skipping: %s unreachable", addr)
	}
	_ = conn.Close()
}

// integrationTarget builds a checks.Target for integration tests.
// Set insecure=true for servers with broken certs (expired, self-signed, etc.)
// so that the HTTP client used by HSTS/redirect probes doesn't abort early.
func integrationTarget(t *testing.T, host string, insecure bool) *checks.Target {
	t.Helper()
	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget(%q): %v", host, err)
	}
	tgt.HTTPClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &stdtls.Config{InsecureSkipVerify: insecure}, //#nosec G402 -- integration test only
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return tgt
}

// integrationRun executes one TLS check against tgt with the family timeout.
func integrationRun(t *testing.T, id string, tgt *checks.Target) *checks.Finding {
	t.Helper()
	r := checks.NewRegistry()
	scannertls.Register(r)
	c, ok := r.Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), familyTimeout)
	defer cancel()
	f, err := c.Run(ctx, tgt)
	if err != nil {
		t.Fatalf("%s.Run: %v", id, err)
	}
	t.Logf("%-40s  status=%-8s  %s", id, f.Status, f.Title)
	return f
}

func wantFail(t *testing.T, f *checks.Finding, label string) {
	t.Helper()
	if f.Status != checks.StatusFail {
		t.Errorf("%s: got %s, want fail", label, f.Status)
	}
}

func wantPass(t *testing.T, f *checks.Finding, label string) {
	t.Helper()
	if f.Status != checks.StatusPass {
		t.Errorf("%s: got %s, want pass", label, f.Status)
	}
}

// wantPassOrSkip accepts pass (clean) or skipped (condition not met on this host).
func wantPassOrSkip(t *testing.T, f *checks.Finding, label string) {
	t.Helper()
	if f.Status == checks.StatusFail {
		t.Errorf("%s: got fail, want pass or skipped", label)
	}
}

// ── Certificate checks ────────────────────────────────────────────────────────

func TestFamily_CertExpired(t *testing.T) {
	const host = "expired.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDCertExpired, tgt), host)
}

func TestFamily_CertSelfSigned(t *testing.T) {
	const host = "self-signed.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDCertSelfSigned, tgt), host)
}

func TestFamily_CertNameMismatch(t *testing.T) {
	const host = "wrong.host.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDCertNameMismatch, tgt), host)
}

func TestFamily_CertChainIncomplete(t *testing.T) {
	const host = "incomplete-chain.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDCertChainIncomplete, tgt), host)
}

// TestFamily_CertWeakSig checks that a SHA-1-signed intermediate triggers the
// weak-signature check (badssl.com provides sha1-intermediate for this).
func TestFamily_CertWeakSig(t *testing.T) {
	const host = "sha1-intermediate.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	f := integrationRun(t, scannertls.IDCertWeakSignature, tgt)
	if f.Status == checks.StatusPass {
		t.Errorf("%s: weak-signature check passed — expected fail or skipped", host)
	}
}

// ── Legacy protocol checks ────────────────────────────────────────────────────

func TestFamily_LegacyTLS10_Accepted(t *testing.T) {
	const host = "tls-v1-0.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDProtocolLegacyTLS10, tgt), host)
}

func TestFamily_LegacyTLS11_Accepted(t *testing.T) {
	const host = "tls-v1-1.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDProtocolLegacyTLS11, tgt), host)
}

// TestFamily_ModernServer_NoLegacyTLS10 verifies a TLS-1.2-only server
// correctly passes the legacy TLS 1.0 check (not vulnerable).
func TestFamily_ModernServer_NoLegacyTLS10(t *testing.T) {
	const host = "tls-v1-2.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, false)
	wantPassOrSkip(t, integrationRun(t, scannertls.IDProtocolLegacyTLS10, tgt), host)
}

// ── Cipher checks ─────────────────────────────────────────────────────────────

func TestFamily_CipherRC4(t *testing.T) {
	const host = "rc4.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDCipherRC4, tgt), host)
}

func TestFamily_CipherDHWeak(t *testing.T) {
	const host = "dh1024.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, true)
	wantFail(t, integrationRun(t, scannertls.IDCipherDHWeak, tgt), host)
}

// ── HSTS / redirect ───────────────────────────────────────────────────────────

func TestFamily_HSTS_Present(t *testing.T) {
	const host = "hsts.badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, false)
	wantPass(t, integrationRun(t, scannertls.IDHSTSMissing, tgt), host)
}

func TestFamily_HTTPRedirect(t *testing.T) {
	const host = "badssl.com"
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, false)
	wantPass(t, integrationRun(t, scannertls.IDRedirectHTTPToHTTPS, tgt), host)
}

// ── A+ reference servers ──────────────────────────────────────────────────────

// testAPlusServer runs the core TLS checks against host and asserts that no
// check returns fail (a result of pass or skipped is acceptable).
func testAPlusServer(t *testing.T, host string) {
	t.Helper()
	integrationSkip(t, host+":443")
	tgt := integrationTarget(t, host, false)

	criticalIDs := []string{
		scannertls.IDProtocolTLS12Missing,
		scannertls.IDCipherNoForwardSecrecy,
		scannertls.IDCertExpired,
		scannertls.IDCertChainIncomplete,
		scannertls.IDCertNameMismatch,
		scannertls.IDCertSelfSigned,
		scannertls.IDHSTSMissing,
		scannertls.IDRedirectHTTPToHTTPS,
		scannertls.IDProtocolLegacyTLS10,
		scannertls.IDProtocolLegacyTLS11,
		scannertls.IDProtocolLegacySSL3,
		scannertls.IDCipherRC4,
		scannertls.IDCipherNull,
		scannertls.IDCipherExport,
	}

	for _, id := range criticalIDs {
		f := integrationRun(t, id, tgt)
		if f.Status == checks.StatusFail {
			t.Errorf("A+ server %s FAILED %s: %s", host, id, f.Title)
		}
	}
}

func TestFamily_APlus_Cloudflare(t *testing.T) { testAPlusServer(t, "cloudflare.com") }
func TestFamily_APlus_GitHub(t *testing.T)     { testAPlusServer(t, "github.com") }
func TestFamily_APlus_Mozilla(t *testing.T)    { testAPlusServer(t, "mozilla.org") }

// ── Milestone 2 : famille TLS complète ───────────────────────────────────────

// TestMilestone2_TLSFamilyComplete runs the full TLS check suite against a
// representative set of badssl.com servers and three A+ references, printing
// a consolidated report. It fails if any known-bad server passes a check it
// should fail, or if any A+ server fails a critical check.
func TestMilestone2_TLSFamilyComplete(t *testing.T) {
	type scenario struct {
		host     string
		insecure bool
		wantFail []string // check IDs that MUST fail on this host
		wantPass []string // check IDs that MUST pass on this host
	}

	scenarios := []scenario{
		{
			host:     "expired.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDCertExpired},
		},
		{
			host:     "self-signed.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDCertSelfSigned},
		},
		{
			host:     "wrong.host.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDCertNameMismatch},
		},
		{
			host:     "incomplete-chain.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDCertChainIncomplete},
		},
		{
			host:     "tls-v1-0.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDProtocolLegacyTLS10},
		},
		{
			host:     "tls-v1-1.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDProtocolLegacyTLS11},
		},
		{
			host:     "rc4.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDCipherRC4},
		},
		{
			host:     "dh1024.badssl.com",
			insecure: true,
			wantFail: []string{scannertls.IDCipherDHWeak},
		},
		// A+ reference servers — critical checks must pass.
		{
			host:     "cloudflare.com",
			insecure: false,
			wantPass: []string{
				scannertls.IDProtocolTLS12Missing,
				scannertls.IDCipherNoForwardSecrecy,
				scannertls.IDCertExpired,
				scannertls.IDHSTSMissing,
				scannertls.IDProtocolLegacyTLS10,
				scannertls.IDCipherRC4,
			},
		},
		{
			host:     "github.com",
			insecure: false,
			wantPass: []string{
				scannertls.IDProtocolTLS12Missing,
				scannertls.IDCertExpired,
				scannertls.IDHSTSMissing,
				scannertls.IDProtocolLegacyTLS10,
			},
		},
		{
			host:     "mozilla.org",
			insecure: false,
			wantPass: []string{
				scannertls.IDProtocolTLS12Missing,
				scannertls.IDCertExpired,
				scannertls.IDHSTSMissing,
				scannertls.IDProtocolLegacyTLS10,
			},
		},
	}

	r := checks.NewRegistry()
	scannertls.Register(r)

	allPassed := true
	for _, sc := range scenarios {
		addr := sc.host + ":443"
		if !func() bool {
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		}() {
			t.Logf("SKIP  %s (unreachable)", sc.host)
			continue
		}

		tgt := integrationTarget(t, sc.host, sc.insecure)
		t.Logf("── %s ──", sc.host)

		for _, id := range sc.wantFail {
			c, ok := r.Get(id)
			if !ok {
				t.Errorf("check %s not registered", id)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), familyTimeout)
			f, err := c.Run(ctx, tgt)
			cancel()
			if err != nil {
				t.Errorf("%s %s: run error: %v", sc.host, id, err)
				allPassed = false
				continue
			}
			t.Logf("  %-40s  %s", id, f.Status)
			if f.Status != checks.StatusFail {
				t.Errorf("  UNEXPECTED: %s on %s got %s, want fail", id, sc.host, f.Status)
				allPassed = false
			}
		}

		for _, id := range sc.wantPass {
			c, ok := r.Get(id)
			if !ok {
				t.Errorf("check %s not registered", id)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), familyTimeout)
			f, err := c.Run(ctx, tgt)
			cancel()
			if err != nil {
				t.Errorf("%s %s: run error: %v", sc.host, id, err)
				allPassed = false
				continue
			}
			t.Logf("  %-40s  %s", id, f.Status)
			if f.Status == checks.StatusFail {
				t.Errorf("  UNEXPECTED: %s on A+ server %s got fail", id, sc.host)
				allPassed = false
			}
		}
	}

	if allPassed {
		t.Log("\n🎯 Milestone 2 achieved: TLS family correctly identifies all tested scenarios.")
	}
}
