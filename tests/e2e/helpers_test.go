//go:build e2e

// Package e2e exercises the full scanner orchestrator against real
// targets. These tests are end-to-end (every check family registered, a
// real Runner.Run, a real report.Build) and require internet access for
// the badssl.com / reference suites and a local Docker fixture for the
// legacy suite.
//
// Build tag is `e2e` (distinct from the per-family `integration` tag) so
// the slower full-scan suites do not run with `go test -tags integration`.
//
//	go test -tags e2e ./tests/e2e/ -v -run TestE2E_BadSSL
//	go test -tags e2e ./tests/e2e/ -v -run TestE2E_APlus
//	WEBSEC0_LEGACY_FIXTURE_HOST=localhost:8443 \
//	  go test -tags e2e ./tests/e2e/ -v -run TestE2E_LegacyFixture
package e2e

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/report"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/JoshuaMart/websec0/internal/scanner/cookies"
	scannerdns "github.com/JoshuaMart/websec0/internal/scanner/dns"
	"github.com/JoshuaMart/websec0/internal/scanner/email"
	"github.com/JoshuaMart/websec0/internal/scanner/headers"
	scannerhttp "github.com/JoshuaMart/websec0/internal/scanner/http"
	"github.com/JoshuaMart/websec0/internal/scanner/safety"
	scannertls "github.com/JoshuaMart/websec0/internal/scanner/tls"
	"github.com/JoshuaMart/websec0/internal/scanner/wellknown"
)

// e2eTimeout is the wall-clock budget for one full scan (one target).
// Conservative: 50 checks × 8 s timeout = 400 s worst case, but the
// runner runs ten in parallel, so the practical bound is ~60 s.
const e2eTimeout = 90 * time.Second

// reachable is a 3-second TCP probe used to skip a test when the
// upstream host is unreachable (offline CI, transient outage). We
// prefer a clear skip over a flaky failure.
func reachable(t *testing.T, hostport string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", hostport, 3*time.Second)
	if err != nil {
		t.Logf("skip: %s unreachable (%v)", hostport, err)
		return false
	}
	_ = conn.Close()
	return true
}

// fullRegistry assembles every Check family registered by the production
// server and CLI. Mirrors cmd/websec0/main.go and cmd/websec0-cli.
func fullRegistry(t *testing.T) *checks.Registry {
	t.Helper()
	r := checks.NewRegistry()
	wellknown.Register(r)
	scannertls.Register(r)
	headers.Register(r)
	cookies.Register(r)
	scannerdns.Register(r)
	email.Register(r)
	scannerhttp.Register(r)
	return r
}

// runFullScan executes every registered check against host and returns
// the rendered Report. insecure relaxes the HTTP client TLS verification
// (needed for badssl.com targets with deliberately broken certs so that
// the HSTS / redirect / mixed-content probes do not abort early).
func runFullScan(t *testing.T, host string, insecure bool) *report.Report {
	t.Helper()

	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget(%q): %v", host, err)
	}

	// SSRF gate. Permissive() is used so the local legacy fixture
	// (loopback / RFC 1918) is allowed; metadata IPs remain blocked.
	policy := safety.Permissive()
	pinned, decision := safety.ResolveAndValidate(context.Background(), tgt.Hostname, policy, nil)
	if decision != nil {
		t.Fatalf("target %q blocked: %s", host, decision.HumanError())
	}
	tgt.PinnedIPs = pinned

	if insecure {
		tgt.HTTPClient = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &stdtls.Config{InsecureSkipVerify: true}, //#nosec G402 -- e2e only
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else {
		tgt.HTTPClient = safety.HTTPClient(tgt.Hostname, pinned, policy)
	}

	r := fullRegistry(t)
	runner := scanner.NewRunner(r, scanner.RunnerConfig{
		MaxConcurrent:   10,
		PerCheckTimeout: 8 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), e2eTimeout)
	defer cancel()

	started := time.Now().UTC()
	findings, err := runner.Run(ctx, tgt, nil, nil)
	if err != nil {
		t.Fatalf("Runner.Run(%q): %v", host, err)
	}
	completed := time.Now().UTC()

	rep := report.Build(
		"e2e-"+host,
		host,
		started,
		completed,
		findings,
		report.BuildOptions{ScannerVersion: "e2e"},
	)
	t.Logf("%s: grade=%s score=%d duration=%ds findings=%d",
		host, rep.Summary.Grade, rep.Summary.Score, rep.Scan.DurationSeconds, len(rep.Findings))
	return rep
}

// findingByID returns the FindingEntry for id, or nil if absent.
func findingByID(rep *report.Report, id string) *report.FindingEntry {
	for i := range rep.Findings {
		if rep.Findings[i].ID == id {
			return &rep.Findings[i]
		}
	}
	return nil
}

// assertStatus asserts that the finding for id has the expected status.
// Missing finding fails the test.
func assertStatus(t *testing.T, rep *report.Report, id string, want checks.FindingStatus) {
	t.Helper()
	f := findingByID(rep, id)
	if f == nil {
		t.Errorf("%s: %s not in findings", rep.Scan.Target, id)
		return
	}
	if f.Status != want {
		t.Errorf("%s: %s got status=%s, want %s (title=%q)",
			rep.Scan.Target, id, f.Status, want, f.Title)
	}
}

// assertNotFail asserts the check did not fail. Missing or pass / skipped
// is fine — we only fail the test if status is fail.
func assertNotFail(t *testing.T, rep *report.Report, id string) {
	t.Helper()
	f := findingByID(rep, id)
	if f == nil {
		return
	}
	if f.Status == checks.StatusFail {
		t.Errorf("%s: %s unexpectedly failed (title=%q)",
			rep.Scan.Target, id, f.Title)
	}
}
