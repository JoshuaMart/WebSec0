//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/checks"
	scannerhttp "github.com/JoshuaMart/websec0/internal/scanner/http"
)

// TestE2E_ApacheFixture exercises the orchestrator against the local
// httpd:2.4 fixture under tests/e2e/legacy-fixture/apache/. Opt-in via
// WEBSEC0_APACHE_FIXTURE_HOST (e.g. localhost:18543).
//
// The Apache fixture covers the misconfigurations that nginx 1.18 does
// not naturally surface:
//   - HTTP-TRACE-ENABLED via `TraceEnable On`
//   - HTTP-CORS-ORIGIN-REFLECTED via `Header set Access-Control-Allow-Origin "%{ORIGIN}e"`
//   - Apache-flavoured `ServerTokens Full` (full version banner)
func TestE2E_ApacheFixture(t *testing.T) {
	host := os.Getenv("WEBSEC0_APACHE_FIXTURE_HOST")
	if host == "" {
		t.Skip("WEBSEC0_APACHE_FIXTURE_HOST not set — bring up tests/e2e/legacy-fixture/ first")
	}

	hostport := host
	if !strings.Contains(hostport, ":") {
		hostport = host + ":443"
	}
	if !reachable(t, hostport) {
		t.Fatalf("Apache fixture %s unreachable — is `make -C tests/e2e/legacy-fixture up` running?", hostport)
	}

	rep := runFullScan(t, host, true)

	// Apache-distinct hard assertions.
	mustFail := []string{
		// TRACE method enabled — the signature Apache misconfig.
		scannerhttp.IDTraceEnabled,
		// CORS reflection (the SetEnvIf + Header trick in httpd.conf).
		scannerhttp.IDCORSOriginReflected,
		// Mixed content from the fixture's HTML.
		scannerhttp.IDMixedContent,
	}
	for _, id := range mustFail {
		assertStatus(t, rep, id, checks.StatusFail)
	}

	// Apache full banner. ServerTokens Full → "Server: Apache/2.4.x …"
	if f := findingByID(rep, "HEADER-INFO-SERVER"); f == nil {
		t.Errorf("HEADER-INFO-SERVER missing from findings (ServerTokens Full should trigger)")
	} else if f.Status != checks.StatusFail && f.Status != checks.StatusWarn {
		t.Errorf("HEADER-INFO-SERVER got %s, want fail or warn", f.Status)
	}

	// Same loopback caveat as the nginx fixture.
	if rep.Summary.Score >= 80 {
		t.Errorf("Apache fixture score=%d unexpectedly high (grade=%s) — fixture or scoring drift?",
			rep.Summary.Score, rep.Summary.Grade)
	}
	if rep.Summary.Counts.Critical+rep.Summary.Counts.High < 3 {
		t.Errorf("Apache fixture surfaced only %d critical+high findings — expected ≥ 3",
			rep.Summary.Counts.Critical+rep.Summary.Counts.High)
	}
}
