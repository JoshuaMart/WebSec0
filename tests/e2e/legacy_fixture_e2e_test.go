//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/headers"
	scannertls "github.com/JoshuaMart/websec0/internal/scanner/tls"
)

// TestE2E_LegacyFixture exercises the orchestrator against the local
// nginx fixture under tests/e2e/legacy-fixture/. The test is opt-in: it
// runs only when WEBSEC0_LEGACY_FIXTURE_HOST is set (e.g. to
// `localhost:18443`). CI without Docker simply skips.
//
// The fixture is wrong on purpose. We assert that the scanner *flags*
// the deliberate misconfigurations — that's the entire point of having
// a controlled, reproducible target.
func TestE2E_LegacyFixture(t *testing.T) {
	host := os.Getenv("WEBSEC0_LEGACY_FIXTURE_HOST")
	if host == "" {
		t.Skip("WEBSEC0_LEGACY_FIXTURE_HOST not set — bring up tests/e2e/legacy-fixture/ first")
	}

	// The hostname-only form for the scanner. The fixture binds to
	// 127.0.0.1:18443, so callers usually pass "localhost:18443".
	hostport := host
	if !strings.Contains(hostport, ":") {
		hostport = host + ":443"
	}
	if !reachable(t, hostport) {
		t.Fatalf("fixture %s unreachable — is `make -C tests/e2e/legacy-fixture up` running?", hostport)
	}

	// runFullScan takes a hostname; the scanner derives the port itself
	// for the TLS family. We pass the host:port form because the fixture
	// is on a non-standard port and the headers/http/wellknown probes
	// need it. checks.NewTarget accepts "host:port".
	rep := runFullScan(t, host, true)

	// Hard assertions: the deliberate misconfigurations must surface.
	mustFail := []string{
		// TLS legacy
		scannertls.IDProtocolLegacyTLS10,
		scannertls.IDProtocolLegacyTLS11,
		// TLS cert (self-signed)
		scannertls.IDCertSelfSigned,
		// TLS hardening missing
		scannertls.IDHSTSMissing,
		scannertls.IDOCSPStaplingMissing,
		// HTTP redirect missing
		scannertls.IDRedirectHTTPToHTTPS,
		// Headers — the fixture sets none
		headers.IDCSPMissing,
		headers.IDXCTOMissing,
		headers.IDXFOMissing,
		headers.IDReferrerPolicyMissing,
	}
	for _, id := range mustFail {
		assertStatus(t, rep, id, checks.StatusFail)
	}

	// The fixture has Server-disclosure (server_tokens on). The exact
	// check ID is HEADER-INFO-SERVER. We don't import the constant
	// (kept private to the headers pkg) — assert on string ID.
	if f := findingByID(rep, "HEADER-INFO-SERVER"); f == nil {
		t.Errorf("HEADER-INFO-SERVER missing from findings (server_tokens on should trigger)")
	} else if f.Status != checks.StatusFail && f.Status != checks.StatusWarn {
		t.Errorf("HEADER-INFO-SERVER got %s, want fail or warn", f.Status)
	}

	// Sanity gate. A loopback fixture has no MX / no DNS / no cookies
	// to scan, so the email/dns/cookies families return mostly skipped
	// findings — those families auto-score 100 and pull the weighted
	// global up. The threshold reflects that math: TLS + headers + http
	// being completely broken nets ~70 in practice.
	if rep.Summary.Score >= 80 {
		t.Errorf("legacy fixture score=%d unexpectedly high (grade=%s) — fixture or scoring drift?",
			rep.Summary.Score, rep.Summary.Grade)
	}
	if rep.Summary.Counts.Critical+rep.Summary.Counts.High < 3 {
		t.Errorf("legacy fixture surfaced only %d critical+high findings — expected ≥ 3",
			rep.Summary.Counts.Critical+rep.Summary.Counts.High)
	}
}
