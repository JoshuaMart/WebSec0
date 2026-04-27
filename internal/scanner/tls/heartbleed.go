package tls

import (
	"context"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// heartbleedCheck implements TLS-VULN-HEARTBLEED.
//
// Definitive Heartbleed detection requires completing a TLS 1.0/1.1 handshake
// and then sending an encrypted heartbeat request — an operation that depends
// on zcrypto or zgrab2 (see SPECIFICATIONS.md §4.3 and TODO.md §6.5).
//
// This stub registers the check in the catalog and returns StatusSkipped so
// that the finding appears in reports with an actionable note. The active probe
// will be implemented in a follow-up phase when zcrypto is added as a
// dependency.
type heartbleedCheck struct{}

func (heartbleedCheck) ID() string                       { return IDVulnHeartbleed }
func (heartbleedCheck) Family() checks.Family            { return checks.FamilyTLS }
func (heartbleedCheck) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (heartbleedCheck) Title() string                    { return "Server is not vulnerable to Heartbleed" }
func (heartbleedCheck) Description() string {
	return "Heartbleed (CVE-2014-0160) is a critical buffer over-read in OpenSSL's TLS heartbeat extension that allows an attacker to read up to 64 KB of server memory per request, potentially leaking private keys, session tokens, and credentials. Active detection requires completing a TLS handshake via zcrypto."
}
func (heartbleedCheck) RFCRefs() []string { return []string{"RFC 6520"} }

func (heartbleedCheck) Run(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
	return skippedFinding(IDVulnHeartbleed, checks.SeverityCritical,
		"active Heartbleed probe not yet implemented (requires zcrypto/zgrab2 — see TODO §6.5)"), nil
}
