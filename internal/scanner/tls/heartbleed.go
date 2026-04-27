package tls

import (
	"context"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/tls/probes"
)

type heartbleedCheck struct{}

func (heartbleedCheck) ID() string                       { return IDVulnHeartbleed }
func (heartbleedCheck) Family() checks.Family            { return checks.FamilyTLS }
func (heartbleedCheck) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (heartbleedCheck) Title() string                    { return "Server is not vulnerable to Heartbleed" }
func (heartbleedCheck) Description() string {
	return "Heartbleed (CVE-2014-0160) is a critical buffer over-read in OpenSSL's TLS heartbeat extension " +
		"(RFC 6520). An attacker sends a heartbeat request with a payload_length far larger than the actual " +
		"payload; vulnerable OpenSSL allocates a response buffer of payload_length bytes and copies that " +
		"many bytes from heap memory, leaking private keys, session tokens, passwords, and other secrets. " +
		"Affected versions: OpenSSL 1.0.1 through 1.0.1f."
}
func (heartbleedCheck) RFCRefs() []string { return []string{"RFC 6520"} }

func (heartbleedCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	addr := t.DialAddress("443")

	status, err := probes.ProbeHeartbleed(ctx, addr)
	if err != nil {
		return errFinding(IDVulnHeartbleed, checks.SeverityCritical, err), nil
	}

	switch status {
	case probes.HeartbleedVulnerable:
		return failFinding(IDVulnHeartbleed, checks.SeverityCritical,
			"Heartbleed vulnerability detected (CVE-2014-0160)",
			"The server responded to a malformed TLS Heartbeat request with more data than requested, "+
				"confirming CVE-2014-0160 (Heartbleed). Upgrade OpenSSL to ≥ 1.0.1g or ≥ 1.0.2 immediately "+
				"and rotate all private keys and session secrets.",
			map[string]any{"cve": "CVE-2014-0160"}), nil

	case probes.HeartbleedSafe:
		return passFinding(IDVulnHeartbleed, checks.SeverityCritical,
			"not vulnerable to Heartbleed", nil), nil

	default: // HeartbleedUnknown
		return skippedFinding(IDVulnHeartbleed, checks.SeverityCritical,
			"Heartbleed probe inconclusive (connection failed or server unreachable)"), nil
	}
}
