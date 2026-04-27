package email

import (
	"context"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// --- EMAIL-TLSRPT-MISSING --------------------------------------------

type tlsrptMissingCheck struct{}

func (tlsrptMissingCheck) ID() string                       { return IDTLSRPTMissing }
func (tlsrptMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (tlsrptMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (tlsrptMissingCheck) Title() string                    { return "Domain publishes TLS-RPT" }
func (tlsrptMissingCheck) Description() string {
	return "TLS-RPT (RFC 8460) lets receivers post failure reports about MTA-STS / DANE TLS issues."
}
func (tlsrptMissingCheck) RFCRefs() []string { return []string{"RFC 8460"} }

func (tlsrptMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDTLSRPTMissing, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDTLSRPTMissing, checks.SeverityLow); g != nil {
		return g, nil
	}
	if r.TLSRPT == "" {
		return fail(IDTLSRPTMissing, checks.SeverityLow,
			"no TLS-RPT record",
			"Publish a TXT record `v=TLSRPTv1; rua=mailto:tlsrpt@<domain>` on `_smtp._tls.<domain>`.", nil), nil
	}
	return pass(IDTLSRPTMissing, checks.SeverityLow,
		"TLS-RPT record present",
		map[string]any{"raw": r.TLSRPT}), nil
}

// --- EMAIL-BIMI-MISSING ----------------------------------------------

type bimiMissingCheck struct{}

func (bimiMissingCheck) ID() string                       { return IDBIMIMissing }
func (bimiMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (bimiMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (bimiMissingCheck) Title() string                    { return "Domain publishes BIMI" }
func (bimiMissingCheck) Description() string {
	return "BIMI displays a verified brand logo next to your messages in supporting clients (Gmail, Apple Mail, Yahoo)."
}
func (bimiMissingCheck) RFCRefs() []string {
	return []string{"draft-brand-indicators-for-message-identification"}
}

func (bimiMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDBIMIMissing, checks.SeverityInfo, err), nil
	}
	if g := gateOnMX(r, IDBIMIMissing, checks.SeverityInfo); g != nil {
		return g, nil
	}
	if r.BIMI == "" {
		return fail(IDBIMIMissing, checks.SeverityInfo,
			"no BIMI record",
			"Publish a TXT record `v=BIMI1; l=https://…/logo.svg` on `default._bimi.<domain>`.", nil), nil
	}
	return pass(IDBIMIMissing, checks.SeverityInfo,
		"BIMI record present",
		map[string]any{"raw": r.BIMI}), nil
}
