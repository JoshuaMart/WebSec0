package email

import (
	"context"
	"strconv"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// MTASTSPolicy is the parsed shape of /.well-known/mta-sts.txt
// (newline-separated `key: value`).
type MTASTSPolicy struct {
	Version string
	Mode    string // enforce / testing / none
	MX      []string
	MaxAge  int // seconds
}

// ParseMTASTSPolicy parses the policy file body. Returns nil on empty input.
func ParseMTASTSPolicy(raw string) *MTASTSPolicy {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	p := &MTASTSPolicy{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "version":
			p.Version = v
		case "mode":
			p.Mode = strings.ToLower(v)
		case "mx":
			p.MX = append(p.MX, v)
		case "max_age":
			n, err := strconv.Atoi(v)
			if err == nil {
				p.MaxAge = n
			}
		}
	}
	return p
}

// --- EMAIL-MTASTS-MISSING --------------------------------------------

type mtastsMissingCheck struct{}

func (mtastsMissingCheck) ID() string                       { return IDMTASTSMissing }
func (mtastsMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (mtastsMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (mtastsMissingCheck) Title() string                    { return "Domain publishes MTA-STS" }
func (mtastsMissingCheck) Description() string {
	return "MTA-STS (RFC 8461) forces transit MTAs to use TLS when delivering to your MX."
}
func (mtastsMissingCheck) RFCRefs() []string { return []string{"RFC 8461"} }

func (mtastsMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDMTASTSMissing, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDMTASTSMissing, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if r.MTASTSTxt == "" || r.MTASTSPolicy == "" {
		return fail(IDMTASTSMissing, checks.SeverityMedium,
			"MTA-STS not deployed",
			"Publish a TXT record `_mta-sts.<domain>` and a policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.",
			map[string]any{"txt_present": r.MTASTSTxt != "", "policy_present": r.MTASTSPolicy != ""}), nil
	}
	return pass(IDMTASTSMissing, checks.SeverityMedium,
		"MTA-STS TXT and policy present",
		map[string]any{"txt": r.MTASTSTxt}), nil
}

// --- EMAIL-MTASTS-MODE-TESTING ---------------------------------------

type mtastsModeTestingCheck struct{}

func (mtastsModeTestingCheck) ID() string                       { return IDMTASTSModeTesting }
func (mtastsModeTestingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (mtastsModeTestingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (mtastsModeTestingCheck) Title() string                    { return "MTA-STS mode is `enforce`" }
func (mtastsModeTestingCheck) Description() string {
	return "`mode: testing` collects telemetry but does not enforce TLS — flip to `enforce` once stable."
}
func (mtastsModeTestingCheck) RFCRefs() []string { return []string{"RFC 8461 §3.2"} }

func (mtastsModeTestingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDMTASTSModeTesting, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDMTASTSModeTesting, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if r.MTASTSPolicy == "" {
		return skipped(IDMTASTSModeTesting, checks.SeverityMedium, "no MTA-STS policy"), nil
	}
	p := ParseMTASTSPolicy(r.MTASTSPolicy)
	if p == nil {
		return skipped(IDMTASTSModeTesting, checks.SeverityMedium, "policy parse failed"), nil
	}
	switch p.Mode {
	case "enforce":
		return pass(IDMTASTSModeTesting, checks.SeverityMedium,
			"MTA-STS in enforce mode", nil), nil
	case "testing":
		return fail(IDMTASTSModeTesting, checks.SeverityMedium,
			"MTA-STS in `testing` mode",
			"Move to `mode: enforce` once telemetry is clean.", nil), nil
	case "none":
		return fail(IDMTASTSModeTesting, checks.SeverityMedium,
			"MTA-STS in `none` mode (effectively disabled)", "", nil), nil
	default:
		return warn(IDMTASTSModeTesting, checks.SeverityMedium,
			"MTA-STS mode unrecognised",
			"Expected `enforce` / `testing` / `none`.",
			map[string]any{"mode": p.Mode}), nil
	}
}

// --- EMAIL-MTASTS-MAX-AGE-LOW ----------------------------------------

const mtastsMinMaxAge = 86400 * 30 // 30 days

type mtastsMaxAgeLowCheck struct{}

func (mtastsMaxAgeLowCheck) ID() string                       { return IDMTASTSMaxAgeLow }
func (mtastsMaxAgeLowCheck) Family() checks.Family            { return checks.FamilyEmail }
func (mtastsMaxAgeLowCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (mtastsMaxAgeLowCheck) Title() string                    { return "MTA-STS max_age is at least 30 days" }
func (mtastsMaxAgeLowCheck) Description() string {
	return "Short max_age means cached policies expire fast and many MTAs fall back to non-strict TLS."
}
func (mtastsMaxAgeLowCheck) RFCRefs() []string { return []string{"RFC 8461 §3.2"} }

func (mtastsMaxAgeLowCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDMTASTSMaxAgeLow, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDMTASTSMaxAgeLow, checks.SeverityLow); g != nil {
		return g, nil
	}
	if r.MTASTSPolicy == "" {
		return skipped(IDMTASTSMaxAgeLow, checks.SeverityLow, "no MTA-STS policy"), nil
	}
	p := ParseMTASTSPolicy(r.MTASTSPolicy)
	if p == nil {
		return skipped(IDMTASTSMaxAgeLow, checks.SeverityLow, "policy parse failed"), nil
	}
	ev := map[string]any{"max_age_seconds": p.MaxAge}
	if p.MaxAge == 0 {
		return fail(IDMTASTSMaxAgeLow, checks.SeverityLow,
			"MTA-STS policy missing max_age", "", ev), nil
	}
	if p.MaxAge < mtastsMinMaxAge {
		return fail(IDMTASTSMaxAgeLow, checks.SeverityLow,
			"MTA-STS max_age below 30 days",
			"Set max_age to at least 2592000 (30 days).", ev), nil
	}
	return pass(IDMTASTSMaxAgeLow, checks.SeverityLow,
		"MTA-STS max_age ≥ 30 days", ev), nil
}
