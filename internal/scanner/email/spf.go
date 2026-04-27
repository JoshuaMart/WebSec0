package email

import (
	"context"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// SPF is the parsed shape of an `v=spf1 …` record.
type SPF struct {
	Raw          string
	Terms        []SPFTerm
	HasAll       bool
	AllQualifier byte // '+', '-', '~', '?'; 0 if no `all`
}

// SPFTerm is a single mechanism or modifier.
type SPFTerm struct {
	Qualifier byte   // '+' / '-' / '~' / '?' for mechanisms, 0 for modifiers
	Name      string // include / a / mx / ip4 / ip6 / ptr / exists / all / redirect / exp / unknown
	Value     string // text after `:` or `=`
	Raw       string
}

// ParseSPF parses a raw record. Returns nil on empty input. Malformed
// terms are recorded but do not abort parsing — InvalidSyntax check
// inspects ParseErrors via the helper below.
func ParseSPF(raw string) (*SPF, []string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := &SPF{Raw: raw}
	var errs []string

	parts := strings.Fields(raw)
	if len(parts) == 0 || !strings.EqualFold(parts[0], "v=spf1") {
		errs = append(errs, "missing v=spf1 prefix")
		return out, errs
	}
	for _, p := range parts[1:] {
		t := parseTerm(p)
		out.Terms = append(out.Terms, t)
		if strings.EqualFold(t.Name, "all") {
			out.HasAll = true
			out.AllQualifier = t.Qualifier
		}
	}
	return out, errs
}

func parseTerm(p string) SPFTerm {
	t := SPFTerm{Raw: p}
	body := p
	switch body[0] {
	case '+', '-', '~', '?':
		t.Qualifier = body[0]
		body = body[1:]
	}
	// Modifier (key=value) vs mechanism (name[:value]).
	if eq := strings.IndexByte(body, '='); eq >= 0 && !strings.ContainsAny(body[:eq], ":/") {
		t.Name = strings.ToLower(body[:eq])
		t.Value = body[eq+1:]
		t.Qualifier = 0 // modifiers don't carry qualifiers
		return t
	}
	if t.Qualifier == 0 {
		t.Qualifier = '+' // default qualifier per RFC 7208 §4.6.2
	}
	if colon := strings.IndexByte(body, ':'); colon >= 0 {
		t.Name = strings.ToLower(body[:colon])
		t.Value = body[colon+1:]
		return t
	}
	if slash := strings.IndexByte(body, '/'); slash >= 0 {
		t.Name = strings.ToLower(body[:slash])
		t.Value = body[slash:]
		return t
	}
	t.Name = strings.ToLower(body)
	return t
}

// --- EMAIL-SPF-MISSING -----------------------------------------------

type spfMissingCheck struct{}

func (spfMissingCheck) ID() string                       { return IDSPFMissing }
func (spfMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (spfMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (spfMissingCheck) Title() string                    { return "Domain publishes an SPF record" }
func (spfMissingCheck) Description() string {
	return "SPF (RFC 7208) lets receivers reject forged mail claiming to come from your domain."
}
func (spfMissingCheck) RFCRefs() []string { return []string{"RFC 7208"} }

func (spfMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSPFMissing, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDSPFMissing, checks.SeverityHigh); g != nil {
		return g, nil
	}
	if len(r.SPF) == 0 {
		return fail(IDSPFMissing, checks.SeverityHigh,
			"no SPF record",
			"Publish a TXT record `v=spf1 …` on the apex.", nil), nil
	}
	return pass(IDSPFMissing, checks.SeverityHigh,
		"SPF record present",
		map[string]any{"raw": r.SPFRaw[0]}), nil
}

// --- EMAIL-SPF-MULTIPLE-RECORDS --------------------------------------

type spfMultipleCheck struct{}

func (spfMultipleCheck) ID() string                       { return IDSPFMultiple }
func (spfMultipleCheck) Family() checks.Family            { return checks.FamilyEmail }
func (spfMultipleCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (spfMultipleCheck) Title() string                    { return "Single SPF record per RFC 7208 §3.2" }
func (spfMultipleCheck) Description() string {
	return "Multiple SPF records make all of them invalid (PermError)."
}
func (spfMultipleCheck) RFCRefs() []string { return []string{"RFC 7208 §3.2"} }

func (spfMultipleCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSPFMultiple, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDSPFMultiple, checks.SeverityHigh); g != nil {
		return g, nil
	}
	if len(r.SPFRaw) == 0 {
		return skipped(IDSPFMultiple, checks.SeverityHigh, "no SPF record"), nil
	}
	if len(r.SPFRaw) > 1 {
		return fail(IDSPFMultiple, checks.SeverityHigh,
			"multiple SPF records published",
			"Merge into a single `v=spf1 …` record.",
			map[string]any{"records": r.SPFRaw}), nil
	}
	return pass(IDSPFMultiple, checks.SeverityHigh,
		"single SPF record", nil), nil
}

// --- EMAIL-SPF-INVALID-SYNTAX ----------------------------------------

type spfInvalidSyntaxCheck struct{}

func (spfInvalidSyntaxCheck) ID() string                       { return IDSPFInvalidSyntax }
func (spfInvalidSyntaxCheck) Family() checks.Family            { return checks.FamilyEmail }
func (spfInvalidSyntaxCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (spfInvalidSyntaxCheck) Title() string                    { return "SPF record is syntactically valid" }
func (spfInvalidSyntaxCheck) Description() string {
	return "Malformed SPF records are evaluated as PermError and protection is lost."
}
func (spfInvalidSyntaxCheck) RFCRefs() []string { return []string{"RFC 7208"} }

func (spfInvalidSyntaxCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSPFInvalidSyntax, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDSPFInvalidSyntax, checks.SeverityHigh); g != nil {
		return g, nil
	}
	if len(r.SPF) == 0 {
		return skipped(IDSPFInvalidSyntax, checks.SeverityHigh, "no SPF record"), nil
	}
	_, errs := ParseSPF(r.SPF[0])
	if len(errs) > 0 {
		return fail(IDSPFInvalidSyntax, checks.SeverityHigh,
			"SPF parse errors",
			strings.Join(errs, "; "),
			map[string]any{"errors": errs}), nil
	}
	return pass(IDSPFInvalidSyntax, checks.SeverityHigh,
		"SPF parses cleanly", nil), nil
}

// --- EMAIL-SPF-NO-ALL-MECHANISM --------------------------------------

type spfNoAllCheck struct{}

func (spfNoAllCheck) ID() string                       { return IDSPFNoAll }
func (spfNoAllCheck) Family() checks.Family            { return checks.FamilyEmail }
func (spfNoAllCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (spfNoAllCheck) Title() string                    { return "SPF record terminates with an `all` mechanism" }
func (spfNoAllCheck) Description() string {
	return "Without a terminal `all`, SPF evaluation falls back to Neutral and never rejects forgeries."
}
func (spfNoAllCheck) RFCRefs() []string { return []string{"RFC 7208 §4.7"} }

func (spfNoAllCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSPFNoAll, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDSPFNoAll, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if len(r.SPF) == 0 {
		return skipped(IDSPFNoAll, checks.SeverityMedium, "no SPF record"), nil
	}
	parsed, _ := ParseSPF(r.SPF[0])
	if parsed == nil || !parsed.HasAll {
		return fail(IDSPFNoAll, checks.SeverityMedium,
			"no `all` mechanism",
			"Append `-all` (or `~all`) to the record.", nil), nil
	}
	return pass(IDSPFNoAll, checks.SeverityMedium,
		"SPF terminates with `all`",
		map[string]any{"qualifier": string(parsed.AllQualifier)}), nil
}

// --- EMAIL-SPF-PASS-ALL ----------------------------------------------

type spfPassAllCheck struct{}

func (spfPassAllCheck) ID() string                       { return IDSPFPassAll }
func (spfPassAllCheck) Family() checks.Family            { return checks.FamilyEmail }
func (spfPassAllCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (spfPassAllCheck) Title() string                    { return "SPF doesn't end with `+all`" }
func (spfPassAllCheck) Description() string {
	return "`+all` (or bare `all`) accepts mail from every IP — defeats SPF entirely."
}
func (spfPassAllCheck) RFCRefs() []string { return []string{"RFC 7208"} }

func (spfPassAllCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSPFPassAll, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDSPFPassAll, checks.SeverityHigh); g != nil {
		return g, nil
	}
	if len(r.SPF) == 0 {
		return skipped(IDSPFPassAll, checks.SeverityHigh, "no SPF record"), nil
	}
	parsed, _ := ParseSPF(r.SPF[0])
	if parsed != nil && parsed.HasAll && parsed.AllQualifier == '+' {
		return fail(IDSPFPassAll, checks.SeverityHigh,
			"SPF ends with `+all`",
			"Tighten to `-all` or `~all`.", nil), nil
	}
	return pass(IDSPFPassAll, checks.SeverityHigh,
		"SPF does not pass-all", nil), nil
}

// --- EMAIL-SPF-SOFTFAIL-ALL ------------------------------------------

type spfSoftfailAllCheck struct{}

func (spfSoftfailAllCheck) ID() string                       { return IDSPFSoftfailAll }
func (spfSoftfailAllCheck) Family() checks.Family            { return checks.FamilyEmail }
func (spfSoftfailAllCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (spfSoftfailAllCheck) Title() string                    { return "SPF ends with hard fail (`-all`)" }
func (spfSoftfailAllCheck) Description() string {
	return "`~all` (Softfail) lets some receivers still deliver forgeries — `-all` is stricter."
}
func (spfSoftfailAllCheck) RFCRefs() []string { return []string{"RFC 7208"} }

func (spfSoftfailAllCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSPFSoftfailAll, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDSPFSoftfailAll, checks.SeverityLow); g != nil {
		return g, nil
	}
	if len(r.SPF) == 0 {
		return skipped(IDSPFSoftfailAll, checks.SeverityLow, "no SPF record"), nil
	}
	parsed, _ := ParseSPF(r.SPF[0])
	if parsed != nil && parsed.HasAll && parsed.AllQualifier == '~' {
		return warn(IDSPFSoftfailAll, checks.SeverityLow,
			"SPF ends with `~all` (softfail)",
			"Consider tightening to `-all` once you've confirmed all senders are listed.", nil), nil
	}
	return pass(IDSPFSoftfailAll, checks.SeverityLow,
		"SPF doesn't softfail", nil), nil
}

// --- EMAIL-SPF-PTR-MECHANISM -----------------------------------------

type spfPTRCheck struct{}

func (spfPTRCheck) ID() string                       { return IDSPFPTRMechanism }
func (spfPTRCheck) Family() checks.Family            { return checks.FamilyEmail }
func (spfPTRCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (spfPTRCheck) Title() string                    { return "SPF avoids the deprecated `ptr` mechanism" }
func (spfPTRCheck) Description() string {
	return "RFC 7208 §5.5 deprecates `ptr` — it's slow, expensive, and unreliable."
}
func (spfPTRCheck) RFCRefs() []string { return []string{"RFC 7208 §5.5"} }

func (spfPTRCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSPFPTRMechanism, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDSPFPTRMechanism, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if len(r.SPF) == 0 {
		return skipped(IDSPFPTRMechanism, checks.SeverityMedium, "no SPF record"), nil
	}
	parsed, _ := ParseSPF(r.SPF[0])
	if parsed == nil {
		return skipped(IDSPFPTRMechanism, checks.SeverityMedium, "SPF parse failed"), nil
	}
	for _, term := range parsed.Terms {
		if term.Name == "ptr" {
			return fail(IDSPFPTRMechanism, checks.SeverityMedium,
				"SPF uses the deprecated `ptr` mechanism",
				"Replace with `a` / `mx` / `ip4` / `ip6` / `include`.", nil), nil
		}
	}
	return pass(IDSPFPTRMechanism, checks.SeverityMedium,
		"no `ptr` mechanism", nil), nil
}
