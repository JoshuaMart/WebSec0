package email

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"

	"github.com/Jomar/websec101/internal/checks"
)

// DKIM is the parsed shape of a `v=DKIM1 …` record.
type DKIM struct {
	Raw      string
	Tags     map[string]string // lowercase tag → value
	KeyBits  int               // 0 if unknown / non-RSA
	Hashes   []string          // h= tag, default sha256
	TestMode bool              // t=y
	Revoked  bool              // p= empty → revoked
}

// ParseDKIM parses a single DKIM record. Returns nil for empty input.
func ParseDKIM(raw string) *DKIM {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	d := &DKIM{Raw: raw, Tags: map[string]string{}}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		d.Tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if h, ok := d.Tags["h"]; ok && h != "" {
		for _, tok := range strings.Split(h, ":") {
			d.Hashes = append(d.Hashes, strings.ToLower(strings.TrimSpace(tok)))
		}
	} else {
		d.Hashes = []string{"sha256"} // RFC 6376 §3.5 default
	}
	for _, flag := range strings.Split(d.Tags["t"], ":") {
		if strings.EqualFold(strings.TrimSpace(flag), "y") {
			d.TestMode = true
		}
	}
	pkey := strings.ReplaceAll(d.Tags["p"], " ", "")
	if pkey == "" {
		d.Revoked = true
	} else if der, err := base64.StdEncoding.DecodeString(pkey); err == nil {
		if pub, perr := x509.ParsePKIXPublicKey(der); perr == nil {
			if rsapub, ok := pub.(*rsa.PublicKey); ok {
				d.KeyBits = rsapub.N.BitLen()
			}
		}
	}
	return d
}

// --- EMAIL-DKIM-NONE-FOUND -------------------------------------------

type dkimNoneFoundCheck struct{}

func (dkimNoneFoundCheck) ID() string                       { return IDDKIMNoneFound }
func (dkimNoneFoundCheck) Family() checks.Family            { return checks.FamilyEmail }
func (dkimNoneFoundCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (dkimNoneFoundCheck) Title() string                    { return "DKIM key published on at least one common selector" }
func (dkimNoneFoundCheck) Description() string {
	return "WebSec101 probes ~25 common DKIM selectors. None matching means DKIM is either unconfigured or uses a non-conventional selector name."
}
func (dkimNoneFoundCheck) RFCRefs() []string { return []string{"RFC 6376"} }

func (dkimNoneFoundCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDKIMNoneFound, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDDKIMNoneFound, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if len(r.DKIM) == 0 {
		var sel []string
		for s := range r.DKIMErrs {
			sel = append(sel, s)
		}
		return fail(IDDKIMNoneFound, checks.SeverityMedium,
			"no DKIM key on common selectors",
			"Publish a `v=DKIM1` TXT record on `<selector>._domainkey.<domain>`.",
			map[string]any{"probed_selectors": CommonDKIMSelectors, "lookup_errors": len(sel)}), nil
	}
	return pass(IDDKIMNoneFound, checks.SeverityMedium,
		"DKIM keys found",
		map[string]any{"selectors": keys(r.DKIM)}), nil
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- EMAIL-DKIM-WEAK-KEY ---------------------------------------------

type dkimWeakKeyCheck struct{}

func (dkimWeakKeyCheck) ID() string                       { return IDDKIMWeakKey }
func (dkimWeakKeyCheck) Family() checks.Family            { return checks.FamilyEmail }
func (dkimWeakKeyCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (dkimWeakKeyCheck) Title() string                    { return "DKIM keys are at least 1024 bits" }
func (dkimWeakKeyCheck) Description() string {
	return "RFC 8301 mandates ≥ 1024-bit RSA; 2048-bit is the modern default."
}
func (dkimWeakKeyCheck) RFCRefs() []string { return []string{"RFC 8301"} }

func (dkimWeakKeyCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDKIMWeakKey, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDDKIMWeakKey, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if len(r.DKIM) == 0 {
		return skipped(IDDKIMWeakKey, checks.SeverityMedium, "no DKIM record"), nil
	}
	weak := map[string]int{}
	for sel, raw := range r.DKIM {
		d := ParseDKIM(raw)
		if d != nil && d.KeyBits > 0 && d.KeyBits < 1024 {
			weak[sel] = d.KeyBits
		}
	}
	if len(weak) > 0 {
		return fail(IDDKIMWeakKey, checks.SeverityMedium,
			"DKIM keys below 1024 bits",
			"Rotate to a 2048-bit RSA key (or Ed25519 once your senders support it).",
			map[string]any{"weak": weak}), nil
	}
	return pass(IDDKIMWeakKey, checks.SeverityMedium,
		"DKIM keys are ≥ 1024 bits", nil), nil
}

// --- EMAIL-DKIM-SHA1 -------------------------------------------------

type dkimSHA1Check struct{}

func (dkimSHA1Check) ID() string                       { return IDDKIMSHA1 }
func (dkimSHA1Check) Family() checks.Family            { return checks.FamilyEmail }
func (dkimSHA1Check) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (dkimSHA1Check) Title() string                    { return "DKIM uses SHA-256 (not SHA-1)" }
func (dkimSHA1Check) Description() string {
	return "RFC 8301 forbids SHA-1 in DKIM signatures. Modern records pin h=sha256."
}
func (dkimSHA1Check) RFCRefs() []string { return []string{"RFC 8301"} }

func (dkimSHA1Check) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDKIMSHA1, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDDKIMSHA1, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if len(r.DKIM) == 0 {
		return skipped(IDDKIMSHA1, checks.SeverityMedium, "no DKIM record"), nil
	}
	bad := map[string][]string{}
	for sel, raw := range r.DKIM {
		d := ParseDKIM(raw)
		if d == nil {
			continue
		}
		for _, h := range d.Hashes {
			if h == "sha1" {
				bad[sel] = d.Hashes
			}
		}
	}
	if len(bad) > 0 {
		return fail(IDDKIMSHA1, checks.SeverityMedium,
			"DKIM record allows SHA-1",
			"Drop the `h=sha1` tag (RFC 8301 forbids it).",
			map[string]any{"selectors": bad}), nil
	}
	return pass(IDDKIMSHA1, checks.SeverityMedium,
		"all DKIM records pin SHA-256", nil), nil
}

// --- EMAIL-DKIM-TEST-MODE --------------------------------------------

type dkimTestModeCheck struct{}

func (dkimTestModeCheck) ID() string                       { return IDDKIMTestMode }
func (dkimTestModeCheck) Family() checks.Family            { return checks.FamilyEmail }
func (dkimTestModeCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (dkimTestModeCheck) Title() string                    { return "DKIM records are not in test mode" }
func (dkimTestModeCheck) Description() string {
	return "`t=y` instructs receivers to ignore DKIM failures — only acceptable during initial deployment."
}
func (dkimTestModeCheck) RFCRefs() []string { return []string{"RFC 6376 §3.6.1"} }

func (dkimTestModeCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDKIMTestMode, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDDKIMTestMode, checks.SeverityLow); g != nil {
		return g, nil
	}
	if len(r.DKIM) == 0 {
		return skipped(IDDKIMTestMode, checks.SeverityLow, "no DKIM record"), nil
	}
	var bad []string
	for sel, raw := range r.DKIM {
		d := ParseDKIM(raw)
		if d != nil && d.TestMode {
			bad = append(bad, sel)
		}
	}
	if len(bad) > 0 {
		return fail(IDDKIMTestMode, checks.SeverityLow,
			"DKIM record is in test mode (t=y)",
			"Remove `t=y` once deployment is stable.",
			map[string]any{"selectors": bad}), nil
	}
	return pass(IDDKIMTestMode, checks.SeverityLow,
		"DKIM records are in production mode", nil), nil
}
