package wellknown

import (
	"context"
	"fmt"
	"time"

	"github.com/Jomar/websec101/internal/checks"
)

// Check IDs for the security.txt family.
const (
	IDMissing     = "WELLKNOWN-SECURITY-TXT-MISSING"
	IDExpired     = "WELLKNOWN-SECURITY-TXT-EXPIRED"
	IDNoContact   = "WELLKNOWN-SECURITY-TXT-NO-CONTACT"
	IDNoExpires   = "WELLKNOWN-SECURITY-TXT-NO-EXPIRES"
	IDNotHTTPS    = "WELLKNOWN-SECURITY-TXT-NOT-HTTPS"
	IDNoSignature = "WELLKNOWN-SECURITY-TXT-NO-SIGNATURE"
	rfc9116Refs   = "RFC 9116"
)

// Register adds every security.txt check to r.
func Register(r *checks.Registry) {
	r.Register(missingCheck{})
	r.Register(expiredCheck{})
	r.Register(noContactCheck{})
	r.Register(noExpiresCheck{})
	r.Register(notHTTPSCheck{})
	r.Register(noSignatureCheck{})
}

// --- WELLKNOWN-SECURITY-TXT-MISSING -----------------------------------

type missingCheck struct{}

func (missingCheck) ID() string                       { return IDMissing }
func (missingCheck) Family() checks.Family            { return checks.FamilyWellKnown }
func (missingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (missingCheck) Title() string                    { return "security.txt is published" }
func (missingCheck) Description() string {
	return "RFC 9116 defines a /.well-known/security.txt file that lets researchers find the right contact for vulnerability disclosure."
}
func (missingCheck) RFCRefs() []string { return []string{rfc9116Refs, "RFC 8615"} }

func (missingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := FetchSecurityTxt(ctx, t)
	if err != nil {
		return errFinding(IDMissing, checks.FamilyWellKnown, checks.SeverityMedium, err), nil
	}
	if !res.Found {
		return &checks.Finding{
			ID:          IDMissing,
			Family:      checks.FamilyWellKnown,
			Severity:    checks.SeverityMedium,
			Status:      checks.StatusFail,
			Title:       "No security.txt published",
			Description: "Neither /.well-known/security.txt nor /security.txt could be retrieved.",
			Evidence:    map[string]any{"attempts": res.FetchErrs},
		}, nil
	}
	return passFinding(IDMissing, checks.FamilyWellKnown, "security.txt is published", res), nil
}

// --- WELLKNOWN-SECURITY-TXT-EXPIRED -----------------------------------

type expiredCheck struct{}

func (expiredCheck) ID() string                       { return IDExpired }
func (expiredCheck) Family() checks.Family            { return checks.FamilyWellKnown }
func (expiredCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (expiredCheck) Title() string                    { return "security.txt has not expired" }
func (expiredCheck) Description() string {
	return "An expired Expires field signals the disclosure information may be stale (RFC 9116 §2.5.5)."
}
func (expiredCheck) RFCRefs() []string { return []string{rfc9116Refs} }

func (expiredCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := FetchSecurityTxt(ctx, t)
	if err != nil {
		return errFinding(IDExpired, checks.FamilyWellKnown, checks.SeverityHigh, err), nil
	}
	if !res.Found || res.Parsed == nil {
		return skippedFinding(IDExpired, checks.FamilyWellKnown, checks.SeverityHigh, "no security.txt"), nil
	}
	if res.Parsed.Expires == nil {
		return skippedFinding(IDExpired, checks.FamilyWellKnown, checks.SeverityHigh, "no Expires field"), nil
	}
	now := time.Now().UTC()
	if res.Parsed.Expires.Before(now) {
		return &checks.Finding{
			ID:          IDExpired,
			Family:      checks.FamilyWellKnown,
			Severity:    checks.SeverityHigh,
			Status:      checks.StatusFail,
			Title:       "security.txt has expired",
			Description: fmt.Sprintf("Expires=%s is in the past (now=%s).", res.Parsed.Expires.Format(time.RFC3339), now.Format(time.RFC3339)),
			Evidence:    map[string]any{"expires": res.Parsed.Expires.UTC()},
		}, nil
	}
	return &checks.Finding{
		ID:       IDExpired,
		Family:   checks.FamilyWellKnown,
		Severity: checks.SeverityHigh,
		Status:   checks.StatusPass,
		Title:    "security.txt is fresh",
		Evidence: map[string]any{"expires": res.Parsed.Expires.UTC()},
	}, nil
}

// --- WELLKNOWN-SECURITY-TXT-NO-CONTACT --------------------------------

type noContactCheck struct{}

func (noContactCheck) ID() string                       { return IDNoContact }
func (noContactCheck) Family() checks.Family            { return checks.FamilyWellKnown }
func (noContactCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (noContactCheck) Title() string                    { return "security.txt declares Contact" }
func (noContactCheck) Description() string {
	return "RFC 9116 §2.5.3 requires at least one Contact field (mailto:, https:, or tel:)."
}
func (noContactCheck) RFCRefs() []string { return []string{rfc9116Refs} }

func (noContactCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := FetchSecurityTxt(ctx, t)
	if err != nil {
		return errFinding(IDNoContact, checks.FamilyWellKnown, checks.SeverityHigh, err), nil
	}
	if !res.Found || res.Parsed == nil {
		return skippedFinding(IDNoContact, checks.FamilyWellKnown, checks.SeverityHigh, "no security.txt"), nil
	}
	if len(res.Parsed.Contact) == 0 {
		return &checks.Finding{
			ID:          IDNoContact,
			Family:      checks.FamilyWellKnown,
			Severity:    checks.SeverityHigh,
			Status:      checks.StatusFail,
			Title:       "security.txt has no Contact",
			Description: "RFC 9116 §2.5.3 mandates at least one Contact entry.",
		}, nil
	}
	return &checks.Finding{
		ID:       IDNoContact,
		Family:   checks.FamilyWellKnown,
		Severity: checks.SeverityHigh,
		Status:   checks.StatusPass,
		Title:    "security.txt declares Contact",
		Evidence: map[string]any{"contacts": res.Parsed.Contact},
	}, nil
}

// --- WELLKNOWN-SECURITY-TXT-NO-EXPIRES --------------------------------

type noExpiresCheck struct{}

func (noExpiresCheck) ID() string                       { return IDNoExpires }
func (noExpiresCheck) Family() checks.Family            { return checks.FamilyWellKnown }
func (noExpiresCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (noExpiresCheck) Title() string                    { return "security.txt declares Expires" }
func (noExpiresCheck) Description() string {
	return "RFC 9116 §2.5.5 requires a single Expires field so consumers can detect stale documents."
}
func (noExpiresCheck) RFCRefs() []string { return []string{rfc9116Refs} }

func (noExpiresCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := FetchSecurityTxt(ctx, t)
	if err != nil {
		return errFinding(IDNoExpires, checks.FamilyWellKnown, checks.SeverityMedium, err), nil
	}
	if !res.Found || res.Parsed == nil {
		return skippedFinding(IDNoExpires, checks.FamilyWellKnown, checks.SeverityMedium, "no security.txt"), nil
	}
	if res.Parsed.Expires == nil {
		return &checks.Finding{
			ID:          IDNoExpires,
			Family:      checks.FamilyWellKnown,
			Severity:    checks.SeverityMedium,
			Status:      checks.StatusFail,
			Title:       "security.txt has no Expires",
			Description: "RFC 9116 §2.5.5 mandates a single Expires field.",
		}, nil
	}
	return &checks.Finding{
		ID:       IDNoExpires,
		Family:   checks.FamilyWellKnown,
		Severity: checks.SeverityMedium,
		Status:   checks.StatusPass,
		Title:    "security.txt declares Expires",
		Evidence: map[string]any{"expires": res.Parsed.Expires.UTC()},
	}, nil
}

// --- WELLKNOWN-SECURITY-TXT-NOT-HTTPS ---------------------------------

type notHTTPSCheck struct{}

func (notHTTPSCheck) ID() string                       { return IDNotHTTPS }
func (notHTTPSCheck) Family() checks.Family            { return checks.FamilyWellKnown }
func (notHTTPSCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (notHTTPSCheck) Title() string                    { return "security.txt is served over HTTPS" }
func (notHTTPSCheck) Description() string {
	return "RFC 9116 §3 requires security.txt to be served over HTTPS."
}
func (notHTTPSCheck) RFCRefs() []string { return []string{rfc9116Refs} }

func (notHTTPSCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := FetchSecurityTxt(ctx, t)
	if err != nil {
		return errFinding(IDNotHTTPS, checks.FamilyWellKnown, checks.SeverityMedium, err), nil
	}
	if !res.Found {
		return skippedFinding(IDNotHTTPS, checks.FamilyWellKnown, checks.SeverityMedium, "no security.txt"), nil
	}
	if res.FoundOverHTTPOnly {
		return &checks.Finding{
			ID:          IDNotHTTPS,
			Family:      checks.FamilyWellKnown,
			Severity:    checks.SeverityMedium,
			Status:      checks.StatusFail,
			Title:       "security.txt is only served over plain HTTP",
			Description: "RFC 9116 §3 requires HTTPS.",
			Evidence:    map[string]any{"url": res.FinalURL},
		}, nil
	}
	return &checks.Finding{
		ID:       IDNotHTTPS,
		Family:   checks.FamilyWellKnown,
		Severity: checks.SeverityMedium,
		Status:   checks.StatusPass,
		Title:    "security.txt is served over HTTPS",
		Evidence: map[string]any{"url": res.FinalURL},
	}, nil
}

// --- WELLKNOWN-SECURITY-TXT-NO-SIGNATURE ------------------------------

type noSignatureCheck struct{}

func (noSignatureCheck) ID() string                       { return IDNoSignature }
func (noSignatureCheck) Family() checks.Family            { return checks.FamilyWellKnown }
func (noSignatureCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (noSignatureCheck) Title() string                    { return "security.txt is OpenPGP-signed" }
func (noSignatureCheck) Description() string {
	return "RFC 9116 §3.3 recommends signing security.txt with an OpenPGP cleartext signature."
}
func (noSignatureCheck) RFCRefs() []string { return []string{rfc9116Refs} }

func (noSignatureCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := FetchSecurityTxt(ctx, t)
	if err != nil {
		return errFinding(IDNoSignature, checks.FamilyWellKnown, checks.SeverityLow, err), nil
	}
	if !res.Found || res.Parsed == nil {
		return skippedFinding(IDNoSignature, checks.FamilyWellKnown, checks.SeverityLow, "no security.txt"), nil
	}
	if !res.Parsed.Signed {
		return &checks.Finding{
			ID:          IDNoSignature,
			Family:      checks.FamilyWellKnown,
			Severity:    checks.SeverityLow,
			Status:      checks.StatusWarn,
			Title:       "security.txt is not OpenPGP-signed",
			Description: "Consider signing the file (RFC 9116 §3.3) so consumers can detect tampering.",
		}, nil
	}
	return &checks.Finding{
		ID:       IDNoSignature,
		Family:   checks.FamilyWellKnown,
		Severity: checks.SeverityLow,
		Status:   checks.StatusPass,
		Title:    "security.txt is OpenPGP-signed",
	}, nil
}

// --- helpers ----------------------------------------------------------

func passFinding(id string, fam checks.Family, title string, res *FetchResult) *checks.Finding {
	ev := map[string]any{"url": res.FinalURL}
	if !res.CanonicalPath {
		ev["legacy_path"] = true
	}
	return &checks.Finding{
		ID:       id,
		Family:   fam,
		Severity: checks.SeverityMedium,
		Status:   checks.StatusPass,
		Title:    title,
		Evidence: ev,
	}
}

func errFinding(id string, fam checks.Family, sev checks.Severity, err error) *checks.Finding {
	return &checks.Finding{
		ID:          id,
		Family:      fam,
		Severity:    sev,
		Status:      checks.StatusError,
		Title:       "fetcher error",
		Description: err.Error(),
	}
}

func skippedFinding(id string, fam checks.Family, sev checks.Severity, reason string) *checks.Finding {
	return &checks.Finding{
		ID:          id,
		Family:      fam,
		Severity:    sev,
		Status:      checks.StatusSkipped,
		Title:       "skipped: " + reason,
		Description: "Dependent state was unavailable; nothing to evaluate.",
	}
}
