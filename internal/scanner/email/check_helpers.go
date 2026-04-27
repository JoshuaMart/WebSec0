package email

import "github.com/JoshuaMart/websec0/internal/checks"

// Check IDs for the email family.
const (
	IDSPFMissing         = "EMAIL-SPF-MISSING"
	IDSPFMultiple        = "EMAIL-SPF-MULTIPLE-RECORDS"
	IDSPFInvalidSyntax   = "EMAIL-SPF-INVALID-SYNTAX"
	IDSPFNoAll           = "EMAIL-SPF-NO-ALL-MECHANISM"
	IDSPFPassAll         = "EMAIL-SPF-PASS-ALL"
	IDSPFSoftfailAll     = "EMAIL-SPF-SOFTFAIL-ALL"
	IDSPFPTRMechanism    = "EMAIL-SPF-PTR-MECHANISM"
	IDDKIMNoneFound      = "EMAIL-DKIM-NONE-FOUND"
	IDDKIMWeakKey        = "EMAIL-DKIM-WEAK-KEY"
	IDDKIMSHA1           = "EMAIL-DKIM-SHA1"
	IDDKIMTestMode       = "EMAIL-DKIM-TEST-MODE"
	IDDMARCMissing       = "EMAIL-DMARC-MISSING"
	IDDMARCInvalidSyntax = "EMAIL-DMARC-INVALID-SYNTAX"
	IDDMARCPolicyNone    = "EMAIL-DMARC-POLICY-NONE"
	IDDMARCPolicyWeak    = "EMAIL-DMARC-POLICY-WEAK"
	IDDMARCNoRUA         = "EMAIL-DMARC-NO-RUA"
	IDMTASTSMissing      = "EMAIL-MTASTS-MISSING"
	IDMTASTSModeTesting  = "EMAIL-MTASTS-MODE-TESTING"
	IDMTASTSMaxAgeLow    = "EMAIL-MTASTS-MAX-AGE-LOW"
	IDTLSRPTMissing      = "EMAIL-TLSRPT-MISSING"
	IDBIMIMissing        = "EMAIL-BIMI-MISSING"
)

// gateOnMX returns a non-nil "skipped" finding when the domain has no MX
// record (i.e. doesn't receive mail). This is the MX gating per
// SPECIFICATIONS.md §3 — no need to flag missing SPF on a domain that
// can't be a forge target.
func gateOnMX(r *Result, id string, sev checks.Severity) *checks.Finding {
	if !r.HasMX {
		return &checks.Finding{
			ID:       id,
			Family:   checks.FamilyEmail,
			Severity: sev,
			Status:   checks.StatusSkipped,
			Title:    "skipped: no MX record",
		}
	}
	return nil
}

func errFinding(id string, sev checks.Severity, err error) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyEmail, Severity: sev,
		Status: checks.StatusError, Title: "email: probe error", Description: err.Error(),
	}
}
func skipped(id string, sev checks.Severity, reason string) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyEmail, Severity: sev,
		Status: checks.StatusSkipped, Title: "skipped: " + reason,
	}
}
func pass(id string, sev checks.Severity, title string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyEmail, Severity: sev,
		Status: checks.StatusPass, Title: title, Evidence: ev,
	}
}
func fail(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyEmail, Severity: sev,
		Status: checks.StatusFail, Title: title, Description: desc, Evidence: ev,
	}
}
func warn(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyEmail, Severity: sev,
		Status: checks.StatusWarn, Title: title, Description: desc, Evidence: ev,
	}
}
