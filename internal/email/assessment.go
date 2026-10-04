package email

import (
	"slices"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func assessment(status scan.Status, title, summary string, recommendations ...string) *scan.EmailAssessment {
	if recommendations == nil {
		recommendations = []string{}
	}
	return &scan.EmailAssessment{Status: status, Title: title, Summary: summary, Recommendations: recommendations}
}

func assessRecord(record *scan.DNSRecord, protocol string) *scan.EmailAssessment {
	switch record.State {
	case scan.DNSRecordAbsent:
		return assessment(scan.StatusWarn, protocol+" missing", "No applicable policy was found.",
			"Publish a policy appropriate to whether this domain sends email.")
	case scan.DNSRecordInvalid:
		return assessment(scan.StatusFail, "Invalid "+protocol+" configuration", "The published records could not establish a usable policy.",
			"Correct the malformed or duplicate records described in the diagnostics.")
	case scan.DNSRecordUnavailable:
		return assessment(scan.StatusInfo, "Verification unavailable", "A DNS error or scan limit prevented a conclusion.",
			"Retry the scan once DNS is responding; this result does not mean the policy is missing.")
	default:
		return nil
	}
}

func assessSPF(spf *scan.SPFReport) *scan.EmailAssessment {
	if a := assessRecord(&spf.DNSRecord, "SPF"); a != nil {
		return a
	}
	if spf.Audit != nil && len(spf.Audit.Issues) > 0 {
		return assessment(scan.StatusFail, "Broken SPF dependencies", "A referenced policy is missing, invalid or circular. Senders reaching it can encounter an SPF error.",
			"Correct the dependency errors listed below with your mail provider.")
	}
	if spf.All == "+all" {
		return assessment(scan.StatusWarn, "Permissive SPF policy", "The +all mechanism authorizes any sender that reaches it.",
			"List your legitimate senders and review the catch-all policy with your mail provider.")
	}
	if slices.Contains(spf.Warnings, permissivePrefixWarning) {
		return assessment(scan.StatusWarn, "Permissive SPF policy", permissivePrefixWarning,
			"Replace positive /0 ranges with the IP ranges of your legitimate senders.")
	}
	if spf.Audit != nil && spf.Audit.LookupLimitExceeded {
		return assessment(scan.StatusWarn, "Potential SPF lookup overflow", "The static dependency walk exceeds the 10-term SPF budget. An actual sender's evaluation may stop earlier.",
			"Review the include/redirect chain with your mail provider to keep evaluated DNS-causing terms within 10.")
	}
	var a *scan.EmailAssessment
	switch spf.All {
	case "-all":
		a = assessment(scan.StatusPass, "SPF fail policy", "Senders not matched by earlier mechanisms receive an SPF fail result. This alone does not guarantee rejection.")
	case "~all":
		a = assessment(scan.StatusInfo, "SPF softfail policy", "Senders not matched earlier receive a softfail. Softfail is a valid policy choice, not a configuration error by itself.",
			"Confirm that the policy covers every legitimate sender. Keep softfail if it is intentional; review enforcement together with DMARC.")
	case "?all":
		a = assessment(scan.StatusWarn, "Neutral SPF policy", "For unmatched senders, the domain makes no assertion about authorization.",
			"Review the intended policy and authorized senders with your mail provider.")
	default:
		if spf.Redirect != "" {
			a = assessment(scan.StatusInfo, "Delegated SPF policy", "Unmatched senders are evaluated using the redirect policy.")
		} else {
			a = assessment(scan.StatusWarn, "Implicit neutral SPF policy", "No all mechanism or redirect is declared; unmatched senders receive a neutral result.",
				"Make the intended fallback explicit after confirming all legitimate senders.")
		}
	}
	if spf.Audit == nil || !spf.Audit.Complete || len(spf.Warnings) > 0 {
		if a.Status == scan.StatusPass {
			a.Status = scan.StatusInfo
		}
		a.Recommendations = append(a.Recommendations, "Review the warnings and incomplete checks in Technical details before treating the policy as fully verified.")
	}
	return a
}

func assessDMARC(dmarc *scan.DMARCReport) *scan.EmailAssessment {
	if a := assessRecord(&dmarc.DNSRecord, "DMARC"); a != nil {
		return a
	}
	reporting := dmarc.ReportingState == "configured"
	var a *scan.EmailAssessment
	switch dmarc.Policy {
	case "none":
		if reporting {
			a = assessment(scan.StatusWarn, "DMARC monitoring only", "The policy requests aggregate reports, but no rejection or quarantine for messages that fail DMARC.")
		} else {
			a = assessment(scan.StatusWarn, "No enforcement or reports", "The policy requests neither rejection nor quarantine, and has no usable aggregate reporting destination.")
		}
		a.Recommendations = append(a.Recommendations, "Check legitimate senders' SPF/DKIM alignment and review reports before moving gradually to quarantine or reject.")
	case "quarantine":
		a = assessment(scan.StatusPass, "DMARC quarantine requested", "The policy asks receivers to treat messages that fail DMARC as suspicious.")
	case "reject":
		a = assessment(scan.StatusPass, "DMARC rejection requested", "The policy asks receivers to reject messages that fail DMARC. Actual handling remains the receiver's decision.")
	default:
		return assessment(scan.StatusInfo, "DMARC policy undetermined", "The available observations do not establish an enforcement policy.")
	}
	if !reporting {
		a.Status = scan.StatusWarn
		a.Recommendations = append([]string{"Add a valid rua reporting address to observe authentication results; verify external reporting authorization when required."}, a.Recommendations...)
	}
	if dmarc.Testing || len(dmarc.Warnings) > 0 {
		a.Status = scan.StatusWarn
	}
	return a
}
