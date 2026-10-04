package email

import (
	"context"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestAssessSPF(t *testing.T) {
	for _, tc := range []struct {
		record string
		status scan.Status
		title  string
	}{
		{"v=spf1 -all", scan.StatusPass, "SPF fail policy"},
		{"v=spf1 ip4:0.0.0.0/0 ip6:::/0 -all", scan.StatusWarn, "Permissive SPF policy"},
		{"v=spf1 +IP4:192.0.2.1/0 -all", scan.StatusWarn, "Permissive SPF policy"},
		{"v=spf1 ip6:2001:db8::/0 -all", scan.StatusWarn, "Permissive SPF policy"},
		{"v=spf1 -ip4:0.0.0.0/0 ~ip6:::/0 -all", scan.StatusPass, "SPF fail policy"},
		{"v=spf1 ?ip4:0.0.0.0/0 -all", scan.StatusPass, "SPF fail policy"},
		{"v=spf1 -all ip4:0.0.0.0/0 ip6:::/0", scan.StatusPass, "SPF fail policy"},
		{"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all", scan.StatusPass, "SPF fail policy"},
		{"v=spf1 ~all", scan.StatusInfo, "SPF softfail policy"},
		{"v=spf1 +all", scan.StatusWarn, "Permissive SPF policy"},
		{"v=spf1 ?all", scan.StatusWarn, "Neutral SPF policy"},
		{"v=spf1", scan.StatusWarn, "Implicit neutral SPF policy"},
		{"v=spf1 redirect=a.example.com", scan.StatusInfo, "Delegated SPF policy"},
		{"v=spf1 a -all", scan.StatusInfo, "SPF fail policy"},
		{"v=spf1 unknown", scan.StatusFail, "Invalid SPF configuration"},
	} {
		t.Run(tc.record, func(t *testing.T) {
			lookup := func(name string) ([]string, error) {
				if name == "example.com" {
					return []string{tc.record}, nil
				}
				return []string{"v=spf1 -all"}, nil
			}
			spf := inspectSPF("example.com", lookup)
			if spf.State == scan.DNSRecordObserved {
				spf.Audit = auditSPF("example.com", &spf, lookup)
			}
			got := assessSPF(&spf)
			if got.Status != tc.status || got.Title != tc.title {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestAssessDMARC(t *testing.T) {
	for _, tc := range []struct {
		record           string
		status           scan.Status
		title, reporting string
	}{
		{"v=DMARC1; p=none", scan.StatusWarn, "No enforcement or reports", "absent"},
		{"v=DMARC1; p=none; rua=mailto:reports@example.com", scan.StatusWarn, "DMARC monitoring only", "configured"},
		{"v=DMARC1; p=none; rua=broken", scan.StatusWarn, "No enforcement or reports", "invalid"},
		{"v=DMARC1; p=reject; rua=mailto:reports@example.com", scan.StatusPass, "DMARC rejection requested", "configured"},
		{"v=DMARC1; p=quarantine; rua=mailto:reports@example.com", scan.StatusPass, "DMARC quarantine requested", "configured"},
		{"v=DMARC1; p=reject", scan.StatusWarn, "DMARC rejection requested", "absent"},
		{"v=DMARC1; p=reject; t=y; rua=mailto:reports@example.com", scan.StatusWarn, "DMARC quarantine requested", "configured"},
		{"v=DMARC1; p=reject; rua=mailto:reports@example.com,broken", scan.StatusWarn, "DMARC rejection requested", "configured"},
	} {
		t.Run(tc.record, func(t *testing.T) {
			dmarc := inspectDMARC("example.com", func(string) ([]string, error) { return []string{tc.record}, nil })
			got := assessDMARC(&dmarc)
			if got.Status != tc.status || got.Title != tc.title || dmarc.ReportingState != tc.reporting {
				t.Fatalf("%+v, %+v", got, dmarc)
			}
			if tc.reporting != "configured" && !strings.Contains(strings.Join(got.Recommendations, " "), "rua") {
				t.Fatal("missing reporting recommendation")
			}
		})
	}
}

func TestVerdictsForMissingAndUnavailableRecords(t *testing.T) {
	for _, state := range []scan.DNSRecordState{scan.DNSRecordAbsent, scan.DNSRecordUnavailable, scan.DNSRecordInvalid} {
		spf := scan.SPFReport{DNSRecord: scan.DNSRecord{State: state}}
		dmarc := scan.DMARCReport{DNSRecord: scan.DNSRecord{State: state}}
		for _, got := range []*scan.EmailAssessment{assessSPF(&spf), assessDMARC(&dmarc)} {
			if got.Status == scan.StatusPass || got.Title == "" || len(got.Recommendations) == 0 {
				t.Fatal(got)
			}
		}
	}
}

func TestScreenshotPoliciesHaveActionableVerdicts(t *testing.T) {
	got := Probe(t.Context(), "www.example.com", func(_ context.Context, name string) ([]string, error) {
		switch name {
		case "example.com":
			return []string{"v=spf1 include:mx.provider.example.com ~all"}, nil
		case "_dmarc.example.com":
			return []string{"v=DMARC1; p=none"}, nil
		case "mx.provider.example.com":
			return []string{"v=spf1 ip4:192.0.2.0/24 -all"}, nil
		default:
			t.Fatalf("unexpected lookup: %s", name)
			return nil, nil
		}
	})
	if got.SPF.Assessment.Status != scan.StatusInfo || !got.SPF.Audit.Complete || got.SPF.Audit.LookupTerms != 1 {
		t.Fatalf("%+v", got.SPF)
	}
	if got.DMARC.Assessment.Title != "No enforcement or reports" || got.DMARC.ReportingState != "absent" {
		t.Fatalf("%+v", got.DMARC)
	}
}
