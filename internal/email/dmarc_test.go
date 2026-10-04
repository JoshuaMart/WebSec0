package email

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestDMARCPolicyDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name, domain        string
		records             map[string][]string
		state               scan.DNSRecordState
		policy, source, tag string
		queries             int
		testing             bool
	}{
		{"direct", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=reject; sp=none"}}, scan.DNSRecordObserved, "reject", "example.com", "p", 1, false},
		{"absent", "example.com", nil, scan.DNSRecordAbsent, "", "", "", 2, false},
		{"unrelated", "example.com", map[string][]string{"example.com": {"v=DMARC10; p=reject", "v=dmarc1; p=reject", "p=reject; v=DMARC1"}}, scan.DNSRecordAbsent, "", "", "", 2, false},
		{"inherit sp", "tenant.github.io", map[string][]string{"github.io": {"v=DMARC1; p=none; sp=reject; psd=n"}}, scan.DNSRecordObserved, "reject", "github.io", "sp", 2, false},
		{"inherit p", "tenant.github.io", map[string][]string{"github.io": {"v=DMARC1; p=reject; psd=n"}}, scan.DNSRecordObserved, "reject", "github.io", "p", 2, false},
		{"highest ancestor", "a.b.example.com", map[string][]string{"b.example.com": {"v=DMARC1; p=none"}, "example.com": {"v=DMARC1; p=reject"}}, scan.DNSRecordObserved, "reject", "example.com", "p", 4, false},
		{"org boundary", "a.b.example.com", map[string][]string{"b.example.com": {"v=DMARC1; p=quarantine; psd=n"}, "example.com": {"v=DMARC1; p=reject"}}, scan.DNSRecordObserved, "quarantine", "b.example.com", "p", 2, false},
		{"PSD with org", "a.b.example.com", map[string][]string{"b.example.com": {"v=DMARC1; p=none"}, "example.com": {"v=DMARC1; p=reject; psd=y"}}, scan.DNSRecordObserved, "none", "b.example.com", "p", 3, false},
		{"PSD without org", "a.b.example.com", map[string][]string{"example.com": {"v=DMARC1; p=reject; psd=y"}}, scan.DNSRecordObserved, "reject", "example.com", "p", 3, false},
		{"PSD excludes deeper candidate", "a.b.c.example.com", map[string][]string{"b.c.example.com": {"v=DMARC1; p=none"}, "example.com": {"v=DMARC1; p=reject; psd=y"}}, scan.DNSRecordObserved, "reject", "example.com", "p", 4, false},
		{"duplicate records", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=reject", "v=DMARC1; p=none"}}, scan.DNSRecordInvalid, "", "", "", 2, false},
		{"duplicate discarded for parent", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=reject", "v=DMARC1; p=none"}, "com": {"v=DMARC1; p=quarantine; psd=y"}}, scan.DNSRecordObserved, "quarantine", "com", "p", 2, false},
		{"test reject", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=reject; t=y"}}, scan.DNSRecordObserved, "quarantine", "example.com", "p", 1, true},
		{"test quarantine", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=quarantine; t=y"}}, scan.DNSRecordObserved, "none", "example.com", "p", 1, true},
		{"test none", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=none; t=y"}}, scan.DNSRecordObserved, "none", "example.com", "p", 1, true},
		{"default p", "example.com", map[string][]string{"example.com": {"v=DMARC1; rua=mailto:reports@example.com"}}, scan.DNSRecordObserved, "none", "example.com", "p", 1, false},
		{"bad policy with reporting", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=typo; sp=reject; rua=mailto:reports@example.com!10m"}}, scan.DNSRecordObserved, "none", "example.com", "p", 1, false},
		{"bad policy", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=typo"}}, scan.DNSRecordInvalid, "", "", "", 1, false},
		{"bad reporting", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=typo; rua=mailto:@"}}, scan.DNSRecordInvalid, "", "", "", 1, false},
		{"duplicate tags", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=reject; p=none"}}, scan.DNSRecordInvalid, "", "", "", 2, false},
		{"version case and whitespace", "example.com", map[string][]string{"example.com": {"V = DMARC1; P = REJECT ;"}}, scan.DNSRecordObserved, "reject", "example.com", "p", 1, false},
		{"legacy pct", "example.com", map[string][]string{"example.com": {"v=DMARC1; p=reject; pct=0"}}, scan.DNSRecordObserved, "reject", "example.com", "p", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectDMARC(tc.domain, func(name string) ([]string, error) { return tc.records[strings.TrimPrefix(name, "_dmarc.")], nil })
			if got.State != tc.state || got.Policy != tc.policy || got.PolicyDomain != tc.source || got.PolicyTag != tc.tag || len(got.Queries) != tc.queries || got.Testing != tc.testing {
				t.Fatalf("got %+v", got)
			}
			if got.Inherited != (tc.source != "" && tc.source != tc.domain) {
				t.Fatal("wrong inheritance", got)
			}
		})
	}
}

func TestDMARCTreeLimit(t *testing.T) {
	domain := "a.b.c.d.e.f.g.h.i.j.mail.example.com"
	got := inspectDMARC(domain, func(string) ([]string, error) { return nil, nil })
	want := []string{"_dmarc." + domain, "_dmarc.g.h.i.j.mail.example.com", "_dmarc.h.i.j.mail.example.com", "_dmarc.i.j.mail.example.com", "_dmarc.j.mail.example.com", "_dmarc.mail.example.com", "_dmarc.example.com", "_dmarc.com"}
	if !reflect.DeepEqual(got.Queries, want) {
		t.Fatalf("%v", got.Queries)
	}
}

func TestDMARCInvalidPolicyDoesNotInheritEnforcement(t *testing.T) {
	for _, policy := range []string{"p=invalid", "p=reject; sp=invalid", "p=reject; np=invalid"} {
		for _, reporting := range []string{"", "; rua=broken", "; rua=mailto:reports@example.com"} {
			t.Run(policy+reporting, func(t *testing.T) {
				record := "v=DMARC1; " + policy + reporting
				got := inspectDMARC("tenant.github.io", func(name string) ([]string, error) {
					if name == "_dmarc.tenant.github.io" {
						return []string{record}, nil
					}
					t.Fatalf("unexpected parent lookup: %s", name)
					return nil, nil
				})
				if got.Inherited || !reflect.DeepEqual(got.Records, []string{record}) || len(got.Warnings) == 0 {
					t.Fatalf("missing original policy diagnostics: %+v", got)
				}
				if strings.Contains(reporting, "mailto:") {
					if got.State != scan.DNSRecordObserved || got.Policy != "none" {
						t.Fatalf("reporting fallback: %+v", got)
					}
				} else if got.State != scan.DNSRecordInvalid || got.Policy != "" || assessDMARC(&got).Status != scan.StatusFail {
					t.Fatalf("unusable policy: %+v", got)
				}
			})
		}
	}
}

func TestDMARCUnknownTagsDoNotInvalidatePolicy(t *testing.T) {
	got := inspectDMARC("example.com", func(string) ([]string, error) {
		return []string{"v=DMARC1; p=reject; x=one; x=two; rua=mailto:reports@example.com"}, nil
	})
	if got.State != scan.DNSRecordObserved || got.Policy != "reject" || len(got.Warnings) != 0 || assessDMARC(&got).Status != scan.StatusPass {
		t.Fatalf("unknown extensions changed the verdict: %+v", got)
	}
}

func TestDMARCErrorCannotEstablishPolicy(t *testing.T) {
	got := inspectDMARC("a.example.com", func(name string) ([]string, error) {
		switch name {
		case "_dmarc.example.com":
			return []string{"v=DMARC1; p=reject"}, nil
		case "_dmarc.com":
			return nil, errors.New("SERVFAIL")
		default:
			return nil, nil
		}
	})
	if got.State != scan.DNSRecordUnavailable || got.Policy != "" || got.PolicyDomain != "" {
		t.Fatalf("%+v", got)
	}
}

func TestDMARCIgnoresMalformedOptionalTags(t *testing.T) {
	p := parseDMARC("v=DMARC1; p=reject; future-extension; rua=; t=; x=bad\tvalue", "example.com")
	if p == nil || p.tags["p"] != "reject" || len(p.warnings) != 1 {
		t.Fatalf("%+v", p)
	}
	p = parseDMARC("v=DMARC1; p=; rua=mailto:reports@example.com", "example.com")
	if p == nil || p.tags["p"] != "none" {
		t.Fatalf("%+v", p)
	}
}

func TestDMARCWarnings(t *testing.T) {
	p := parseDMARC("v=DMARC1; p=reject; t=invalid; psd=invalid; adkim=invalid; aspf=invalid; pct=0", "example.com")
	if p == nil || len(p.warnings) != 5 || p.tags["t"] != "n" || p.tags["psd"] != "u" {
		t.Fatalf("%+v", p)
	}
}

func TestDMARCDiagnosticsBounded(t *testing.T) {
	p := parseDMARC("v=DMARC1; p=reject;"+strings.Repeat(";", 60000), "example.com")
	if p == nil || len(p.warnings) != 1 {
		t.Fatal("unbounded diagnostics")
	}
}

func TestDMARCReportingURIs(t *testing.T) {
	for _, tc := range []struct {
		value   string
		count   int
		invalid bool
	}{
		{"mailto:reports@example.com", 1, false},
		{"mailto:reports@example.com!10m", 1, false},
		{"mailto:reports%40example.com", 1, false},
		{"mailto:%22not%40me%22@example.org", 1, false},
		{"mailto:%22oh%5C%5Cno%22@example.org", 1, false},
		{"mailto:%22reports%22@example.org", 1, false},
		{"mailto:%22a%20b%22@example.org", 1, false},
		{"mailto:%22a(b)%22@example.org", 1, false},
		{"mailto:Reports%20%3Creports@example.org%3E", 0, true},
		{"mailto:%3Creports@example.org%3E", 0, true},
		{"mailto:reports@example.org(comment)", 0, true},
		{"mailto:reports(comment)@example.org", 0, true},
		{"mailto:%22unterminated@example.org", 0, true},
		{"mailto:%22a%0Ab%22@example.org", 0, true},
		{"mailto:a@example.com, mailto:b@example.com", 2, false},
		{"https://reports.example.com/collect", 1, false},
		{"mailto:reports@example.com,broken", 1, true},
		{"mailto:a@b@c", 0, true},
		{"mailto:@", 0, true},
		{"mailto:", 0, true},
		{"https:", 0, true},
		{"", 0, true},
		{"mailto:a%0A@example.com", 0, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			uris, invalid := reportingURIs(tc.value)
			if len(uris) != tc.count || invalid != tc.invalid {
				t.Fatalf("%v %v", uris, invalid)
			}
		})
	}
}
