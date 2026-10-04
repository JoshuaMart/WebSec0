package email

import (
	"reflect"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestSPF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []string
		state   scan.DNSRecordState
		all     string
		warning string
	}{
		{"absent", nil, scan.DNSRecordAbsent, "", ""},
		{"unrelated", []string{"verification=abc", "v=spf10 -all"}, scan.DNSRecordAbsent, "", ""},
		{"deny", []string{"v=spf1 -all"}, scan.DNSRecordObserved, "-all", ""},
		{"softfail", []string{"v=spf1 include:_spf.example.com ~all"}, scan.DNSRecordObserved, "~all", ""},
		{"neutral", []string{"v=spf1 ?all"}, scan.DNSRecordObserved, "?all", ""},
		{"permissive", []string{"V=SPF1 ALL"}, scan.DNSRecordObserved, "+all", "+all"},
		{"first all", []string{"v=spf1 -all +all"}, scan.DNSRecordObserved, "-all", ""},
		{"empty policy", []string{"v=spf1"}, scan.DNSRecordObserved, "", ""},
		{"duplicate", []string{"v=spf1 -all", "v=spf1 ~all"}, scan.DNSRecordInvalid, "", "Multiple SPF"},
		{"addresses", []string{"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:example.com/24//64 -all"}, scan.DNSRecordObserved, "-all", ""},
		{"bad IPv4", []string{"v=spf1 ip4:192.0.2.1/33 -all"}, scan.DNSRecordInvalid, "", "invalid"},
		{"bad family", []string{"v=spf1 ip4:2001:db8::1"}, scan.DNSRecordInvalid, "", "invalid"},
		{"zone", []string{"v=spf1 ip6:fe80::1%eth0"}, scan.DNSRecordInvalid, "", "invalid"},
		{"redirect", []string{"v=spf1 redirect=example.net"}, scan.DNSRecordObserved, "", ""},
		{"ignored redirect", []string{"v=spf1 -all redirect=example.net"}, scan.DNSRecordObserved, "-all", "ignored"},
		{"duplicate redirect", []string{"v=spf1 redirect=a.com REDIRECT=b.com"}, scan.DNSRecordInvalid, "", "invalid"},
		{"unknown modifier", []string{"v=spf1 future=value -all"}, scan.DNSRecordObserved, "-all", ""},
		{"unknown mechanism", []string{"v=spf1 future:value -all"}, scan.DNSRecordInvalid, "", "invalid"},
		{"missing argument", []string{"v=spf1 include:"}, scan.DNSRecordInvalid, "", "invalid"},
		{"ptr", []string{"v=spf1 ptr -all"}, scan.DNSRecordObserved, "-all", "discouraged"},
		{"macro equals", []string{"v=spf1 exists:%{l=}.example.com -all"}, scan.DNSRecordObserved, "-all", ""},
		{"macro slash", []string{"v=spf1 a:%{l/}.example.com/24//64 -all"}, scan.DNSRecordObserved, "-all", ""},
		{"macro domain", []string{"v=spf1 include:%{d} -all"}, scan.DNSRecordObserved, "-all", ""},
		{"bad macro CIDR", []string{"v=spf1 a:%{d}/33"}, scan.DNSRecordInvalid, "", "invalid"},
		{"bad macro", []string{"v=spf1 exists:%{bad}.example.com"}, scan.DNSRecordInvalid, "", "invalid"},
		{"unclosed macro", []string{"v=spf1 include:%{d"}, scan.DNSRecordInvalid, "", "invalid"},
		{"literal brace", []string{"v=spf1 include:literal}"}, scan.DNSRecordInvalid, "", "invalid"},
		{"escaped macro", []string{"v=spf1 include:%%{d}"}, scan.DNSRecordInvalid, "", "invalid"},
		{"leading zero CIDR", []string{"v=spf1 mx/024"}, scan.DNSRecordInvalid, "", "invalid"},
		{"empty CIDR", []string{"v=spf1 a/"}, scan.DNSRecordInvalid, "", "invalid"},
		{"v6 only CIDR", []string{"v=spf1 a//64 -all"}, scan.DNSRecordObserved, "-all", ""},
		{"qualifier only", []string{"v=spf1 -"}, scan.DNSRecordInvalid, "", "invalid"},
		{"control byte", []string{"v=spf1 -all\n"}, scan.DNSRecordInvalid, "", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := inspectSPF("example.com", func(string) ([]string, error) { return tc.records, nil })
			if got.State != tc.state || got.All != tc.all {
				t.Fatalf("got %+v", got)
			}
			if tc.warning != "" && !strings.Contains(strings.Join(got.Warnings, " "), tc.warning) {
				t.Fatalf("missing warning %q: %+v", tc.warning, got)
			}
			if tc.warning == "" && len(got.Warnings) != 0 {
				t.Fatal(got.Warnings)
			}
		})
	}
}

func TestSPFDeclaredDependencies(t *testing.T) {
	got := inspectSPF("example.com", func(string) ([]string, error) {
		return []string{"v=spf1 include:a.com INCLUDE:b.com redirect=c.com"}, nil
	})
	if !reflect.DeepEqual(got.Includes, []string{"a.com", "b.com"}) || got.Redirect != "c.com" {
		t.Fatalf("%+v", got)
	}
}

func TestSPFDiagnosticsBounded(t *testing.T) {
	got := inspectSPF("example.com", func(string) ([]string, error) {
		return []string{"v=spf1 " + strings.Repeat("ptr ", 10000) + "-all"}, nil
	})
	if got.State != scan.DNSRecordObserved || len(got.Warnings) != 1 {
		t.Fatal("unbounded diagnostics")
	}
}
