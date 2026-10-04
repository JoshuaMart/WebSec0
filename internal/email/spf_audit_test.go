package email

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestSPFDependencyAudit(t *testing.T) {
	for _, tc := range []struct {
		name, root   string
		records      map[string][]string
		complete     bool
		terms        int
		queries      []string
		issue, limit string
	}{
		{"literal", "v=spf1 ip4:192.0.2.0/24 -all", nil, true, 0, []string{"example.com"}, "", ""},
		{"include", "v=spf1 include:a.example.com ~all", map[string][]string{"a.example.com": {"v=spf1 ip6:2001:db8::/32 -all"}}, true, 1, []string{"example.com", "a.example.com"}, "", ""},
		{"redirect", "v=spf1 redirect=a.example.com", map[string][]string{"a.example.com": {"v=spf1 include:b.example.com -all"}, "b.example.com": {"v=spf1 -all"}}, true, 2, []string{"example.com", "a.example.com", "b.example.com"}, "", ""},
		{"ignored terms", "v=spf1 redirect:a.example.com", nil, false, 0, nil, "", ""},
		{"after all", "v=spf1 -all include:a.example.com redirect=b.example.com", nil, true, 0, []string{"example.com"}, "", ""},
		{"ignored redirect before all", "v=spf1 redirect=a.example.com -all", nil, true, 0, []string{"example.com"}, "", ""},
		{"missing", "v=spf1 include:a.example.com -all", nil, false, 1, []string{"example.com", "a.example.com"}, "No SPF policy", ""},
		{"malformed", "v=spf1 include:a.example.com -all", map[string][]string{"a.example.com": {"v=spf1 bad:term"}}, false, 1, []string{"example.com", "a.example.com"}, "Invalid SPF policy", ""},
		{"duplicate", "v=spf1 include:a.example.com -all", map[string][]string{"a.example.com": {"v=spf1 -all", "v=spf1 ~all"}}, false, 1, []string{"example.com", "a.example.com"}, "Invalid SPF policy", ""},
		{"cycle", "v=spf1 include:a.example.com -all", map[string][]string{"a.example.com": {"v=spf1 redirect=EXAMPLE.COM."}}, false, 2, []string{"example.com", "a.example.com"}, "Circular SPF dependency", ""},
		{"macro", "v=spf1 include:%{d}.example.com -all", nil, false, 1, []string{"example.com"}, "", "Macro-based"},
		{"bad name", "v=spf1 include:a..example.com -all", nil, false, 1, []string{"example.com"}, "not a usable DNS name", ""},
		{"address terms", "v=spf1 a mx ptr exists:a.example.com -all", nil, false, 4, []string{"example.com"}, "", "Address mechanisms"},
		{"repeat counts not queries", "v=spf1 include:a.example.com include:A.EXAMPLE.COM. -all", map[string][]string{"a.example.com": {"v=spf1 -all"}}, true, 2, []string{"example.com", "a.example.com"}, "", ""},
		{"shared dependency not a cycle", "v=spf1 include:a.example.com include:b.example.com -all", map[string][]string{"a.example.com": {"v=spf1 include:c.example.com -all"}, "b.example.com": {"v=spf1 include:c.example.com -all"}, "c.example.com": {"v=spf1 -all"}}, true, 4, []string{"example.com", "a.example.com", "c.example.com", "b.example.com"}, "", ""},
		{"weak child", "v=spf1 include:a.example.com -all", map[string][]string{"a.example.com": {"v=spf1 +all"}}, false, 1, []string{"example.com", "a.example.com"}, "", "policy warnings"},
		{"permissive child range", "v=spf1 include:a.example.com -all", map[string][]string{"a.example.com": {"v=spf1 ip4:0.0.0.0/0 -all"}}, false, 1, []string{"example.com", "a.example.com"}, "", "positive /0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			lookup := func(name string) ([]string, error) {
				calls = append(calls, name)
				if name == "example.com" {
					return []string{tc.root}, nil
				}
				return tc.records[name], nil
			}
			root := inspectSPF("example.com", lookup)
			if tc.queries == nil {
				if root.State != scan.DNSRecordInvalid {
					t.Fatal("expected malformed root")
				}
				return
			}
			got := auditSPF("example.com", &root, lookup)
			if got.Complete != tc.complete || got.LookupTerms != tc.terms || !reflect.DeepEqual(got.Queries, tc.queries) || !reflect.DeepEqual(calls, tc.queries) {
				t.Fatalf("%+v; calls=%v", got, calls)
			}
			if tc.issue != "" && !strings.Contains(strings.Join(got.Issues, " "), tc.issue) {
				t.Fatalf("missing issue %q: %+v", tc.issue, got)
			}
			if tc.limit != "" && !strings.Contains(strings.Join(got.Limitations, " "), tc.limit) {
				t.Fatalf("missing limitation %q: %+v", tc.limit, got)
			}
		})
	}
}

func TestSPFTermBudget(t *testing.T) {
	for _, terms := range []int{10, 11, 1000} {
		t.Run(fmt.Sprint(terms), func(t *testing.T) {
			calls := 0
			root := inspectSPF("example.com", func(string) ([]string, error) {
				return []string{"v=spf1 " + strings.Repeat("include:a.example.com ", terms) + "-all"}, nil
			})
			audit := auditSPF("example.com", &root, func(string) ([]string, error) { calls++; return []string{"v=spf1 -all"}, nil })
			if calls != 1 || audit.LookupTerms != min(terms, 11) || audit.LookupLimitExceeded != (terms > 10) || audit.Complete != (terms <= 10) {
				t.Fatalf("%+v; calls=%d", audit, calls)
			}
			if len(audit.Issues) != 0 {
				t.Fatal("a potential lookup overflow must not be reported as proven invalidity")
			}
		})
	}
}

func TestSPFDeepChainIsBounded(t *testing.T) {
	calls := 0
	root := inspectSPF("example.com", func(string) ([]string, error) { return []string{"v=spf1 redirect=a1.example.com"}, nil })
	audit := auditSPF("example.com", &root, func(string) ([]string, error) {
		calls++
		return []string{fmt.Sprintf("v=spf1 redirect=a%d.example.com", calls+1)}, nil
	})
	if calls != 10 || audit.LookupTerms != 11 || !audit.LookupLimitExceeded {
		t.Fatalf("%+v; calls=%d", audit, calls)
	}
}

func TestSPFDNSFailureKeepsRootObservation(t *testing.T) {
	got := Probe(t.Context(), "example.com", func(_ context.Context, name string) ([]string, error) {
		switch name {
		case "example.com":
			return []string{"v=spf1 include:a.example.com -all"}, nil
		case "_dmarc.example.com":
			return []string{"v=DMARC1; p=reject"}, nil
		default:
			return nil, errors.New("timeout")
		}
	})
	if got.SPF.State != scan.DNSRecordObserved || got.SPF.Audit.Complete || len(got.SPF.Audit.Issues) != 0 || got.SPF.Assessment.Status == scan.StatusPass {
		t.Fatalf("%+v", got.SPF)
	}
	if got.DMARC.Policy != "reject" {
		t.Fatal("SPF dependencies obscured DMARC")
	}
}

func TestSPFDeadlinePreservesBothRootPolicies(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got := Probe(ctx, "example.com", func(_ context.Context, name string) ([]string, error) {
		switch name {
		case "example.com":
			return []string{"v=spf1 include:a.example.com -all"}, nil
		case "_dmarc.example.com":
			return []string{"v=DMARC1; p=none"}, nil
		default:
			cancel()
			return nil, context.Canceled
		}
	})
	if got.SPF.Audit.Complete || got.DMARC.State != scan.DNSRecordObserved {
		t.Fatalf("%+v", got)
	}
}

func FuzzSPFAudit(f *testing.F) {
	for _, record := range []string{"v=spf1 -all", "v=spf1 include:a.example.com -all", "v=spf1 a mx -all", "v=spf1 redirect=a.example.com"} {
		f.Add(record)
	}
	f.Fuzz(func(t *testing.T, record string) {
		if len(record) > maxTXTBytes {
			t.Skip()
		}
		root := inspectSPF("example.com", func(string) ([]string, error) { return []string{record}, nil })
		if root.State != scan.DNSRecordObserved {
			return
		}
		calls := 0
		audit := auditSPF("example.com", &root, func(string) ([]string, error) { calls++; return []string{record}, nil })
		if calls > 10 || audit.LookupTerms > 11 {
			t.Fatalf("unbounded traversal: %+v, %d", audit, calls)
		}
	})
}
