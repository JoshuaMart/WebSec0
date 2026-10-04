package email

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/catalog"
	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestDomain(t *testing.T) {
	for host, want := range map[string]string{
		"example.com": "example.com", "www.example.com": "example.com",
		"WWW.Example.COM.": "example.com", "example.co.uk": "example.co.uk",
		"www.example.co.uk": "example.co.uk", "tenant.github.io": "tenant.github.io",
		"www.tenant.github.io": "tenant.github.io", "www.com": "www.com",
		"xn--bcher-kva.de": "xn--bcher-kva.de",
		"api.example.com":  "", "www.api.example.com": "", "co.uk": "",
		"github.io": "", "localhost": "", "example.test": "", "127.0.0.1": "", "": "",
	} {
		t.Run(host, func(t *testing.T) {
			if got := Domain(host); got != want {
				t.Fatalf("Domain(%q) = %q, want %q", host, got, want)
			}
		})
	}
}

func TestProbeScope(t *testing.T) {
	var queries []string
	lookup := func(ctx context.Context, name string) ([]string, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > lookupTimeout {
			t.Fatal("DNS lookup lacks bounded deadline")
		}
		queries = append(queries, name)
		switch name {
		case "example.com":
			return []string{"v=spf1 include:mail.other.com redirect=other.com -all"}, nil
		case "mail.other.com":
			return []string{"v=spf1 ip4:192.0.2.0/24 -all"}, nil
		case "_dmarc.example.com":
			return []string{"v=DMARC1; p=reject; rua=mailto:reports@other.com"}, nil
		default:
			t.Fatalf("unexpected DNS lookup: %s", name)
			return nil, nil
		}
	}
	for _, host := range []string{"example.com", "www.example.com"} {
		queries = nil
		result := Probe(t.Context(), host, lookup)
		if result == nil || result.Domain != "example.com" || result.SPF.All != "-all" || result.DMARC.Policy != "reject" {
			t.Fatalf("unexpected report: %+v", result)
		}
		if !reflect.DeepEqual(queries, []string{"example.com", "_dmarc.example.com", "mail.other.com"}) {
			t.Fatal(queries)
		}
	}
	queries = nil
	if Probe(t.Context(), "api.example.com", lookup) != nil || len(queries) != 0 {
		t.Fatal("subdomain must be unassessed without DNS lookups")
	}
}

func TestLookupRecords(t *testing.T) {
	for _, tc := range []struct {
		name      string
		records   []string
		err       error
		wantError bool
	}{
		{"nodata", nil, nil, false},
		{"nxdomain", nil, &net.DNSError{IsNotFound: true}, false},
		{"timeout", nil, &net.DNSError{IsTimeout: true}, true},
		{"servfail", nil, &net.DNSError{IsTemporary: true}, true},
		{"ambiguous", nil, &net.DNSError{IsNotFound: true, IsTimeout: true}, true},
		{"other", nil, errors.New("resolver failure"), true},
		{"count limit", make([]string, maxTXTRecords+1), nil, true},
		{"size limit", []string{strings.Repeat("x", maxTXTBytes+1)}, nil, true},
		{"at limits", []string{strings.Repeat("x", maxTXTBytes)}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := lookupRecords(t.Context(), "example.com", func(context.Context, string) ([]string, error) { return tc.records, tc.err })
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v", err)
			}
			if tc.err != nil && !tc.wantError && len(records) != 0 {
				t.Fatal(records)
			}
		})
	}
}

func TestProbeCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result := Probe(ctx, "example.com", func(context.Context, string) ([]string, error) { t.Fatal("lookup after cancellation"); return nil, nil })
	if result.SPF.State != scan.DNSRecordUnavailable || result.DMARC.State != scan.DNSRecordUnavailable {
		t.Fatalf("%+v", result)
	}
	if len(result.SPF.Records) != 0 || result.DMARC.Policy != "" {
		t.Fatal("cancelled probe claims a policy")
	}
}

func TestLookupCancellationDiscardsLateAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	records, err := lookupRecords(ctx, "example.com", func(context.Context, string) ([]string, error) {
		cancel()
		return []string{"v=spf1 -all"}, nil
	})
	if !errors.Is(err, context.Canceled) || records != nil {
		t.Fatalf("%v, %v", records, err)
	}
}

func TestEmailIDsInCatalog(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"email.spf", "email.dmarc"} {
		found := false
		for _, check := range c.Checks {
			if check.ID == id {
				found = true
				if check.ScoreImpact != "none" {
					t.Fatalf("%s affects grades", id)
				}
			}
		}
		if !found {
			t.Fatalf("%s missing from catalog", id)
		}
	}
}

func FuzzPolicyParsers(f *testing.F) {
	for _, record := range []string{"v=spf1 -all", "v=spf1 exists:%{l=}.example.com -all", "v=DMARC1; p=reject; t=y", "v=DMARC1; p=none; rua=mailto:a@example.com"} {
		f.Add(record)
	}
	f.Fuzz(func(t *testing.T, record string) {
		if len(record) > maxTXTBytes {
			t.Skip()
		}
		lookup := func(string) ([]string, error) { return []string{record}, nil }
		spf := inspectSPF("example.com", lookup)
		if spf.State == scan.DNSRecordInvalid && (spf.All != "" || spf.Redirect != "" || len(spf.Includes) != 0) {
			t.Fatal("invalid SPF exposes parsed policy")
		}
		_ = inspectDMARC("example.com", lookup)
	})
}

func TestProbeIndependentObservations(t *testing.T) {
	for _, failed := range []string{"example.com", "_dmarc.example.com"} {
		t.Run(failed, func(t *testing.T) {
			got := Probe(t.Context(), "example.com", func(_ context.Context, name string) ([]string, error) {
				if name == failed {
					return nil, &net.DNSError{IsTemporary: true}
				}
				if name == "example.com" {
					return []string{"v=spf1 -all"}, nil
				}
				return []string{"v=DMARC1; p=reject"}, nil
			})
			if failed == "example.com" {
				if got.SPF.State != scan.DNSRecordUnavailable || got.DMARC.State != scan.DNSRecordObserved {
					t.Fatalf("%+v", got)
				}
			} else if got.SPF.State != scan.DNSRecordObserved || got.DMARC.State != scan.DNSRecordUnavailable {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestProbeNXDOMAINIsAbsence(t *testing.T) {
	got := Probe(t.Context(), "example.com", func(context.Context, string) ([]string, error) { return nil, &net.DNSError{IsNotFound: true} })
	if got.SPF.State != scan.DNSRecordAbsent || got.DMARC.State != scan.DNSRecordAbsent {
		t.Fatalf("%+v", got)
	}
}

func BenchmarkProbeFixtures(b *testing.B) {
	lookup := func(_ context.Context, name string) ([]string, error) {
		if name == "example.com" {
			return []string{"v=spf1 include:_spf.example.com ip4:192.0.2.0/24 -all"}, nil
		}
		if name == "_spf.example.com" {
			return []string{"v=spf1 ip6:2001:db8::/32 -all"}, nil
		}
		return []string{"v=DMARC1; p=reject; rua=mailto:reports@example.com"}, nil
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = Probe(b.Context(), "www.example.com", lookup)
	}
}
