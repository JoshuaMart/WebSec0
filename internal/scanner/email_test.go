package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestRunEmailScopeAndCache(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	for _, parallel := range []bool{false, true} {
		for _, host := range []string{"example.com", "www.example.com", "api.example.com", "www.api.example.com"} {
			t.Run(host+"/"+map[bool]string{false: "sequential", true: "parallel"}[parallel], func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Scan.ParallelProbes = parallel
				s := New(cfg)
				target := targetFor(t, srv)
				target.Host = host
				s.resolver = &localResolver{target: target}
				var calls int
				s.lookupTXT = func(_ context.Context, name string) ([]string, error) {
					calls++
					switch name {
					case "example.com":
						return []string{"v=spf1 -all"}, nil
					case "_dmarc.example.com":
						return []string{"v=DMARC1; p=reject"}, nil
					default:
						return nil, errors.New("unexpected lookup")
					}
				}
				result, err := s.Run(t.Context(), Request{Host: host})
				if err != nil {
					t.Fatal(err)
				}
				eligible := host == "example.com" || host == "www.example.com"
				if eligible {
					if result.Email == nil || result.Email.Domain != "example.com" || result.Email.SPF.State != scan.DNSRecordObserved || result.Email.DMARC.Policy != "reject" || calls != 2 {
						t.Fatalf("%+v; %d lookups", result.Email, calls)
					}
				} else if result.Email != nil || calls != 0 {
					t.Fatal("subdomain was assessed", result.Email, calls)
				}
				raw, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), `"email":`) != eligible {
					t.Fatalf("incorrect email presence: %s", raw)
				}
				var decoded scan.Result
				if err := json.Unmarshal(raw, &decoded); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(decoded.Email, result.Email) {
					t.Fatal("email JSON round trip changed report")
				}
				previousCalls := calls
				cached, err := s.Run(t.Context(), Request{Host: host})
				if err != nil || cached != result || calls != previousCalls {
					t.Fatal("email scan bypassed cache")
				}
				if !eligible {
					return
				}
				s.lookupTXT = func(context.Context, string) ([]string, error) { return nil, errors.New("DNS unavailable") }
				fresh, err := s.Run(t.Context(), Request{Host: host, Fresh: true})
				if err != nil {
					t.Fatal(err)
				}
				if fresh.Email.SPF.State != scan.DNSRecordUnavailable || fresh.Email.DMARC.State != scan.DNSRecordUnavailable {
					t.Fatalf("%+v", fresh.Email)
				}
				if fresh.TLS.Grade != result.TLS.Grade || fresh.TLS.Scores != result.TLS.Scores || fresh.Headers.Grade != result.Headers.Grade || fresh.Headers.Score != result.Headers.Score {
					t.Fatal("email observations affected TLS/HTTP scores")
				}
			})
		}
	}
}

func TestRunEmailRequiresTargetGate(t *testing.T) {
	s := New(config.Defaults())
	s.resolver = &safehttp.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	s.lookupTXT = func(context.Context, string) ([]string, error) {
		t.Error("TXT lookup before target gate")
		return nil, nil
	}
	if _, err := s.Run(t.Context(), Request{Host: "example.com"}); err == nil {
		t.Fatal("blocked web target was accepted")
	}
}
