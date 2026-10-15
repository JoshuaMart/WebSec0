package scanner

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"

	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/safehttp"
)

// loopbackResolver pins every validated host to the httptest server, which
// the production resolver would refuse.
type loopbackResolver struct {
	port     int
	resolved []safehttp.Validated
}

func (r *loopbackResolver) Resolve(_ context.Context, v *safehttp.Validated) (*safehttp.Target, error) {
	r.resolved = append(r.resolved, *v)
	return safehttp.NewTarget(v.Scheme, v.Host, r.port, netip.MustParseAddr("127.0.0.1"))
}

func TestFetchIssuer(t *testing.T) {
	issuer := []byte("issuer-der")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "ca.example.test" {
			t.Errorf("Host header %q, want ca.example.test", r.Host)
		}
		switch r.URL.Path {
		case "/issuer.crt":
			_, _ = w.Write(issuer)
		case "/redirect.crt":
			http.Redirect(w, r, "/issuer.crt", http.StatusFound)
		case "/large.crt":
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxIssuerBytes+1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	for _, tc := range []struct {
		name     string
		url      string
		want     []byte
		wantErr  error
		resolved bool
	}{
		{"ok", "http://ca.example.test/issuer.crt", issuer, nil, true},
		{"not_found", "http://ca.example.test/missing.crt", nil, nil, true},
		{"redirect_not_followed", "http://ca.example.test/redirect.crt", nil, nil, true},
		{"body_cap", "http://ca.example.test/large.crt", nil, safehttp.ErrBodyTooLarge, true},
		{"custom_port", "http://ca.example.test:8080/issuer.crt", nil, safehttp.ErrCustomPortBlocked, false},
		{"https_on_http_port", "https://ca.example.test:80/issuer.crt", nil, safehttp.ErrCustomPortBlocked, false},
		{"scheme", "ldap://ca.example.test/issuer.crt", nil, safehttp.ErrInvalidScheme, false},
		{"ip_literal", "http://127.0.0.1/issuer.crt", nil, safehttp.ErrIPLiteral, false},
		{"userinfo", "http://user@ca.example.test/issuer.crt", nil, safehttp.ErrUserInfo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &loopbackResolver{port: port}
			s := New(config.Defaults())
			s.resolver = resolver
			got, err := s.fetchIssuer(t.Context(), tc.url)
			switch {
			case tc.want != nil:
				if err != nil || !bytes.Equal(got, tc.want) {
					t.Fatalf("got %q, %v; want %q", got, err, tc.want)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err %v, want %v", err, tc.wantErr)
				}
			case err == nil:
				t.Fatalf("expected an error, got body %q", got)
			}
			if (len(resolver.resolved) > 0) != tc.resolved {
				t.Fatalf("resolved %v, want resolution %v", resolver.resolved, tc.resolved)
			}
		})
	}
}

func TestFetchIssuer_UsesScanPolicy(t *testing.T) {
	s := New(config.Defaults())
	s.resolver = &safehttp.Resolver{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.1")}, nil
		},
	}
	if _, err := s.fetchIssuer(t.Context(), "http://ca.example.test/issuer.crt"); !errors.Is(err, safehttp.ErrPrivateTargetBlocked) {
		t.Fatalf("err %v, want ErrPrivateTargetBlocked", err)
	}
}
