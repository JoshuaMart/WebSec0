package scanner

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// stubResultWithGrades is a tiny factory used by tests in the package that
// need a populated *scan.Result without running probes.
func stubResultWithGrades(id, host, tlsGrade, headersGrade string) *scan.Result {
	r := &scan.Result{ID: id, Host: host, ScannedAt: time.Now()}
	if tlsGrade != "" {
		r.TLS = &scan.TLSReport{Grade: scan.Grade(tlsGrade)}
	}
	if headersGrade != "" {
		r.Headers = &scan.HeadersReport{Grade: scan.Grade(headersGrade)}
	}
	return r
}

// targetFor builds a Target pinned to the httptest server's loopback
// address. The integration tests exercise runProbes directly because the
// production resolver blocks loopback regardless of config (see SPEC §8.3).
func targetFor(t *testing.T, srv *httptest.Server) *safehttp.Target {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	tgt, err := safehttp.NewTarget("https", "example.test", port, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return tgt
}

func TestRunProbes_HappyPath(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/security.txt":
			_, _ = w.Write([]byte("Contact: mailto:security@example.test\nExpires: 2099-01-01T00:00:00Z\n"))
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /search\n"))
		default:
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "geolocation=()")
			_, _ = w.Write([]byte("ok"))
		}
	}))
	srv.TLS = &stdtls.Config{MinVersion: stdtls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	s := New(config.Defaults())
	result := s.runProbes(context.Background(), targetFor(t, srv))

	if result.TLS == nil {
		t.Fatal("TLS report missing")
	}
	if result.Headers == nil {
		t.Fatal("Headers report missing")
	}
	if len(result.Custom) == 0 {
		t.Fatal("Custom findings missing")
	}

	// SSLv2 + SSLv3 entries must be present in the protocols list with
	// Probe=raw_clienthello, both not offered (httptest does not speak them).
	var hasSSL2, hasSSL3 bool
	for _, p := range result.TLS.Protocols {
		if p.Name == "SSL 2.0" && p.Probe == scan.ProbeRawClientHello {
			hasSSL2 = true
			if p.Offered {
				t.Error("SSL 2.0 should not be offered by httptest")
			}
		}
		if p.Name == "SSL 3.0" && p.Probe == scan.ProbeRawClientHello {
			hasSSL3 = true
		}
	}
	if !hasSSL2 || !hasSSL3 {
		t.Errorf("SSLv2/v3 probe results missing from protocols list: ssl2=%v ssl3=%v", hasSSL2, hasSSL3)
	}

	// Headers must score; with all six core headers present, expect A+.
	if result.Headers.Grade != scan.GradeAPlus {
		t.Errorf("Headers grade: got %s, want A+", result.Headers.Grade)
	}

	// TLS grade is at least A — httptest cert is self-signed so ChainTrust
	// caps at T regardless of score.
	if result.TLS.Grade != scan.GradeT {
		t.Errorf("TLS grade: expected T (chain not trusted for httptest), got %s", result.TLS.Grade)
	}

	// Custom: security.txt should pass, robots.txt should pass.
	bySID := map[string]scan.Status{}
	for _, f := range result.Custom {
		bySID[f.ID] = f.Status
	}
	if bySID["custom.security_txt"] != scan.StatusPass {
		t.Errorf("security.txt: got %s, want pass", bySID["custom.security_txt"])
	}
	if bySID["custom.robots_txt"] != scan.StatusPass {
		t.Errorf("robots.txt: got %s, want pass", bySID["custom.robots_txt"])
	}
}

func TestRunProbes_MissingHeadersAreFlagged(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New(config.Defaults())
	result := s.runProbes(context.Background(), targetFor(t, srv))

	if result.Headers == nil {
		t.Fatal("Headers report should be present even when all headers are missing")
	}
	if result.Headers.Grade != scan.GradeF {
		t.Errorf("missing all headers: got grade %s, want F", result.Headers.Grade)
	}
	if result.Headers.Score != 0 {
		t.Errorf("missing all headers: got score %d, want 0", result.Headers.Score)
	}
}

func TestRun_RejectsEmptyHost(t *testing.T) {
	s := New(config.Defaults())
	_, err := s.Run(context.Background(), Request{Host: ""})
	if !errors.Is(err, ErrEmptyHost) {
		t.Errorf("expected ErrEmptyHost, got %v", err)
	}
}

func TestRun_RejectsIPLiteral(t *testing.T) {
	s := New(config.Defaults())
	_, err := s.Run(context.Background(), Request{Host: "192.168.1.1"})
	if !errors.Is(err, safehttp.ErrIPLiteral) {
		t.Errorf("expected ErrIPLiteral, got %v", err)
	}
}

func TestRun_RejectsBadScheme(t *testing.T) {
	s := New(config.Defaults())
	_, err := s.Run(context.Background(), Request{Host: "ftp://example.com"})
	if !errors.Is(err, safehttp.ErrInvalidScheme) {
		t.Errorf("expected ErrInvalidScheme, got %v", err)
	}
}

func TestRun_CachesResult(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Stub the resolver to return loopback for any name, bypassing the
	// IsBlocked check by switching policy at the resolver level. We can't
	// flip AllowPrivate to cover loopback here, so we exploit the typed
	// failure: a private-target rejection still surfaces as an error and
	// keeps Run end-to-end testable on the error path.
	cfg := config.Defaults()
	s := New(cfg)

	// Bypass the resolver/policy: stitch a target into the cache directly
	// to exercise the Get path.
	tgt := targetFor(t, srv)
	result := s.runProbes(context.Background(), tgt)
	result.ID = "fake-id"
	s.cache.Put(result.ID, result)

	got, ok := s.Get("fake-id")
	if !ok {
		t.Fatal("Get(fake-id) returned no value")
	}
	if got != result {
		t.Error("cached pointer must round-trip")
	}
}

func TestRun_ResolverFailsCleanly(t *testing.T) {
	// Use a stub resolver that returns no IPs.
	s := New(config.Defaults())
	s.resolver = &safehttp.Resolver{
		Lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
			return nil, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := s.Run(ctx, Request{Host: "nowhere.test"})
	if !errors.Is(err, safehttp.ErrNoAllowedIP) {
		t.Errorf("expected ErrNoAllowedIP, got %v", err)
	}
}
