package headers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/scanner/headers"
)

// fixture spins up an httptest.Server that emits whatever headers the test
// asks for on `/`.
type fixture struct {
	headers map[string]string
}

func newServer(t *testing.T, f *fixture) *checks.Target {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range f.headers {
			w.Header().Set(k, v)
		}
		_, _ = w.Write([]byte("<!doctype html><html><body>ok</body></html>"))
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	tgt.HTTPClient = srv.Client()
	// Override the URL scheme: our fetcher builds https://host/, but the
	// test server is plain HTTP. Patch the client transport to rewrite.
	tgt.HTTPClient.Transport = &schemeRewrite{base: srv.Client().Transport}
	return tgt
}

// schemeRewrite intercepts https:// requests against the test server and
// downgrades them to http://, since httptest.NewServer is HTTP-only.
type schemeRewrite struct{ base http.RoundTripper }

func (s *schemeRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		clone := *req
		u := *req.URL
		u.Scheme = "http"
		clone.URL = &u
		req = &clone
	}
	rt := s.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(req)
}

func runCheck(t *testing.T, id string, tgt *checks.Target) *checks.Finding {
	t.Helper()
	r := checks.NewRegistry()
	headers.Register(r)
	c, ok := r.Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := c.Run(ctx, tgt)
	if err != nil {
		t.Fatalf("%s: Run err = %v", id, err)
	}
	if f == nil {
		t.Fatalf("%s: nil finding", id)
	}
	return f
}

func TestRegisterAddsAllChecks(t *testing.T) {
	t.Parallel()
	r := checks.NewRegistry()
	headers.Register(r)
	for _, id := range []string{
		headers.IDCSPMissing, headers.IDCSPUnsafeInline, headers.IDCSPUnsafeEval,
		headers.IDCSPWildcardSrc, headers.IDCSPNoObjectSrc, headers.IDCSPNoBaseURI,
		headers.IDCSPNoFrameAncestors,
		headers.IDXCTOMissing, headers.IDXFOMissing,
		headers.IDReferrerPolicyMissing, headers.IDReferrerPolicyUnsafe,
		headers.IDPermissionsPolicyMiss, headers.IDFeaturePolicyDeprec,
		headers.IDCOOPMissing, headers.IDCOEPMissing, headers.IDCORPMissing,
		headers.IDReportingEndpointsNo, headers.IDNELNone,
		headers.IDXSSProtectionDeprec, headers.IDHPKPDeprecated, headers.IDExpectCTDeprecated,
		headers.IDInfoServer, headers.IDInfoXPoweredBy, headers.IDInfoXAspNetVersion,
		headers.IDInfoXGenerator, headers.IDInfoServerTiming,
	} {
		if _, ok := r.Get(id); !ok {
			t.Errorf("missing %s", id)
		}
	}
}

func TestEmptyResponseFailsAllPresenceChecks(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{})

	failExpected := []string{
		headers.IDCSPMissing,
		headers.IDXCTOMissing,
		headers.IDXFOMissing,
		headers.IDReferrerPolicyMissing,
		headers.IDPermissionsPolicyMiss,
		headers.IDCOOPMissing,
		headers.IDCOEPMissing,
		headers.IDCORPMissing,
		headers.IDReportingEndpointsNo,
		headers.IDNELNone,
	}
	for _, id := range failExpected {
		if g := runCheck(t, id, tgt); g.Status != checks.StatusFail {
			t.Errorf("%s = %s, want fail", id, g.Status)
		}
	}

	// Deprecated/info checks should pass when their headers are absent.
	for _, id := range []string{
		headers.IDXSSProtectionDeprec, headers.IDHPKPDeprecated, headers.IDExpectCTDeprecated,
		headers.IDFeaturePolicyDeprec,
		headers.IDInfoServer, headers.IDInfoXPoweredBy, headers.IDInfoXAspNetVersion,
		headers.IDInfoXGenerator, headers.IDInfoServerTiming,
	} {
		if g := runCheck(t, id, tgt); g.Status != checks.StatusPass {
			t.Errorf("%s = %s, want pass (header absent)", id, g.Status)
		}
	}
}

func TestStrongResponsePasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Content-Security-Policy":      "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "strict-origin-when-cross-origin",
		"Permissions-Policy":           "camera=(), microphone=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Reporting-Endpoints":          `default="https://example.com/reports"`,
		"NEL":                          `{"report_to":"default","max_age":86400}`,
	}})

	for _, id := range []string{
		headers.IDCSPMissing, headers.IDCSPUnsafeInline, headers.IDCSPUnsafeEval,
		headers.IDCSPWildcardSrc, headers.IDCSPNoObjectSrc, headers.IDCSPNoBaseURI,
		headers.IDCSPNoFrameAncestors,
		headers.IDXCTOMissing, headers.IDXFOMissing,
		headers.IDReferrerPolicyMissing, headers.IDReferrerPolicyUnsafe,
		headers.IDPermissionsPolicyMiss,
		headers.IDCOOPMissing, headers.IDCOEPMissing, headers.IDCORPMissing,
		headers.IDReportingEndpointsNo, headers.IDNELNone,
	} {
		if g := runCheck(t, id, tgt); g.Status != checks.StatusPass {
			t.Errorf("%s = %s, want pass", id, g.Status)
		}
	}
}

func TestCSPUnsafeInlineDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'",
	}})
	if g := runCheck(t, headers.IDCSPUnsafeInline, tgt); g.Status != checks.StatusFail {
		t.Errorf("UNSAFE-INLINE = %s, want fail", g.Status)
	}
	if g := runCheck(t, headers.IDCSPUnsafeEval, tgt); g.Status != checks.StatusFail {
		t.Errorf("UNSAFE-EVAL = %s, want fail", g.Status)
	}
}

func TestCSPWildcardDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Content-Security-Policy": "default-src *",
	}})
	if g := runCheck(t, headers.IDCSPWildcardSrc, tgt); g.Status != checks.StatusFail {
		t.Errorf("WILDCARD = %s, want fail", g.Status)
	}
}

func TestXFOSupersededByCSP(t *testing.T) {
	t.Parallel()
	// XFO missing but CSP frame-ancestors present → should pass
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
	}})
	if g := runCheck(t, headers.IDXFOMissing, tgt); g.Status != checks.StatusPass {
		t.Errorf("XFO with CSP frame-ancestors = %s, want pass", g.Status)
	}
}

func TestReferrerPolicyUnsafe(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Referrer-Policy": "unsafe-url",
	}})
	if g := runCheck(t, headers.IDReferrerPolicyUnsafe, tgt); g.Status != checks.StatusFail {
		t.Errorf("REFERRER-UNSAFE = %s, want fail", g.Status)
	}
}

func TestServerHeaderWithVersionFails(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Server": "nginx/1.18.0",
	}})
	if g := runCheck(t, headers.IDInfoServer, tgt); g.Status != checks.StatusWarn {
		t.Errorf("SERVER-INFO = %s, want warn", g.Status)
	}
}

func TestServerHeaderWithoutVersionPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Server": "cloudflare",
	}})
	if g := runCheck(t, headers.IDInfoServer, tgt); g.Status != checks.StatusPass {
		t.Errorf("SERVER without version = %s, want pass", g.Status)
	}
}

func TestXPoweredByDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"X-Powered-By": "Express",
	}})
	if g := runCheck(t, headers.IDInfoXPoweredBy, tgt); g.Status != checks.StatusWarn {
		t.Errorf("X-POWERED-BY = %s, want warn", g.Status)
	}
}

func TestHPKPDeprecatedDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"Public-Key-Pins": `pin-sha256="abc=";max-age=300`,
	}})
	if g := runCheck(t, headers.IDHPKPDeprecated, tgt); g.Status != checks.StatusFail {
		t.Errorf("HPKP = %s, want fail", g.Status)
	}
}

func TestXSSProtectionDisabledPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{headers: map[string]string{
		"X-XSS-Protection": "0",
	}})
	if g := runCheck(t, headers.IDXSSProtectionDeprec, tgt); g.Status != checks.StatusPass {
		t.Errorf("X-XSS-Protection: 0 = %s, want pass", g.Status)
	}
}

func TestFetchIsCachedAcrossChecks(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	tgt.HTTPClient = srv.Client()
	tgt.HTTPClient.Transport = &schemeRewrite{base: srv.Client().Transport}

	r := checks.NewRegistry()
	headers.Register(r)
	for _, c := range r.All() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = c.Run(ctx, tgt)
		cancel()
	}
	if hits > 1 {
		t.Errorf("server hit %d times, want 1 (cache failed)", hits)
	}
}
