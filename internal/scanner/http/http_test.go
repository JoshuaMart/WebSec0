package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
	scannerhttp "github.com/JoshuaMart/websec0/internal/scanner/http"
)

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

type fixture struct {
	homepageHeaders map[string]string
	homepageBody    string
	optionsAllow    string
	traceStatus     int
	cors            map[string]map[string]string // origin → headers
	notFoundBody    string
	notFoundStatus  int
	robotsCT        string
	robotsBody      string
	changePassCode  int
	changePassLoc   string
}

func newServer(t *testing.T, f *fixture) *checks.Target {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.Method == http.MethodOptions:
			if f.optionsAllow != "" {
				w.Header().Set("Allow", f.optionsAllow)
			}
			w.WriteHeader(204)
		case r.URL.Path == "/" && r.Method == http.MethodTrace:
			st := f.traceStatus
			if st == 0 {
				st = 405
			}
			w.WriteHeader(st)
		case r.URL.Path == "/" && r.Method == http.MethodGet:
			origin := r.Header.Get("Origin")
			if origin != "" && f.cors != nil {
				if hdrs, ok := f.cors[origin]; ok {
					for k, v := range hdrs {
						w.Header().Set(k, v)
					}
				}
			}
			for k, v := range f.homepageHeaders {
				w.Header().Set(k, v)
			}
			body := f.homepageBody
			if body == "" {
				body = "<!doctype html><html><body>ok</body></html>"
			}
			_, _ = w.Write([]byte(body))
		case r.URL.Path == "/robots.txt":
			ct := f.robotsCT
			if ct == "" {
				ct = "text/plain"
			}
			w.Header().Set("Content-Type", ct)
			body := f.robotsBody
			if body == "" {
				body = "User-agent: *\nDisallow:\n"
			}
			_, _ = w.Write([]byte(body))
		case r.URL.Path == "/.well-known/change-password":
			st := f.changePassCode
			if st == 0 {
				st = 404
			}
			if f.changePassLoc != "" {
				w.Header().Set("Location", f.changePassLoc)
			}
			w.WriteHeader(st)
		case strings.HasPrefix(r.URL.Path, "/websec0-test-"):
			// 404 probe.
			st := f.notFoundStatus
			if st == 0 {
				st = 404
			}
			w.WriteHeader(st)
			body := f.notFoundBody
			if body == "" {
				body = "<html><body>not found</body></html>"
			}
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	tgt.HTTPClient = srv.Client()
	tgt.HTTPClient.Transport = &schemeRewrite{base: srv.Client().Transport}
	return tgt
}

func runCheck(t *testing.T, id string, tgt *checks.Target) *checks.Finding {
	t.Helper()
	r := checks.NewRegistry()
	scannerhttp.Register(r)
	c, ok := r.Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f, err := c.Run(ctx, tgt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return f
}

func TestRegisterAddsAllHTTPChecks(t *testing.T) {
	t.Parallel()
	r := checks.NewRegistry()
	scannerhttp.Register(r)
	for _, id := range []string{
		scannerhttp.IDHTTP2Missing, scannerhttp.IDHTTP3Missing, scannerhttp.IDMixedContent,
		scannerhttp.IDOptionsDangerousMethods, scannerhttp.IDTraceEnabled,
		scannerhttp.IDCORSWildcardCredentials, scannerhttp.IDCORSOriginReflected, scannerhttp.IDCORSNullOrigin,
		scannerhttp.ID404StackTrace, scannerhttp.ID404DefaultErrorPage,
		scannerhttp.IDCompressionNone, scannerhttp.IDRobotsTxtInvalid,
		scannerhttp.IDChangePasswordMissing, scannerhttp.IDSRIExternalNoIntegrity,
	} {
		if _, ok := r.Get(id); !ok {
			t.Errorf("missing %s", id)
		}
	}
}

func TestOptionsDangerousMethodsDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{optionsAllow: "GET, POST, PUT, DELETE"})
	if g := runCheck(t, scannerhttp.IDOptionsDangerousMethods, tgt); g.Status != checks.StatusFail {
		t.Errorf("OPTIONS = %s, want fail", g.Status)
	}
}

func TestOptionsSafeAllowPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{optionsAllow: "GET, HEAD, OPTIONS"})
	g := runCheck(t, scannerhttp.IDOptionsDangerousMethods, tgt)
	if g.Status != checks.StatusPass {
		t.Errorf("OPTIONS = %s, want pass", g.Status)
	}
	methods, _ := g.Evidence["methods"].([]string)
	if len(methods) != 3 || methods[0] != "GET" || methods[2] != "OPTIONS" {
		t.Errorf("methods = %v, want [GET HEAD OPTIONS]", methods)
	}
}

func TestTraceEnabledDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{traceStatus: 200})
	if g := runCheck(t, scannerhttp.IDTraceEnabled, tgt); g.Status != checks.StatusFail {
		t.Errorf("TRACE = %s, want fail", g.Status)
	}
}

func TestCORSWildcardCredentialsDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{
		homepageHeaders: map[string]string{
			"Access-Control-Allow-Origin":      "*",
			"Access-Control-Allow-Credentials": "true",
		},
	})
	g := runCheck(t, scannerhttp.IDCORSWildcardCredentials, tgt)
	if g.Status != checks.StatusFail {
		t.Errorf("CORS-WILDCARD-CREDS = %s, want fail", g.Status)
	}
	if g.Evidence["acao"] != "*" || g.Evidence["acac"] != "true" {
		t.Errorf("evidence = %v, want acao=* acac=true", g.Evidence)
	}
}

func TestCORSOriginReflectedDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{
		cors: map[string]map[string]string{
			"https://websec0-test.invalid": {
				"Access-Control-Allow-Origin":      "https://websec0-test.invalid",
				"Access-Control-Allow-Credentials": "true",
			},
		},
	})
	if g := runCheck(t, scannerhttp.IDCORSOriginReflected, tgt); g.Status != checks.StatusFail {
		t.Errorf("CORS-REFLECTED = %s, want fail", g.Status)
	}
}

func TestCORSNullOriginDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{
		cors: map[string]map[string]string{
			"null": {"Access-Control-Allow-Origin": "null"},
		},
	})
	if g := runCheck(t, scannerhttp.IDCORSNullOrigin, tgt); g.Status != checks.StatusFail {
		t.Errorf("CORS-NULL = %s, want fail", g.Status)
	}
}

func TestStackTrace404Detected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{notFoundBody: "Traceback (most recent call last):\n  File \"app.py\", line 42, in handler\n"})
	g := runCheck(t, scannerhttp.ID404StackTrace, tgt)
	if g.Status != checks.StatusFail {
		t.Errorf("404-STACK-TRACE = %s, want fail", g.Status)
	}
	matched, _ := g.Evidence["matched_text"].(string)
	if matched != "Traceback (most recent call last)" {
		t.Errorf("matched_text = %q, want the traceback prefix", matched)
	}
	window, _ := g.Evidence["matched_window"].(string)
	if !strings.Contains(window, "app.py") {
		t.Errorf("matched_window = %q, want it to include the surrounding stack frame", window)
	}
}

func TestDefaultErrorPageDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{notFoundBody: "<html><head><title>404 Not Found</title></head><body>The requested URL was not found on this server.</body></html>"})
	if g := runCheck(t, scannerhttp.ID404DefaultErrorPage, tgt); g.Status != checks.StatusWarn {
		t.Errorf("404-DEFAULT-ERROR-PAGE = %s, want warn", g.Status)
	}
}

func TestRobotsTxtHTMLDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{robotsCT: "text/html", robotsBody: "<html>oops SPA fallback</html>"})
	g := runCheck(t, scannerhttp.IDRobotsTxtInvalid, tgt)
	if g.Status != checks.StatusFail {
		t.Errorf("ROBOTS-TXT-INVALID = %s, want fail", g.Status)
	}
	// Evidence must show the URL probed and a body excerpt — wrong
	// content-type is reported via the earlier branch but the same
	// fail Title here implies HTML body. We only assert the fields are
	// populated, not the exact branch, since either is acceptable.
	if g.Evidence["url"] == "" {
		t.Errorf("evidence[url] is empty")
	}
}

func TestRobotsTxtCleanPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{robotsBody: "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n"})
	g := runCheck(t, scannerhttp.IDRobotsTxtInvalid, tgt)
	if g.Status != checks.StatusPass {
		t.Errorf("ROBOTS-TXT clean = %s, want pass", g.Status)
	}
	dirs, _ := g.Evidence["directives"].(map[string]int)
	if dirs["user-agent"] != 1 || dirs["disallow"] != 1 || dirs["sitemap"] != 1 {
		t.Errorf("directives histogram = %v, want one each of user-agent/disallow/sitemap", dirs)
	}
}

func TestChangePasswordMissingDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{changePassCode: 404})
	g := runCheck(t, scannerhttp.IDChangePasswordMissing, tgt)
	if g.Status != checks.StatusFail {
		t.Errorf("CHANGE-PASSWORD = %s, want fail", g.Status)
	}
	if g.Evidence["url"] == "" {
		t.Errorf("evidence[url] is empty")
	}
	if status, _ := g.Evidence["status"].(int); status != 404 {
		t.Errorf("evidence[status] = %v, want 404", g.Evidence["status"])
	}
}

func TestChangePasswordRedirectPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{changePassCode: 302, changePassLoc: "/account/security"})
	if g := runCheck(t, scannerhttp.IDChangePasswordMissing, tgt); g.Status != checks.StatusPass {
		t.Errorf("CHANGE-PASSWORD redirect = %s, want pass", g.Status)
	}
}

func TestMixedContentDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{
		homepageBody: `<!doctype html><html><body><script src="http://evil.example/x.js"></script><img src="http://evil.example/p.png"></body></html>`,
	})
	g := runCheck(t, scannerhttp.IDMixedContent, tgt)
	if g.Status != checks.StatusFail {
		t.Errorf("MIXED-CONTENT = %s, want fail", g.Status)
	}
	rows, _ := g.Evidence["resources"].([]map[string]any)
	if len(rows) != 2 {
		t.Fatalf("resources = %v, want 2 rows", rows)
	}
	// Script must be flagged as active (executes), img as passive.
	for _, r := range rows {
		switch r["element"] {
		case "script":
			if r["active"] != true {
				t.Errorf("script active = %v, want true", r["active"])
			}
		case "img":
			if r["active"] != false {
				t.Errorf("img active = %v, want false", r["active"])
			}
		default:
			t.Errorf("unexpected element %v", r["element"])
		}
	}
}

func TestMixedContentCleanPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{
		homepageBody: `<!doctype html><html><body><script src="https://example.com/x.js"></script></body></html>`,
	})
	if g := runCheck(t, scannerhttp.IDMixedContent, tgt); g.Status != checks.StatusPass {
		t.Errorf("MIXED-CONTENT clean = %s, want pass", g.Status)
	}
}

func TestSRIMissingOnExternalScript(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{
		homepageBody: `<html><body><script src="https://cdn.evil/lib.js"></script></body></html>`,
	})
	if g := runCheck(t, scannerhttp.IDSRIExternalNoIntegrity, tgt); g.Status != checks.StatusFail {
		t.Errorf("SRI = %s, want fail", g.Status)
	}
}

func TestSRIPresentPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{
		homepageBody: `<html><body><script src="https://cdn.example/lib.js" integrity="sha384-abc"></script></body></html>`,
	})
	if g := runCheck(t, scannerhttp.IDSRIExternalNoIntegrity, tgt); g.Status != checks.StatusPass {
		t.Errorf("SRI present = %s, want pass", g.Status)
	}
}

func TestCompressionDetected(t *testing.T) {
	t.Parallel()
	// Use `br` rather than `gzip` so Go's http transport doesn't transparently
	// decode the response and strip Content-Encoding before we observe it.
	tgt := newServer(t, &fixture{homepageHeaders: map[string]string{"Content-Encoding": "br"}})
	if g := runCheck(t, scannerhttp.IDCompressionNone, tgt); g.Status != checks.StatusPass {
		t.Errorf("COMPRESSION-NONE with br = %s, want pass", g.Status)
	}
}

func TestCompressionMissingDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, &fixture{})
	if g := runCheck(t, scannerhttp.IDCompressionNone, tgt); g.Status != checks.StatusFail {
		t.Errorf("COMPRESSION-NONE = %s, want fail", g.Status)
	}
}
