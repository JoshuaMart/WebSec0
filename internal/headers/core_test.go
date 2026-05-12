package headers

import (
	"net/http"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestEvalHSTS(t *testing.T) {
	cases := []struct {
		name   string
		v      string
		status scan.Status
	}{
		{"absent", "", scan.StatusFail},
		{"too short", "max-age=86400", scan.StatusWarn},
		{"long enough, no includeSubDomains", "max-age=31536000", scan.StatusWarn},
		{"strong", "max-age=63072000; includeSubDomains; preload", scan.StatusPass},
	}
	for _, c := range cases {
		got := evalHSTS(c.v)
		if got.Status != c.status {
			t.Errorf("%s: got %s, want %s", c.name, got.Status, c.status)
		}
	}
}

func TestEvalCSP(t *testing.T) {
	cases := []struct {
		name   string
		v      string
		status scan.Status
	}{
		{"absent", "", scan.StatusFail},
		{"safe", "default-src 'self'; script-src 'self'", scan.StatusPass},
		{"unsafe-inline script", "script-src 'self' 'unsafe-inline'", scan.StatusWarn},
		{"unsafe-inline default fallback", "default-src 'self' 'unsafe-inline'", scan.StatusWarn},
	}
	for _, c := range cases {
		got := evalCSP(c.v)
		if got.Status != c.status {
			t.Errorf("%s: got %s, want %s", c.name, got.Status, c.status)
		}
	}
}

func TestEvalXFO(t *testing.T) {
	cases := []struct {
		name   string
		xfo    string
		csp    string
		status scan.Status
	}{
		{"absent, no CSP", "", "", scan.StatusFail},
		{"DENY", "DENY", "", scan.StatusPass},
		{"SAMEORIGIN lowercase", "sameorigin", "", scan.StatusPass},
		{"weird value", "ALLOWALL", "", scan.StatusWarn},
		{"absent but CSP frame-ancestors", "", "frame-ancestors 'none'", scan.StatusPass},
		{"absent and CSP without frame-ancestors", "", "default-src 'self'", scan.StatusFail},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.xfo != "" {
			h.Set("X-Frame-Options", c.xfo)
		}
		if c.csp != "" {
			h.Set("Content-Security-Policy", c.csp)
		}
		got := evalXFO(h)
		if got.Status != c.status {
			t.Errorf("%s: got %s, want %s", c.name, got.Status, c.status)
		}
	}
}

func TestEvalXCTO(t *testing.T) {
	if evalXCTO("").Status != scan.StatusFail {
		t.Error("absent should fail")
	}
	if evalXCTO("nosniff").Status != scan.StatusPass {
		t.Error("nosniff should pass")
	}
	if evalXCTO("NOSNIFF").Status != scan.StatusPass {
		t.Error("case-insensitive nosniff")
	}
	if evalXCTO("garbage").Status != scan.StatusWarn {
		t.Error("garbage value should warn")
	}
}

func TestEvalReferrerPolicy(t *testing.T) {
	if evalReferrerPolicy("").Status != scan.StatusFail {
		t.Error("absent should fail")
	}
	if evalReferrerPolicy("strict-origin-when-cross-origin").Status != scan.StatusPass {
		t.Error("strict policy should pass")
	}
	if evalReferrerPolicy("no-referrer-when-downgrade").Status != scan.StatusWarn {
		t.Error("permissive policy should warn")
	}
	if evalReferrerPolicy("unsafe-url").Status != scan.StatusWarn {
		t.Error("unsafe-url should warn")
	}
}

func TestEvalPermissionsPolicy(t *testing.T) {
	if evalPermissionsPolicy("").Status != scan.StatusFail {
		t.Error("absent should fail")
	}
	if evalPermissionsPolicy("geolocation=(), camera=()").Status != scan.StatusPass {
		t.Error("any value should pass")
	}
}

func TestEvaluateCore_ReturnsAllSixKeys(t *testing.T) {
	core := EvaluateCore(http.Header{})
	for _, name := range CoreHeaderNames {
		if _, ok := core[name]; !ok {
			t.Errorf("missing key %q in core map", name)
		}
	}
}
