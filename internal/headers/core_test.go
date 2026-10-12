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

// Cases follow the value tables of the HTML Standard's X-Frame-Options
// section: a value combined into one line and the same values sent as
// separate lines must grade the same.
func TestEvalXFO(t *testing.T) {
	cases := []struct {
		name   string
		xfo    []string
		csp    []string
		status scan.Status
		value  string
	}{
		{"absent, no CSP", nil, nil, scan.StatusFail, ""},
		{"DENY", []string{"DENY"}, nil, scan.StatusPass, "DENY"},
		{"SAMEORIGIN lowercase, padded", []string{" sameorigin "}, nil, scan.StatusPass, " sameorigin "},
		{"same value twice in two lines", []string{"DENY", "deny"}, nil, scan.StatusPass, "DENY, deny"},
		{"same value twice in one line", []string{"SAMEORIGIN, SAMEORIGIN"}, nil, scan.StatusPass, "SAMEORIGIN, SAMEORIGIN"},
		{"conflict in two lines", []string{"SAMEORIGIN", "DENY"}, nil, scan.StatusWarn, "SAMEORIGIN, DENY"},
		{"conflict in one line", []string{"DENY, SAMEORIGIN"}, nil, scan.StatusWarn, "DENY, SAMEORIGIN"},
		{"trailing comma", []string{"SAMEORIGIN,"}, nil, scan.StatusWarn, "SAMEORIGIN,"},
		{"ALLOWALL with an invalid value", []string{"ALLOWALL, INVALID"}, nil, scan.StatusWarn, "ALLOWALL, INVALID"},
		{"lone ALLOWALL is ignored", []string{"ALLOWALL"}, nil, scan.StatusFail, "ALLOWALL"},
		{"lone ALLOW-FROM is ignored", []string{"ALLOW-FROM https://example.com/"}, nil, scan.StatusFail, "ALLOW-FROM https://example.com/"},
		{"two invalid values are ignored", []string{"INVALID", "OTHER"}, nil, scan.StatusFail, "INVALID, OTHER"},
		{"blank header is absent", []string{" "}, nil, scan.StatusFail, ""},
		{"absent but CSP frame-ancestors", nil, []string{"frame-ancestors 'none'"}, scan.StatusPass, ""},
		{"absent and CSP without frame-ancestors", nil, []string{"default-src 'self'"}, scan.StatusFail, ""},
		{"ALLOW-FROM overridden by frame-ancestors", []string{"ALLOW-FROM https://example.com/"}, []string{"frame-ancestors https://example.com"}, scan.StatusPass, "ALLOW-FROM https://example.com/"},
		{"conflict overridden by frame-ancestors", []string{"SAMEORIGIN", "DENY"}, []string{"frame-ancestors 'self'"}, scan.StatusPass, "SAMEORIGIN, DENY"},
		{"frame-ancestors in a second CSP line", nil, []string{"default-src 'self'", "frame-ancestors 'none'"}, scan.StatusPass, ""},
		{"frame-ancestors in a second comma-separated policy", nil, []string{"default-src 'self', frame-ancestors 'none'"}, scan.StatusPass, ""},
	}
	for _, c := range cases {
		h := http.Header{}
		for _, v := range c.xfo {
			h.Add("X-Frame-Options", v)
		}
		for _, v := range c.csp {
			h.Add("Content-Security-Policy", v)
		}
		got := evalXFO(h)
		if got.Status != c.status {
			t.Errorf("%s: got %s, want %s", c.name, got.Status, c.status)
		}
		if got.Value != c.value || got.Present != (c.value != "") {
			t.Errorf("%s: got present=%v value=%q, want value %q", c.name, got.Present, got.Value, c.value)
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
