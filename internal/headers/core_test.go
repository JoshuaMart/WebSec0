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

// Cases follow what Chrome 152 applied to a script served as text/plain:
// only the first value of the header counts.
func TestEvalXCTO(t *testing.T) {
	cases := []struct {
		name   string
		lines  []string
		status scan.Status
	}{
		{"absent", nil, scan.StatusFail},
		{"blank header is absent", []string{" "}, scan.StatusFail},
		{"nosniff", []string{"nosniff"}, scan.StatusPass},
		{"any case", []string{"NoSniff"}, scan.StatusPass},
		{"nosniff first in a list", []string{"nosniff, foo"}, scan.StatusPass},
		{"nosniff twice in one line", []string{"nosniff, nosniff"}, scan.StatusPass},
		{"nosniff twice in two lines", []string{"nosniff", "nosniff"}, scan.StatusPass},
		{"nosniff second in a list", []string{"foo, nosniff"}, scan.StatusFail},
		{"nosniff in a second line", []string{"foo", "nosniff"}, scan.StatusFail},
		{"quoted value", []string{`"nosniff"`}, scan.StatusFail},
		{"other value", []string{"garbage"}, scan.StatusFail},
	}
	for _, c := range cases {
		h := http.Header{}
		for _, v := range c.lines {
			h.Add("X-Content-Type-Options", v)
		}
		got := evalXCTO(h)
		if got.Status != c.status {
			t.Errorf("%s: got %s, want %s", c.name, got.Status, c.status)
		}
		if wantPresent := len(c.lines) > 0 && c.lines[0] != " "; got.Present != wantPresent {
			t.Errorf("%s: got present=%v, want %v", c.name, got.Present, wantPresent)
		}
	}
}

// Browsers apply the last recognised value, whether values come as separate
// header lines or as a comma-separated list, and skip unknown ones.
func TestEvalReferrerPolicy(t *testing.T) {
	cases := []struct {
		name   string
		lines  []string
		status scan.Status
		value  string
	}{
		{"absent", nil, scan.StatusFail, ""},
		{"blank header is absent", []string{" "}, scan.StatusFail, ""},
		{"strict policy", []string{"strict-origin-when-cross-origin"}, scan.StatusPass, "strict-origin-when-cross-origin"},
		{"no-referrer-when-downgrade", []string{"no-referrer-when-downgrade"}, scan.StatusWarn, "no-referrer-when-downgrade"},
		{"unsafe-url in any case", []string{"Unsafe-URL"}, scan.StatusWarn, "Unsafe-URL"},
		{"origin passes", []string{"origin"}, scan.StatusPass, "origin"},
		{"fallback list, strict last", []string{"no-referrer, strict-origin-when-cross-origin"}, scan.StatusPass, "no-referrer, strict-origin-when-cross-origin"},
		{"list with unsafe-url last", []string{"no-referrer, unsafe-url"}, scan.StatusWarn, "no-referrer, unsafe-url"},
		{"two lines, unsafe-url last", []string{"strict-origin-when-cross-origin", "unsafe-url"}, scan.StatusWarn, "strict-origin-when-cross-origin, unsafe-url"},
		{"two lines, strict last", []string{"no-referrer-when-downgrade", "strict-origin-when-cross-origin"}, scan.StatusPass, "no-referrer-when-downgrade, strict-origin-when-cross-origin"},
		{"unknown value last is skipped", []string{"unsafe-url, made-up-policy"}, scan.StatusWarn, "unsafe-url, made-up-policy"},
		{"trailing comma is skipped", []string{"unsafe-url,"}, scan.StatusWarn, "unsafe-url,"},
		{"unknown value alone", []string{"made-up-policy"}, scan.StatusFail, "made-up-policy"},
		{"quoted value is unknown", []string{`"no-referrer"`}, scan.StatusFail, `"no-referrer"`},
	}
	for _, c := range cases {
		h := http.Header{}
		for _, v := range c.lines {
			h.Add("Referrer-Policy", v)
		}
		got := evalReferrerPolicy(h)
		if got.Status != c.status {
			t.Errorf("%s: got %s, want %s", c.name, got.Status, c.status)
		}
		if got.Value != c.value || got.Present != (c.value != "") {
			t.Errorf("%s: got present=%v value=%q, want value %q", c.name, got.Present, got.Value, c.value)
		}
	}
}

// Statuses follow what Chrome 152 applied for each header: a syntax error
// drops the whole header, and the last definition of a feature wins.
func TestEvalPermissionsPolicy(t *testing.T) {
	cases := []struct {
		name   string
		lines  []string
		status scan.Status
	}{
		{"absent", nil, scan.StatusFail},
		{"blank header is absent", []string{" "}, scan.StatusFail},
		{"sensitive features disabled", []string{"camera=(), microphone=(), geolocation=()"}, scan.StatusPass},
		{"one sensitive feature disabled", []string{"geolocation=()"}, scan.StatusPass},
		{"camera kept for self, usb disabled", []string{"camera=(self), microphone=(self), usb=()"}, scan.StatusPass},
		{"delegated to one origin", []string{`camera=(self "https://meet.example"), microphone=(self "https://meet.example"), geolocation=()`}, scan.StatusPass},
		{"with parameters", []string{"camera=();report-to=main, microphone=()"}, scan.StatusPass},
		{"none token disables", []string{"camera=none"}, scan.StatusPass},
		{"upper-case name drops the header", []string{"Camera=(), microphone=()"}, scan.StatusFail},
		{"spaces around = drop the header", []string{"camera = (), microphone=()"}, scan.StatusFail},
		{"quoted self drops the header", []string{"camera=('self'), microphone=()"}, scan.StatusFail},
		{"trailing comma drops the header", []string{"camera=(), microphone=(),"}, scan.StatusFail},
		{"Feature-Policy syntax drops the header", []string{"camera 'none'; microphone 'none'"}, scan.StatusFail},
		{"bare origin is ignored, nothing disabled", []string{"camera=(self https://video.example)"}, scan.StatusWarn},
		{"no sensitive feature", []string{"fullscreen=(self)"}, scan.StatusWarn},
		{"obsolete feature only", []string{"interest-cohort=()"}, scan.StatusWarn},
		{"sensitive feature open to all", []string{"camera=*, microphone=()"}, scan.StatusWarn},
		{"star inside a list", []string{"camera=(self *), microphone=()"}, scan.StatusWarn},
		{"second line reopens the feature", []string{"camera=()", "camera=*"}, scan.StatusWarn},
		{"second line disables", []string{"geolocation=(self), interest-cohort=()", "camera=(), microphone=(), geolocation=()"}, scan.StatusPass},
	}
	for _, c := range cases {
		h := http.Header{}
		for _, v := range c.lines {
			h.Add("Permissions-Policy", v)
		}
		got := evalPermissionsPolicy(h)
		if got.Status != c.status {
			t.Errorf("%s: got %s, want %s", c.name, got.Status, c.status)
		}
		if wantPresent := c.status != scan.StatusFail || (len(c.lines) > 0 && c.lines[0] != " "); got.Present != wantPresent {
			t.Errorf("%s: got present=%v, want %v", c.name, got.Present, wantPresent)
		}
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
