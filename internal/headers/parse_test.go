package headers

import (
	"strings"
	"testing"
)

func TestParseHSTS(t *testing.T) {
	cases := []struct {
		in   string
		want HSTSDirectives
	}{
		{"", HSTSDirectives{MaxAge: -1}},
		{"max-age=31536000", HSTSDirectives{MaxAge: 31536000}},
		{
			"max-age=63072000; includeSubDomains; preload",
			HSTSDirectives{MaxAge: 63072000, IncludeSubDomains: true, Preload: true},
		},
		{
			`max-age="31536000"; includeSubDomains`,
			HSTSDirectives{MaxAge: 31536000, IncludeSubDomains: true},
		},
		{"max-age=0", HSTSDirectives{MaxAge: 0}},
		{"includeSubDomains; preload", HSTSDirectives{MaxAge: -1, IncludeSubDomains: true, Preload: true}},
		{
			"MAX-AGE=31536000; INCLUDESUBDOMAINS",
			HSTSDirectives{MaxAge: 31536000, IncludeSubDomains: true},
		},
	}
	for _, c := range cases {
		got := ParseHSTS(c.in)
		if got != c.want {
			t.Errorf("ParseHSTS(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseCSP(t *testing.T) {
	t.Run("explicit script-src", func(t *testing.T) {
		got := ParseCSP("default-src 'self'; script-src 'self' 'unsafe-inline'")
		if !got.HasScriptSrc || !got.ScriptUnsafeInline {
			t.Errorf("expected ScriptSrc with unsafe-inline, got %+v", got)
		}
	})
	t.Run("fallback to default-src", func(t *testing.T) {
		got := ParseCSP("default-src 'self' 'unsafe-inline'")
		if got.HasScriptSrc {
			t.Error("HasScriptSrc should be false")
		}
		if !got.DefaultUnsafeInline {
			t.Error("DefaultUnsafeInline should be true")
		}
	})
	t.Run("frame-ancestors", func(t *testing.T) {
		got := ParseCSP("default-src 'self'; frame-ancestors 'none'")
		if !got.HasFrameAncestors {
			t.Error("HasFrameAncestors should be true")
		}
	})
	t.Run("safe csp", func(t *testing.T) {
		got := ParseCSP("default-src 'self'; script-src 'self' https://cdn.example.com")
		if got.ScriptUnsafeInline || got.DefaultUnsafeInline {
			t.Errorf("safe CSP misclassified: %+v", got)
		}
	})
}

func TestParseCookie(t *testing.T) {
	cases := []struct {
		in   string
		want CookieInfo
	}{
		{"session=abc", CookieInfo{Name: "session"}},
		{
			"session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
			CookieInfo{Name: "session", Secure: true, HTTPOnly: true, SameSite: "Strict"},
		},
		{
			"id=xyz; secure; samesite=lax",
			CookieInfo{Name: "id", Secure: true, SameSite: "lax"},
		},
	}
	for _, c := range cases {
		got := ParseCookie(c.in)
		if got != c.want {
			t.Errorf("ParseCookie(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestServerLeaksVersion(t *testing.T) {
	cases := map[string]bool{
		"nginx/1.27.1":       true,
		"Apache/2.4.52":      true,
		"nginx":              false,
		"cloudflare":         false,
		"Microsoft-IIS/10.0": true,
		"":                   false,
	}
	for in, want := range cases {
		if got := ServerLeaksVersion(in); got != want {
			t.Errorf("ServerLeaksVersion(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsACAOWildcard(t *testing.T) {
	if !IsACAOWildcard("*") {
		t.Error("\"*\" should be wildcard")
	}
	if !IsACAOWildcard(" * ") {
		t.Error("\" * \" with surrounding spaces should be wildcard")
	}
	if IsACAOWildcard("https://example.com") {
		t.Error("non-wildcard misclassified")
	}
}

func TestParsePermissionsPolicy(t *testing.T) {
	got, ok := ParsePermissionsPolicy(`camera=(), microphone=(self "https://a.example" "https://b.example"), geolocation=self, fullscreen=*, usb=(self *), midi=none, camera=(self)`)
	if !ok {
		t.Fatal("valid policy should parse")
	}
	want := map[string]PermissionsAllowlist{
		"camera":      {Self: true}, // last definition wins
		"microphone":  {Self: true, Origins: []string{"https://a.example", "https://b.example"}},
		"geolocation": {Self: true},
		"fullscreen":  {All: true},
		"usb":         {All: true, Self: true},
		"midi":        {},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d features, want %d: %+v", len(got), len(want), got)
	}
	for f, w := range want {
		g := got[f]
		if g.All != w.All || g.Self != w.Self || strings.Join(g.Origins, " ") != strings.Join(w.Origins, " ") {
			t.Errorf("%s: got %+v, want %+v", f, g, w)
		}
	}
	if !got["midi"].Disabled() || got["camera"].Disabled() {
		t.Error("Disabled() should be true for midi=none only")
	}
}

// Dictionary grammar from RFC 9651 §3.2 and §4.2, including bare item types a
// permissions policy never uses: they must parse, not break the header.
func TestParseSFDictionary(t *testing.T) {
	valid := []string{
		"",
		"a",
		"a, b=?0",
		"a=1, b=-2, c=3.141, d=-0.5",
		`a="x \"quoted\" \\ y"`,
		"a=tok/en:x, b=*star",
		"a=:aGVsbG8=:",
		"a=@1659578233",
		`a=%"caf%c3%a9"`,
		"a=(1 2 tok);p=1;q, b=()",
		"a=( 1  2 )",
		"a=1;p, b=2\t,\tc=3",
		"  a=1  ",
		"a=999999999999999",
		"a=1.123",
	}
	for _, v := range valid {
		if _, ok := parseSFDictionary(v); !ok {
			t.Errorf("%q should parse", v)
		}
	}
	invalid := []string{
		"A=1",
		"1a=1",
		"a=1,",
		"a=1,,b=2",
		"a=1 b=2",
		"a =1",
		"a= 1",
		"a=1.",
		"a=1.1234",
		"a=1234567890123.1",
		"a=1234567890123456",
		`a="unterminated`,
		`a="bad \x escape"`,
		"a=(1",
		"a=(1)x",
		"a=(1,2)",
		"a=?2",
		"a=:not base64!:",
		"a=@1.5",
		`a=%"CAF%C3%A9"`,
		"a='self'",
		"a=1;P=2",
		"a=é",
	}
	for _, v := range invalid {
		if _, ok := parseSFDictionary(v); ok {
			t.Errorf("%q should not parse", v)
		}
	}
}
