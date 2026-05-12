package headers

import "testing"

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
