package frontend

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func TestInlineHashes(t *testing.T) {
	doc := `<html><head>
<script type="application/ld+json">{"@type":"WebSite"}</script>
<script src="/_astro/app.js"></script>
<script type="module">run("a&amp;b")</script>
<script>one()</script>
<script></script>
<style>astro-island{display:contents}</style>
</head><body><script>two()` + "\r\n" + `</script></body></html>`

	scripts, styles := inlineHashes([]byte(doc))

	// JSON-LD and src scripts are skipped; entities stay undecoded and CRLF
	// becomes LF, as the browser hashes them.
	wantScripts := []string{sha(`run("a&amp;b")`), sha("one()"), sha(""), sha("two()\n")}
	if strings.Join(scripts, " ") != strings.Join(wantScripts, " ") {
		t.Errorf("script hashes:\n got  %v\n want %v", scripts, wantScripts)
	}
	if len(styles) != 1 || styles[0] != sha("astro-island{display:contents}") {
		t.Errorf("style hashes: got %v", styles)
	}
}

func TestContentSecurityPolicy(t *testing.T) {
	doc := []byte(`<head><script>x()</script></head>`)
	got := contentSecurityPolicy(doc, []string{"https://stats.example.com", "'sha256-AAAA'"})

	for _, want := range []string{
		"default-src 'self'",
		"script-src 'self' " + sha("x()") + " https://stats.example.com 'sha256-AAAA'",
		"style-src 'self';",
		"connect-src 'self' https://stats.example.com;",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("policy missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "unsafe-inline") || strings.Contains(got, "unsafe-eval") {
		t.Errorf("policy must not allow unsafe sources: %s", got)
	}
}

func TestContentSecurityPolicy_NoShell(t *testing.T) {
	got := contentSecurityPolicy(nil, nil)
	if !strings.Contains(got, "script-src 'self';") {
		t.Errorf("file policy should allow only 'self' scripts: %s", got)
	}
}
