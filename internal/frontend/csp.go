package frontend

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// contentSecurityPolicy returns the policy for one served page. Astro emits
// a few inline <script> and <style> elements (island runtime, landing script)
// that cannot be moved to files, so each one present in shell is allowed by
// its SHA-256 hash. Hashing runs after head_inject is spliced in, so inline
// operator snippets are covered too; external ones need extraSources.
//
// extraSources holds validated origins and hash sources from
// frontend.csp_extra_sources. Origins are added to script-src and
// connect-src (analytics scripts usually report to their own origin);
// hashes only to script-src. A nil shell gives the policy for non-HTML files.
func contentSecurityPolicy(shell []byte, extraSources []string) string {
	scriptHashes, styleHashes := inlineHashes(shell)

	scriptSrc := append([]string{"'self'"}, scriptHashes...)
	connectSrc := []string{"'self'"}
	for _, s := range extraSources {
		scriptSrc = append(scriptSrc, s)
		if !strings.HasPrefix(s, "'") {
			connectSrc = append(connectSrc, s)
		}
	}
	styleSrc := append([]string{"'self'"}, styleHashes...)

	return strings.Join([]string{
		"default-src 'self'",
		"script-src " + strings.Join(scriptSrc, " "),
		"style-src " + strings.Join(styleSrc, " "),
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src " + strings.Join(connectSrc, " "),
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
}

// inlineHashes returns CSP hash sources for the inline scripts and styles in
// doc. Scripts with a src, and data blocks such as JSON-LD, are not executed
// as inline scripts and need no hash.
func inlineHashes(doc []byte) (scripts, styles []string) {
	z := html.NewTokenizer(bytes.NewReader(doc))
	var inside atom.Atom
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return scripts, styles
		case html.StartTagToken:
			tok := z.Token()
			inside = 0
			switch {
			case tok.DataAtom == atom.Script && isInlineScript(tok):
				inside = atom.Script
			case tok.DataAtom == atom.Style:
				inside = atom.Style
			}
		case html.TextToken, html.EndTagToken:
			if inside == 0 {
				continue
			}
			// An empty element has no text token: hash the empty string.
			// Script and style text is not entity-decoded; browsers hash it
			// after normalising newlines, as the HTML parser does.
			var text []byte
			if tt == html.TextToken {
				text = bytes.ReplaceAll(z.Raw(), []byte("\r\n"), []byte("\n"))
				text = bytes.ReplaceAll(text, []byte("\r"), []byte("\n"))
			}
			if inside == atom.Script {
				scripts = append(scripts, hashSource(text))
			} else {
				styles = append(styles, hashSource(text))
			}
			inside = 0
		}
	}
}

func hashSource(b []byte) string {
	sum := sha256.Sum256(b)
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// isInlineScript reports whether a <script> start tag holds code the browser
// runs inline: no src attribute, and a JavaScript or module type.
func isInlineScript(tok html.Token) bool {
	for _, a := range tok.Attr {
		switch a.Key {
		case "src":
			return false
		case "type":
			t := strings.ToLower(strings.TrimSpace(a.Val))
			if t != "" && t != "module" && t != "text/javascript" && t != "application/javascript" {
				return false
			}
		}
	}
	return true
}
