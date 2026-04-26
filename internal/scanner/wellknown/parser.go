// Package wellknown implements checks for files published under the
// /.well-known/ URI namespace (RFC 8615), starting with security.txt
// (RFC 9116).
package wellknown

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SecurityTxt is the parsed shape of a security.txt file as defined by
// RFC 9116. Multi-value fields are slices in the order they appear.
type SecurityTxt struct {
	Contact            []string
	Expires            *time.Time
	Encryption         []string
	Acknowledgments    []string
	PreferredLanguages []string
	Canonical          []string
	Policy             []string
	Hiring             []string
	CSAF               []string

	// Signed is true when the document is wrapped in an OpenPGP cleartext
	// signature (`-----BEGIN PGP SIGNED MESSAGE-----` ... `-----END PGP
	// SIGNATURE-----`). The signature itself is not verified at Phase 5.
	Signed bool

	// ParseWarnings holds non-fatal anomalies (unknown fields, malformed
	// values) that callers may surface as `info`-severity findings.
	ParseWarnings []string
}

// ParseSecurityTxt parses an RFC 9116 file. Empty input returns an error;
// other malformations are reported via ParseWarnings while the partial
// result is returned.
func ParseSecurityTxt(raw []byte) (*SecurityTxt, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("security.txt: empty document")
	}

	body, signed := stripPGPSignature(raw)

	out := &SecurityTxt{Signed: signed}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)

	lineno := 0
	for scanner.Scan() {
		lineno++
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		k, v, ok := splitField(trimmed)
		if !ok {
			out.ParseWarnings = append(out.ParseWarnings,
				fmt.Sprintf("line %d: malformed (no `key:`)", lineno))
			continue
		}
		switch strings.ToLower(k) {
		case "contact":
			out.Contact = append(out.Contact, v)
		case "expires":
			t, err := parseRFC3339(v)
			if err != nil {
				out.ParseWarnings = append(out.ParseWarnings,
					fmt.Sprintf("line %d: invalid Expires %q: %v", lineno, v, err))
				continue
			}
			if out.Expires != nil {
				out.ParseWarnings = append(out.ParseWarnings,
					fmt.Sprintf("line %d: duplicate Expires (RFC 9116 §2.5.5)", lineno))
				continue
			}
			out.Expires = &t
		case "encryption":
			out.Encryption = append(out.Encryption, v)
		case "acknowledgments", "acknowledgements": // accept the misspelling
			out.Acknowledgments = append(out.Acknowledgments, v)
		case "preferred-languages":
			if len(out.PreferredLanguages) > 0 {
				out.ParseWarnings = append(out.ParseWarnings,
					fmt.Sprintf("line %d: duplicate Preferred-Languages", lineno))
				continue
			}
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out.PreferredLanguages = append(out.PreferredLanguages, p)
				}
			}
		case "canonical":
			out.Canonical = append(out.Canonical, v)
		case "policy":
			out.Policy = append(out.Policy, v)
		case "hiring":
			out.Hiring = append(out.Hiring, v)
		case "csaf":
			out.CSAF = append(out.CSAF, v)
		default:
			out.ParseWarnings = append(out.ParseWarnings,
				fmt.Sprintf("line %d: unknown field %q", lineno, k))
		}
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("security.txt: scan: %w", err)
	}
	return out, nil
}

// splitField returns ("key", "value", true) for `key: value`, after
// trimming whitespace.
func splitField(line string) (string, string, bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	k := strings.TrimSpace(line[:i])
	v := strings.TrimSpace(line[i+1:])
	if k == "" {
		return "", "", false
	}
	return k, v, true
}

// parseRFC3339 accepts the RFC 3339 / ISO 8601 forms permitted by RFC 9116.
//
// RFC 3339 §5.6 mandates uppercase "Z" for the UTC offset, but many
// real-world generators emit lowercase "z" (e.g. github.com/.well-known/
// security.txt at the time of writing). We normalise so a valid-in-spirit
// document doesn't trigger a false NO-EXPIRES finding.
func parseRFC3339(v string) (time.Time, error) {
	if n := len(v); n > 0 && v[n-1] == 'z' {
		v = v[:n-1] + "Z"
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("not RFC 3339")
}

// stripPGPSignature removes the OpenPGP cleartext signature wrapper if
// present and reports whether the document was signed.
func stripPGPSignature(raw []byte) ([]byte, bool) {
	begin := []byte("-----BEGIN PGP SIGNED MESSAGE-----")
	if !bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), begin) {
		return raw, false
	}
	// Skip the header lines (until a blank line), then read until the
	// signature block.
	idx := bytes.Index(raw, []byte("\n\n"))
	if idx < 0 {
		idx = bytes.Index(raw, []byte("\r\n\r\n"))
	}
	if idx < 0 {
		return raw, true
	}
	body := raw[idx:]
	if cut := bytes.Index(body, []byte("-----BEGIN PGP SIGNATURE-----")); cut >= 0 {
		body = body[:cut]
	}
	return bytes.TrimSpace(body), true
}

// IsSecureURL returns true when u parses cleanly and uses the https scheme.
// Used by the NOT-HTTPS check on Contact/Encryption/etc URLs.
func IsSecureURL(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "mailto:") {
		return true // mailto is not a URL with a scheme we care about here
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}
