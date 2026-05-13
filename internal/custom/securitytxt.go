package custom

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// securityTxtMaxBytes is the response cap for /.well-known/security.txt.
// Real-world files are well under 10 KiB; 64 KiB is a generous safety net.
const securityTxtMaxBytes = 64 * 1024

// SecurityTxt is the RFC 9116 check.
type SecurityTxt struct{}

// ID implements Check.
func (SecurityTxt) ID() string { return "custom.security_txt" }

// securityTxtDetails is the Details payload of the security.txt finding.
type securityTxtDetails struct {
	URL              string    `json:"url"`
	RFC9116Compliant bool      `json:"rfc9116_compliant"`
	Expires          time.Time `json:"expires,omitempty"`
	Signed           bool      `json:"signed"`
	ContactCount     int       `json:"contact_count"`
	Note             string    `json:"note,omitempty"`
}

// Run implements Check.
func (s SecurityTxt) Run(ctx context.Context, target *safehttp.Target) scan.CustomFinding {
	url := target.URL("/.well-known/security.txt")
	body, status, mediaType, err := fetchText(ctx, target, "/.well-known/security.txt", securityTxtMaxBytes)
	if err != nil || status != http.StatusOK {
		return scan.CustomFinding{
			ID:     s.ID(),
			Title:  "security.txt",
			Status: scan.StatusFail,
			Details: mustJSON(securityTxtDetails{
				URL:  url,
				Note: fmt.Sprintf("HTTP %d", status),
			}),
		}
	}

	// RFC 9116 §2.4 mandates text/plain. Anything else (especially an
	// HTML SPA fallback served on /.well-known/security.txt) means the
	// file is missing — surface that rather than parsing the HTML.
	if isHTMLMediaType(mediaType) {
		return scan.CustomFinding{
			ID:     s.ID(),
			Title:  "security.txt",
			Status: scan.StatusFail,
			Details: mustJSON(securityTxtDetails{
				URL:  url,
				Note: fmt.Sprintf("served as %s — RFC 9116 §2.4 requires text/plain, likely a SPA fallback", mediaType),
			}),
		}
	}

	parsed := parseSecurityTxt(body)
	details := securityTxtDetails{
		URL:              url,
		Expires:          parsed.Expires,
		Signed:           parsed.Signed,
		ContactCount:     len(parsed.Contacts),
		RFC9116Compliant: parsed.compliant(),
	}

	finding := scan.CustomFinding{ID: s.ID(), Title: "security.txt"}
	switch {
	case len(parsed.Contacts) == 0:
		finding.Status = scan.StatusFail
	case parsed.Expires.IsZero():
		finding.Status = scan.StatusWarn // RFC 9116 makes Expires REQUIRED.
	case parsed.Expires.Before(time.Now()):
		finding.Status = scan.StatusWarn
	default:
		finding.Status = scan.StatusPass
	}
	finding.Details = mustJSON(details)
	return finding
}

// securityTxtParsed is the minimal set of fields we need to classify the file.
type securityTxtParsed struct {
	Contacts []string
	Expires  time.Time
	Signed   bool
}

func (p securityTxtParsed) compliant() bool {
	return len(p.Contacts) > 0 && !p.Expires.IsZero() && p.Expires.After(time.Now())
}

// parseSecurityTxt extracts Contact lines, the Expires timestamp, and a
// best-effort detection of a PGP-signed wrapper. Lines that do not match
// the "name: value" shape (including signature blocks) are ignored.
func parseSecurityTxt(body string) securityTxtParsed {
	out := securityTxtParsed{}
	if strings.Contains(body, "-----BEGIN PGP SIGNED MESSAGE-----") {
		out.Signed = true
	}
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "contact":
			if val != "" {
				out.Contacts = append(out.Contacts, val)
			}
		case "expires":
			// RFC 3339 §5.6 explicitly allows lowercase 't' and 'z' (and
			// fractional seconds), but time.RFC3339 is case-sensitive and
			// rejects them. Normalize case and fall back to RFC3339Nano.
			norm := strings.ToUpper(val)
			if t, err := time.Parse(time.RFC3339, norm); err == nil {
				out.Expires = t
			} else if t, err := time.Parse(time.RFC3339Nano, norm); err == nil {
				out.Expires = t
			}
		}
	}
	return out
}
