package custom

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// robotsTxtMaxBytes caps the /robots.txt fetch. The largest files in the wild
// are around 100 KiB (search-engine-heavy sites); 256 KiB is generous.
const robotsTxtMaxBytes = 256 * 1024

// RobotsTxt is the robots.txt check. Its primary security relevance is
// information leak: a Disallow line publicly advertises that a path exists.
type RobotsTxt struct{}

// ID implements Check.
func (RobotsTxt) ID() string { return "custom.robots_txt" }

type robotsTxtDetails struct {
	URL                string   `json:"url"`
	SizeBytes          int      `json:"size_bytes"`
	Parseable          bool     `json:"parseable"`
	SuspiciousDisallow []string `json:"suspicious_disallow,omitempty"`
	Note               string   `json:"note,omitempty"`
}

// Run implements Check.
func (r RobotsTxt) Run(ctx context.Context, target *safehttp.Target) scan.CustomFinding {
	url := target.URL("/robots.txt")
	body, status, mediaType, err := fetchText(ctx, target, "/robots.txt", robotsTxtMaxBytes)
	finding := scan.CustomFinding{ID: r.ID(), Title: "robots.txt"}

	if err != nil || status != http.StatusOK {
		finding.Status = scan.StatusInfo
		finding.Details = mustJSON(robotsTxtDetails{
			URL:  url,
			Note: fmt.Sprintf("HTTP %d", status),
		})
		return finding
	}

	// Content-Type is the authoritative signal that a server actually
	// serves a robots.txt rather than answering /robots.txt with its SPA
	// shell. RFC 9309 doesn't mandate a specific media type but every
	// real-world implementation uses text/plain; an HTML response is
	// unambiguous evidence the file is missing.
	if isHTMLMediaType(mediaType) {
		finding.Status = scan.StatusInfo
		finding.Details = mustJSON(robotsTxtDetails{
			URL:       url,
			SizeBytes: len(body),
			Parseable: false,
			Note:      fmt.Sprintf("served as %s — likely a SPA fallback, not a robots.txt", mediaType),
		})
		return finding
	}

	suspicious := findSuspiciousDisallows(body)
	details := robotsTxtDetails{
		URL:                url,
		SizeBytes:          len(body),
		Parseable:          true,
		SuspiciousDisallow: suspicious,
	}
	if len(suspicious) > 0 {
		finding.Status = scan.StatusWarn
	} else {
		finding.Status = scan.StatusPass
	}
	finding.Details = mustJSON(details)
	return finding
}

// suspiciousPathPrefixes is the closed list of path prefixes that, when
// explicitly disallowed, suggest the operator is hiding a sensitive path
// from crawlers — a form of security-by-obscurity that effectively
// confirms the path exists. Lowercase, leading slash.
var suspiciousPathPrefixes = []string{
	"/admin", "/administrator",
	"/internal", "/private",
	"/api",
	"/wp-admin", "/wp-login",
	"/.git", "/.env", "/.aws", "/.ssh",
	"/backup", "/dump", "/db",
	"/debug",
}

// findSuspiciousDisallows scans body and returns the de-duplicated set of
// Disallow values whose path matches a suspicious prefix. Blanket
// "Disallow: /" entries are ignored — they do not leak a specific path.
func findSuspiciousDisallows(body string) []string {
	seen := map[string]bool{}
	var out []string

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(kv[0])) != "disallow" {
			continue
		}
		val := strings.TrimSpace(kv[1])
		if val == "" || val == "/" {
			continue
		}
		lo := strings.ToLower(val)
		for _, p := range suspiciousPathPrefixes {
			if strings.HasPrefix(lo, p) {
				if !seen[val] {
					seen[val] = true
					out = append(out, val)
				}
				break
			}
		}
	}
	return out
}
