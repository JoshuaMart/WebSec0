package http

import (
	"context"
	"strings"

	"github.com/Jomar/websec101/internal/checks"
)

// --- ROBOTS-TXT-INVALID ----------------------------------------------
//
// We do *not* judge the policy itself (allow/disallow) — only the file
// shape. Lines must be `directive: value` or comments / blanks.
// A 200 with non-text/plain content-type, or a body that doesn't follow
// the line shape at all, is suspicious.

type robotsCheck struct{}

func (robotsCheck) ID() string                       { return IDRobotsTxtInvalid }
func (robotsCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (robotsCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (robotsCheck) Title() string                    { return "robots.txt parses correctly when present" }
func (robotsCheck) Description() string {
	return "A robots.txt that returns HTML or no recognised directives is usually a misconfigured route."
}
func (robotsCheck) RFCRefs() []string { return []string{"RFC 9309"} }

func (robotsCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDRobotsTxtInvalid, checks.FamilyHTTP, checks.SeverityInfo, err), nil
	}
	if res.Robots == nil || res.Robots.Err != nil {
		return skipped(IDRobotsTxtInvalid, checks.FamilyHTTP, checks.SeverityInfo, "robots.txt unreachable"), nil //nolint:nilerr // intentional
	}
	if res.Robots.Status != 200 {
		return skipped(IDRobotsTxtInvalid, checks.FamilyHTTP, checks.SeverityInfo, "no robots.txt"), nil
	}
	ct := strings.ToLower(res.Robots.Headers.Get("Content-Type"))
	if ct != "" && !strings.Contains(ct, "text/plain") && !strings.Contains(ct, "text/x-robots") {
		return fail(IDRobotsTxtInvalid, checks.FamilyHTTP, checks.SeverityInfo,
			"robots.txt is not text/plain",
			"Serve as `Content-Type: text/plain; charset=utf-8`.",
			map[string]any{"content_type": ct}), nil
	}
	body := string(res.Robots.Body)
	if strings.Contains(strings.ToLower(body), "<html") || strings.Contains(body, "<!doctype") {
		return fail(IDRobotsTxtInvalid, checks.FamilyHTTP, checks.SeverityInfo,
			"robots.txt body looks like HTML",
			"Likely the SPA fallback handler is serving the index page on this path.", nil), nil
	}
	if !looksLikeRobotsTxt(body) {
		return fail(IDRobotsTxtInvalid, checks.FamilyHTTP, checks.SeverityInfo,
			"robots.txt has no recognised directive",
			"Expected at least one `User-agent:` / `Disallow:` / `Allow:` / `Sitemap:` line.", nil), nil
	}
	return pass(IDRobotsTxtInvalid, checks.FamilyHTTP, checks.SeverityInfo,
		"robots.txt parses cleanly", nil), nil
}

func looksLikeRobotsTxt(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:colon]))
		switch k {
		case "user-agent", "disallow", "allow", "sitemap", "crawl-delay", "host":
			return true
		}
	}
	return false
}
