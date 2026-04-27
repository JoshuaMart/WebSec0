package headers

import (
	"context"
	"regexp"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// versionRegex catches things like "Apache/2.4.41" or "nginx/1.18.0".
var versionRegex = regexp.MustCompile(`(?i)\b[a-z][a-z0-9_+\-]*\s*[/\s]\s*\d+(?:\.\d+){1,3}`)

// disclosureCheck factors the "header X reveals stack info" pattern.
type disclosureCheck struct {
	id       string
	header   string
	severity checks.Severity
	title    string
	desc     string
	// matchVersion: when true, only fail if the value contains a version
	// (e.g. `Server: nginx` is fine; `Server: nginx/1.18.0` is not).
	matchVersion bool
}

func (c disclosureCheck) ID() string                       { return c.id }
func (disclosureCheck) Family() checks.Family              { return checks.FamilyHeaders }
func (c disclosureCheck) DefaultSeverity() checks.Severity { return c.severity }
func (c disclosureCheck) Title() string                    { return c.title }
func (c disclosureCheck) Description() string              { return c.desc }
func (disclosureCheck) RFCRefs() []string {
	return []string{"OWASP Secure Headers Project"}
}

func (c disclosureCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(c.id, c.severity, err), nil
	}
	if !res.Reachable {
		return skippedFinding(c.id, c.severity, "homepage unreachable"), nil
	}
	v := strings.TrimSpace(res.Header(c.header))
	if v == "" {
		return passFinding(c.id, c.severity,
			c.header+" not set", nil), nil
	}
	if c.matchVersion {
		if !versionRegex.MatchString(v) {
			return passFinding(c.id, c.severity,
				c.header+" present but no version revealed",
				map[string]any{"value": v}), nil
		}
	}
	return warnFinding(c.id, c.severity,
		c.header+" reveals stack/version info",
		"Strip or genericise this header at the reverse proxy.",
		map[string]any{"value": v}), nil
}

// --- info-disclosure registrations -----------------------------------

func newInfoServer() checks.Check {
	return disclosureCheck{
		id: IDInfoServer, header: "Server", severity: checks.SeverityInfo,
		title:        "Server header omitted or genericised",
		desc:         "`Server: Apache/2.4.41 (Ubuntu)` tells attackers exactly what they're up against.",
		matchVersion: true,
	}
}
func newInfoXPoweredBy() checks.Check {
	return disclosureCheck{
		id: IDInfoXPoweredBy, header: "X-Powered-By", severity: checks.SeverityLow,
		title: "X-Powered-By header is absent",
		desc:  "Express, PHP, ASP.NET expose framework + version here.",
	}
}
func newInfoXAspNetVersion() checks.Check {
	return disclosureCheck{
		id: IDInfoXAspNetVersion, header: "X-AspNet-Version", severity: checks.SeverityLow,
		title: "X-AspNet-Version header is absent",
		desc:  "ASP.NET-specific banner — disable it via web.config.",
	}
}
func newInfoXGenerator() checks.Check {
	return disclosureCheck{
		id: IDInfoXGenerator, header: "X-Generator", severity: checks.SeverityInfo,
		title: "X-Generator header is absent",
		desc:  "CMS-specific banner (Drupal, Wagtail, ...). Optional but classic.",
	}
}
func newInfoServerTiming() checks.Check {
	return disclosureCheck{
		id: IDInfoServerTiming, header: "Server-Timing", severity: checks.SeverityLow,
		title: "Server-Timing not exposed in production",
		desc:  "Server-Timing leaks backend latencies and component names — keep it staging-only.",
	}
}
