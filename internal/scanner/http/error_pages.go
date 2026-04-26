package http

import (
	"context"
	"regexp"
	"strings"

	"github.com/Jomar/websec101/internal/checks"
)

// stackTraceSignals are language-runtime tokens we expect to see only in
// debug pages. Hits on a public 404 indicate the framework's debug error
// renderer is reachable in production.
var stackTraceSignals = []string{
	`Traceback \(most recent call last\)`,
	`java\.lang\.`,
	`at org\.springframework`,
	`at sun\.reflect`,
	`System\.NullReferenceException`,
	`NoMethodError`,
	`undefined method`,
	`PHP Stack trace`,
	`Fatal error:`,
	`Notice: Undefined`,
	`runtime error:`,
	`goroutine `,
	`panic: `,
	`Exception:`,
	`line \d+ in`,
	`on line \d+`,
}

// defaultErrorPageSignals are byte-for-byte excerpts from canonical
// out-of-the-box error pages.
var defaultErrorPageSignals = []string{
	"<title>404 Not Found</title>",
	"The requested URL was not found on this server.",
	"<center>nginx/",
	"Apache/",
	"<h1>Not Found</h1>",
	"<title>IIS",
	"Server Error in '/' Application",
}

var stackTraceRegexes []*regexp.Regexp

func init() {
	for _, s := range stackTraceSignals {
		stackTraceRegexes = append(stackTraceRegexes, regexp.MustCompile(s))
	}
}

// --- HTTP-404-STACK-TRACE --------------------------------------------

type stackTraceCheck struct{}

func (stackTraceCheck) ID() string                       { return ID404StackTrace }
func (stackTraceCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (stackTraceCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (stackTraceCheck) Title() string                    { return "404 page does not leak a stack trace" }
func (stackTraceCheck) Description() string {
	return "A debug error renderer left enabled on production reveals frameworks, paths, and sometimes secrets."
}
func (stackTraceCheck) RFCRefs() []string { return []string{"OWASP Top 10 — A05"} }

func (stackTraceCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(ID404StackTrace, checks.FamilyHTTP, checks.SeverityHigh, err), nil
	}
	if res.NotFound == nil || res.NotFound.Err != nil {
		return skipped(ID404StackTrace, checks.FamilyHTTP, checks.SeverityHigh, "404 probe unreachable"), nil //nolint:nilerr // intentional
	}
	body := string(res.NotFound.Body)
	for _, re := range stackTraceRegexes {
		if re.FindStringIndex(body) != nil {
			return fail(ID404StackTrace, checks.FamilyHTTP, checks.SeverityHigh,
				"404 page contains stack-trace markers",
				"Disable debug renderers and ship a generic error page.",
				map[string]any{"signal": re.String()}), nil
		}
	}
	return pass(ID404StackTrace, checks.FamilyHTTP, checks.SeverityHigh,
		"404 page is clean", nil), nil
}

// --- HTTP-404-DEFAULT-ERROR-PAGE -------------------------------------

type defaultErrorPageCheck struct{}

func (defaultErrorPageCheck) ID() string                       { return ID404DefaultErrorPage }
func (defaultErrorPageCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (defaultErrorPageCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (defaultErrorPageCheck) Title() string                    { return "404 page is customised" }
func (defaultErrorPageCheck) Description() string {
	return "Default Apache / nginx / IIS error pages reveal stack identity. A custom page costs nothing and hides info."
}
func (defaultErrorPageCheck) RFCRefs() []string { return nil }

func (defaultErrorPageCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(ID404DefaultErrorPage, checks.FamilyHTTP, checks.SeverityLow, err), nil
	}
	if res.NotFound == nil || res.NotFound.Err != nil {
		return skipped(ID404DefaultErrorPage, checks.FamilyHTTP, checks.SeverityLow, "404 probe unreachable"), nil //nolint:nilerr // intentional
	}
	body := string(res.NotFound.Body)
	for _, sig := range defaultErrorPageSignals {
		if strings.Contains(body, sig) {
			return warn(ID404DefaultErrorPage, checks.FamilyHTTP, checks.SeverityLow,
				"404 page is the framework default",
				"Replace with a branded custom 404.",
				map[string]any{"signal": sig}), nil
		}
	}
	return pass(ID404DefaultErrorPage, checks.FamilyHTTP, checks.SeverityLow,
		"404 page is custom", nil), nil
}
