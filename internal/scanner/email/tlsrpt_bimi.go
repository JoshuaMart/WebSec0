package email

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// --- EMAIL-TLSRPT-MISSING --------------------------------------------

type tlsrptMissingCheck struct{}

func (tlsrptMissingCheck) ID() string                       { return IDTLSRPTMissing }
func (tlsrptMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (tlsrptMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (tlsrptMissingCheck) Title() string                    { return "Domain publishes TLS-RPT" }
func (tlsrptMissingCheck) Description() string {
	return "TLS-RPT (RFC 8460) lets receivers post failure reports about MTA-STS / DANE TLS issues."
}
func (tlsrptMissingCheck) RFCRefs() []string { return []string{"RFC 8460"} }

func (tlsrptMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDTLSRPTMissing, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDTLSRPTMissing, checks.SeverityLow); g != nil {
		return g, nil
	}
	if r.TLSRPT == "" {
		return fail(IDTLSRPTMissing, checks.SeverityLow,
			"no TLS-RPT record",
			"Publish a TXT record `v=TLSRPTv1; rua=mailto:tlsrpt@<domain>` on `_smtp._tls.<domain>`.",
			map[string]any{"queried": "_smtp._tls." + t.Hostname}), nil
	}
	return pass(IDTLSRPTMissing, checks.SeverityLow,
		"TLS-RPT record present",
		map[string]any{"raw": r.TLSRPT}), nil
}

// --- EMAIL-BIMI-MISSING ----------------------------------------------

type bimiMissingCheck struct{}

func (bimiMissingCheck) ID() string                       { return IDBIMIMissing }
func (bimiMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (bimiMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (bimiMissingCheck) Title() string                    { return "Domain publishes BIMI" }
func (bimiMissingCheck) Description() string {
	return "BIMI displays a verified brand logo next to your messages in supporting clients (Gmail, Apple Mail, Yahoo)."
}
func (bimiMissingCheck) RFCRefs() []string {
	return []string{"draft-brand-indicators-for-message-identification"}
}

func (bimiMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDBIMIMissing, checks.SeverityInfo, err), nil
	}
	if g := gateOnMX(r, IDBIMIMissing, checks.SeverityInfo); g != nil {
		return g, nil
	}
	if r.BIMI == "" {
		return fail(IDBIMIMissing, checks.SeverityInfo,
			"no BIMI record",
			"Publish a TXT record `v=BIMI1; l=https://…/logo.svg` on `default._bimi.<domain>`.",
			map[string]any{"queried": "default._bimi." + t.Hostname}), nil
	}
	return pass(IDBIMIMissing, checks.SeverityInfo,
		"BIMI record present",
		map[string]any{"raw": r.BIMI}), nil
}

// --- EMAIL-BIMI-INVALID-SVG ------------------------------------------

type bimiInvalidSVGCheck struct{}

func (bimiInvalidSVGCheck) ID() string                       { return IDBIMIInvalidSVG }
func (bimiInvalidSVGCheck) Family() checks.Family            { return checks.FamilyEmail }
func (bimiInvalidSVGCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (bimiInvalidSVGCheck) Title() string                    { return "BIMI logo is a valid SVG Tiny PS document" }
func (bimiInvalidSVGCheck) Description() string {
	return "BIMI logos must be SVG Tiny Portable/Secure (no scripts, correct SVG namespace, baseProfile='tiny-ps'). Non-compliant logos are rejected by Gmail, Apple Mail, and Yahoo."
}
func (bimiInvalidSVGCheck) RFCRefs() []string {
	return []string{"draft-brand-indicators-for-message-identification"}
}

func (bimiInvalidSVGCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDBIMIInvalidSVG, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDBIMIInvalidSVG, checks.SeverityLow); g != nil {
		return g, nil
	}
	if r.BIMI == "" {
		return skipped(IDBIMIInvalidSVG, checks.SeverityLow, "no BIMI record"), nil
	}

	logoURL := parseBIMILogoURL(r.BIMI)
	if logoURL == "" {
		return skipped(IDBIMIInvalidSVG, checks.SeverityLow,
			"no `l=` URL in BIMI record"), nil
	}

	issues := fetchAndValidateSVG(ctx, t, logoURL)
	ev := map[string]any{"logo_url": logoURL}
	if len(issues) > 0 {
		ev["issues"] = issues
		return fail(IDBIMIInvalidSVG, checks.SeverityLow,
			"BIMI logo SVG validation failed",
			strings.Join(issues, "; "),
			ev), nil
	}
	return pass(IDBIMIInvalidSVG, checks.SeverityLow,
		"BIMI logo passes SVG Tiny PS validation", ev), nil
}

// parseBIMILogoURL extracts the value of the `l=` tag from a BIMI record.
func parseBIMILogoURL(raw string) string {
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "l") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// fetchAndValidateSVG retrieves the SVG at url and performs a simplified
// SVG Tiny PS structural check. Returns a list of issues (empty = valid).
func fetchAndValidateSVG(ctx context.Context, t *checks.Target, url string) []string {
	cctx, cancel := context.WithTimeout(ctx, httpsTO)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return []string{"invalid URL: " + err.Error()}
	}
	req.Header.Set("User-Agent", t.UA())

	client := t.Client()
	if client == http.DefaultClient {
		client = &http.Client{Timeout: httpsTO}
	}
	resp, err := client.Do(req)
	if err != nil {
		return []string{"fetch error: " + err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10)) // 512 KB cap
	return checkSVGTinyPS(body)
}

// checkSVGTinyPS performs structural SVG Tiny PS validation on raw SVG bytes.
// Checks: no <script>, proper SVG namespace, baseProfile=tiny-ps.
func checkSVGTinyPS(data []byte) []string {
	var issues []string

	lower := strings.ToLower(string(data))

	// Fast pre-check: scripts forbidden in SVG Tiny PS.
	if strings.Contains(lower, "<script") {
		issues = append(issues, "contains <script> element (forbidden in SVG Tiny PS)")
	}
	if !strings.Contains(lower, "<svg") {
		return append(issues, "not an SVG document (no <svg> root element)")
	}

	// Parse the first start element with xml.Decoder to extract namespace
	// and baseProfile without loading the full document.
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil // accept any declared charset
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			issues = append(issues, "XML parse error: "+err.Error())
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		// First element must be <svg> in the SVG namespace.
		if start.Name.Local != "svg" {
			issues = append(issues, "root element is not <svg>: "+start.Name.Local)
			break
		}
		const svgNS = "http://www.w3.org/2000/svg"
		if start.Name.Space != "" && start.Name.Space != svgNS {
			issues = append(issues, "unexpected SVG namespace: "+start.Name.Space)
		}
		var baseProfile string
		for _, attr := range start.Attr {
			if attr.Name.Local == "baseProfile" {
				baseProfile = attr.Value
			}
		}
		if baseProfile != "tiny-ps" {
			issues = append(issues,
				fmt.Sprintf("baseProfile=%q, expected \"tiny-ps\"", baseProfile))
		}
		break
	}
	return issues
}
