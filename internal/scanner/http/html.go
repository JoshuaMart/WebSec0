package http

import (
	"bytes"
	"context"
	"strings"

	"golang.org/x/net/html"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/headers"
)

// htmlAssets is the digest of attribute values we care about per element.
type htmlAssets struct {
	Scripts       []scriptAsset
	Stylesheets   []linkAsset
	HTTPResources []mixedRef // plain-http sub-resources, with element-type context
}

type scriptAsset struct {
	Src       string
	Integrity string
	Crossorig string
}

type linkAsset struct {
	Href      string
	Integrity string
	Crossorig string
}

// mixedRef captures one plain-http sub-resource on a HTTPS page.
// Active=true means the element type can execute / control the page
// (script, link[stylesheet], iframe). Active=false means passive
// content (img, audio, video, source) — still a problem, but a softer
// one that browsers downgrade rather than block outright.
type mixedRef struct {
	URL         string
	ElementType string
	Active      bool
}

func parseAssets(body []byte) *htmlAssets {
	if len(bytes.TrimSpace(body)) == 0 {
		return &htmlAssets{}
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return &htmlAssets{}
	}
	a := &htmlAssets{}
	walk(doc, a)
	return a
}

func walk(n *html.Node, a *htmlAssets) {
	if n.Type == html.ElementNode {
		switch strings.ToLower(n.Data) {
		case "script":
			s := scriptAsset{}
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "src":
					s.Src = strings.TrimSpace(attr.Val)
				case "integrity":
					s.Integrity = strings.TrimSpace(attr.Val)
				case "crossorigin":
					s.Crossorig = strings.TrimSpace(attr.Val)
				}
			}
			if s.Src != "" {
				a.Scripts = append(a.Scripts, s)
				if strings.HasPrefix(strings.ToLower(s.Src), "http://") {
					a.HTTPResources = append(a.HTTPResources,
						mixedRef{URL: s.Src, ElementType: "script", Active: true})
				}
			}
		case "link":
			l := linkAsset{}
			rel := ""
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "rel":
					rel = strings.ToLower(attr.Val)
				case "href":
					l.Href = strings.TrimSpace(attr.Val)
				case "integrity":
					l.Integrity = strings.TrimSpace(attr.Val)
				case "crossorigin":
					l.Crossorig = strings.TrimSpace(attr.Val)
				}
			}
			if strings.Contains(rel, "stylesheet") && l.Href != "" {
				a.Stylesheets = append(a.Stylesheets, l)
				if strings.HasPrefix(strings.ToLower(l.Href), "http://") {
					a.HTTPResources = append(a.HTTPResources,
						mixedRef{URL: l.Href, ElementType: "link[stylesheet]", Active: true})
				}
			}
		case "img", "iframe", "audio", "video", "source":
			elem := strings.ToLower(n.Data)
			active := elem == "iframe"
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "src") {
					if strings.HasPrefix(strings.ToLower(attr.Val), "http://") {
						a.HTTPResources = append(a.HTTPResources,
							mixedRef{URL: attr.Val, ElementType: elem, Active: active})
					}
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, a)
	}
}

// isExternal reports whether asset URL is hosted on a different host
// than the target (external resources are the ones that should carry
// SRI per W3C SRI spec §3).
func isExternal(asset, host string) bool {
	if asset == "" {
		return false
	}
	low := strings.ToLower(asset)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		return false
	}
	// Strip scheme + path to compare hosts.
	rest := strings.TrimPrefix(strings.TrimPrefix(low, "http://"), "https://")
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	return rest != strings.ToLower(host)
}

// --- HTTP-MIXED-CONTENT ----------------------------------------------

type mixedContentCheck struct{}

func (mixedContentCheck) ID() string                       { return IDMixedContent }
func (mixedContentCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (mixedContentCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (mixedContentCheck) Title() string                    { return "Homepage has no mixed-content references" }
func (mixedContentCheck) Description() string {
	return "Browsers block / downgrade plain-HTTP sub-resources on HTTPS pages, and active mixed content can compromise the page entirely."
}
func (mixedContentCheck) RFCRefs() []string { return []string{"W3C Mixed Content"} }

func (mixedContentCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := headers.Fetch(ctx, t)
	if err != nil {
		return errFinding(IDMixedContent, checks.FamilyHTTP, checks.SeverityHigh, err), nil
	}
	if !res.Reachable {
		return skipped(IDMixedContent, checks.FamilyHTTP, checks.SeverityHigh, "homepage unreachable"), nil
	}
	a := parseAssets(res.Body)
	if len(a.HTTPResources) > 0 {
		return fail(IDMixedContent, checks.FamilyHTTP, checks.SeverityHigh,
			"homepage references plain-HTTP sub-resources",
			"Replace `http://` with `https://` (or with relative URLs).",
			map[string]any{"resources": uniqMixedRefs(a.HTTPResources)}), nil
	}
	return pass(IDMixedContent, checks.FamilyHTTP, checks.SeverityHigh,
		"no mixed content detected", nil), nil
}

// uniqMixedRefs deduplicates by URL — the same asset can appear several
// times in a page (e.g. <img> repeated in different sections); we want
// one row per distinct resource. Renders each row to a JSON-friendly
// map for evidence emission.
func uniqMixedRefs(refs []mixedRef) []map[string]any {
	seen := map[string]struct{}{}
	out := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		if _, ok := seen[r.URL]; ok {
			continue
		}
		seen[r.URL] = struct{}{}
		out = append(out, map[string]any{
			"url":     r.URL,
			"element": r.ElementType,
			"active":  r.Active,
		})
	}
	return out
}

// --- SRI-EXTERNAL-RESOURCE-NO-INTEGRITY ------------------------------

type sriCheck struct{}

func (sriCheck) ID() string                       { return IDSRIExternalNoIntegrity }
func (sriCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (sriCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (sriCheck) Title() string                    { return "External scripts/stylesheets carry SRI integrity" }
func (sriCheck) Description() string {
	return "Subresource Integrity (W3C SRI) makes the browser refuse a tampered third-party asset."
}
func (sriCheck) RFCRefs() []string { return []string{"W3C SRI"} }

func (sriCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := headers.Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSRIExternalNoIntegrity, checks.FamilyHTTP, checks.SeverityMedium, err), nil
	}
	if !res.Reachable {
		return skipped(IDSRIExternalNoIntegrity, checks.FamilyHTTP, checks.SeverityMedium, "homepage unreachable"), nil
	}
	a := parseAssets(res.Body)
	var bad []string
	for _, s := range a.Scripts {
		if isExternal(s.Src, t.Hostname) && s.Integrity == "" {
			bad = append(bad, s.Src)
		}
	}
	for _, l := range a.Stylesheets {
		if isExternal(l.Href, t.Hostname) && l.Integrity == "" {
			bad = append(bad, l.Href)
		}
	}
	if len(bad) > 0 {
		return fail(IDSRIExternalNoIntegrity, checks.FamilyHTTP, checks.SeverityMedium,
			"external assets without SRI integrity",
			"Add `integrity=\"sha384-…\"` (and `crossorigin=\"anonymous\"`) on every <script>/<link> from a third-party host.",
			map[string]any{"resources": uniq(bad)}), nil
	}
	if len(a.Scripts)+len(a.Stylesheets) == 0 {
		return skipped(IDSRIExternalNoIntegrity, checks.FamilyHTTP, checks.SeverityMedium, "no scripts/stylesheets on homepage"), nil
	}
	return pass(IDSRIExternalNoIntegrity, checks.FamilyHTTP, checks.SeverityMedium,
		"every external asset has SRI",
		map[string]any{"scripts": len(a.Scripts), "stylesheets": len(a.Stylesheets)}), nil
}

func uniq(s []string) []string {
	seen := map[string]struct{}{}
	out := s[:0]
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
