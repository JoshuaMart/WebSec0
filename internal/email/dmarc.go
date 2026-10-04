package email

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

var tagName = regexp.MustCompile(`^[A-Za-z]+$`)

type dmarcPolicy struct {
	record   string
	domain   string
	tags     map[string]string
	warnings []string
	unusable bool
}

func inspectDMARC(domain string, lookup lookupFunc) scan.DMARCReport {
	out := scan.DMARCReport{DNSRecord: newRecord("email.dmarc"), Queries: []string{}, ReportingURIs: []string{}}
	var candidate *dmarcPolicy
	var invalid bool
	for _, name := range treeNames(domain) {
		query := "_dmarc." + name
		out.Queries = append(out.Queries, query)
		records, err := lookup(query)
		if err != nil {
			unavailable(&out.DNSRecord, query)
			return out
		}
		relevant := []string{}
		for _, record := range records {
			first, _, _ := strings.Cut(record, ";")
			key, value, ok := strings.Cut(first, "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), "v") && strings.TrimSpace(value) == "DMARC1" {
				relevant = append(relevant, record)
			}
		}
		var policy *dmarcPolicy
		if len(relevant) == 1 {
			policy = parseDMARC(relevant[0], name)
		}
		if len(relevant) > 0 && policy == nil {
			invalid = true
			out.Warnings = append(out.Warnings, fmt.Sprintf("No usable DMARC policy at %s: malformed policy or multiple DMARC records.", query))
			if name == domain {
				out.Records = relevant
			}
			continue
		}
		if policy == nil {
			continue
		}
		if name == domain {
			return applyDMARC(&out, policy, domain)
		}
		switch policy.tags["psd"] {
		case "n":
			return applyDMARC(&out, policy, domain)
		case "y":
			// The organizational domain is one label below the PSD. Prefer its
			// record if found; otherwise apply the PSD record (RFC 9989 §4.10).
			if candidate != nil && parent(candidate.domain) == name {
				return applyDMARC(&out, candidate, domain)
			}
			return applyDMARC(&out, policy, domain)
		default:
			candidate = policy // Without a boundary, the fewest-label policy wins.
		}
	}
	if candidate != nil {
		return applyDMARC(&out, candidate, domain)
	}
	if invalid {
		out.State = scan.DNSRecordInvalid
	}
	return out
}

func applyDMARC(out *scan.DMARCReport, p *dmarcPolicy, domain string) scan.DMARCReport {
	out.Records = []string{p.record}
	out.Warnings = append(out.Warnings, p.warnings...)
	if p.unusable {
		out.State = scan.DNSRecordInvalid
		return *out
	}
	out.State = scan.DNSRecordObserved
	out.PolicyDomain, out.Inherited = p.domain, p.domain != domain
	out.Policy, out.PolicyTag = p.tags["p"], "p"
	raw, present := p.tags["rua"]
	out.ReportingState = "absent"
	if present {
		var invalid bool
		out.ReportingURIs, invalid = reportingURIs(raw)
		out.ReportingState = "invalid"
		if len(out.ReportingURIs) > 0 {
			out.ReportingState = "configured"
		}
		if invalid {
			out.Warnings = append(out.Warnings, "The rua tag contains an invalid reporting URI; correct it to request aggregate reports reliably.")
		}
	}

	if out.Inherited && p.tags["sp"] != "" {
		out.Policy, out.PolicyTag = p.tags["sp"], "sp"
	}
	out.Testing = p.tags["t"] == "y"
	if out.Testing {
		switch out.Policy {
		case "reject":
			out.Policy = "quarantine"
		case "quarantine":
			out.Policy = "none"
		}
		out.Warnings = append(out.Warnings, "DMARC testing mode (t=y) is enabled: reject becomes quarantine, and quarantine becomes none.")
	}
	return *out
}

func treeNames(domain string) []string {
	names := []string{domain}
	labels := strings.Split(domain, ".")
	if len(labels) > 8 {
		labels = labels[len(labels)-7:]
	} else {
		labels = labels[1:]
	}
	for len(labels) > 0 {
		names = append(names, strings.Join(labels, "."))
		labels = labels[1:]
	}
	return names
}

func parent(domain string) string {
	_, rest, _ := strings.Cut(domain, ".")
	return rest
}

func parseDMARC(record, domain string) *dmarcPolicy {
	tags := map[string]string{}
	var malformed bool
	parts := strings.Split(record, ";")
	for i, part := range parts {
		part = strings.Trim(part, " \t\r\n")
		if part == "" && i == len(parts)-1 {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if i == 0 && (!ok || name != "v" || value != "DMARC1") {
			return nil
		}
		if !ok || !tagName.MatchString(name) {
			malformed = true
			continue
		}
		switch name {
		case "v", "p", "sp", "np", "psd", "t", "adkim", "aspf", "rua", "ruf", "fo", "ri", "rf", "pct":
		default:
			continue // Unknown extensions do not participate in policy validation.
		}
		if _, duplicate := tags[name]; duplicate {
			return nil
		}
		valid := value != ""
		for _, c := range value {
			if c < 32 || c > 126 {
				valid = false
			}
		}
		if !valid && name != "p" && name != "sp" && name != "np" && name != "rua" {
			malformed = true
			continue
		}
		switch name {
		case "p", "sp", "np", "psd", "t", "adkim", "aspf":
			value = strings.ToLower(value)
		}
		tags[name] = value
	}
	if tags["v"] != "DMARC1" {
		return nil
	}
	out := &dmarcPolicy{record: record, domain: domain, tags: tags}
	if malformed {
		out.warnings = append(out.warnings, "Malformed optional DMARC tags were ignored; defaults apply where defined.")
	}
	if _, exists := tags["p"]; !exists {
		tags["p"] = "none"
		out.warnings = append(out.warnings, "No p tag is published; RFC 9989 defaults to none. Older DMARC implementations may treat this record differently.")
	}
	badPolicy := !policyValue(tags["p"])
	for _, key := range []string{"sp", "np"} {
		if value, exists := tags[key]; exists && !policyValue(value) {
			badPolicy = true
		}
	}
	if badPolicy {
		if !hasReportingURI(tags["rua"]) {
			out.unusable = true
			out.warnings = append(out.warnings, "An invalid policy tag without a usable reporting URI prevents DMARC processing (RFC 9989).")
		} else {
			tags["p"] = "none"
			delete(tags, "sp")
			delete(tags, "np")
			out.warnings = append(out.warnings, "An invalid policy tag falls back to none because a reporting URI is present (RFC 9989).")
		}
	}
	for _, item := range []struct{ key, choices, fallback string }{
		{"psd", "ynu", "u"}, {"t", "yn", "n"}, {"adkim", "rs", "r"}, {"aspf", "rs", "r"},
	} {
		if value, exists := tags[item.key]; exists && (len(value) != 1 || !strings.Contains(item.choices, value)) {
			tags[item.key] = item.fallback
			out.warnings = append(out.warnings, fmt.Sprintf("Invalid %s tag; the default %s is used.", item.key, item.fallback))
		}
	}
	if _, exists := tags["pct"]; exists {
		out.warnings = append(out.warnings, "The legacy pct tag is ignored by RFC 9989; older receivers may apply it.")
	}
	return out
}

func policyValue(value string) bool {
	return value == "none" || value == "quarantine" || value == "reject"
}

func hasReportingURI(value string) bool {
	uris, _ := reportingURIs(value)
	return len(uris) > 0
}

// Reporting destinations are inspected as data only, never contacted.
func reportingURIs(value string) ([]string, bool) {
	uris := []string{}
	invalid := false
	for _, raw := range strings.Split(value, ",") {
		uri, _, _ := strings.Cut(strings.TrimSpace(raw), "!")
		if !validReportingURI(uri) {
			invalid = true
			continue
		}
		uris = append(uris, uri)
	}
	return uris, invalid
}

func validReportingURI(uri string) bool {
	if strings.ContainsAny(uri, " \t\r\n") {
		return false
	}
	parsed, err := url.Parse(uri)
	if err != nil || !parsed.IsAbs() {
		return false
	}
	if parsed.Scheme != "mailto" {
		return parsed.Opaque != "" || parsed.Host != ""
	}
	address, err := url.PathUnescape(parsed.Opaque)
	if err != nil || parsed.Fragment != "" {
		return false
	}
	// ParseAddress accepts display names and comments; mailto requires addr-spec.
	var quoted, escaped bool
	for _, c := range address {
		switch {
		case escaped:
			escaped = false
		case c == '\\' && quoted:
			escaped = true
		case c == '"':
			quoted = !quoted
		case !quoted && strings.ContainsRune(" \t\r\n()<>", c):
			return false
		}
	}
	mailbox, err := mail.ParseAddress(address)
	return err == nil && mailbox.Name == ""
}
