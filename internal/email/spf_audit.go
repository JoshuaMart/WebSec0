package email

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

const maxSPFLookupTerms = 10

type spfAudit struct {
	out     *scan.SPFAudit
	lookup  lookupFunc
	records map[string]*scan.SPFReport
	active  map[string]bool
}

func auditSPF(domain string, root *scan.SPFReport, lookup lookupFunc) *scan.SPFAudit {
	out := &scan.SPFAudit{Complete: true, Queries: []string{domain}, Issues: []string{}, Limitations: []string{}}
	a := spfAudit{out: out, lookup: lookup, records: map[string]*scan.SPFReport{domain: root}, active: map[string]bool{}}
	a.walk(domain, root)
	out.Complete = len(out.Limitations) == 0 && len(out.Issues) == 0
	return out
}

// walk follows only mechanisms before the first all, and a redirect only without
// all. Term counts include repeated references even when their TXT is cached.
func (a *spfAudit) walk(domain string, record *scan.SPFReport) {
	a.active[domain] = true
	defer delete(a.active, domain)
	for _, term := range strings.Fields(record.Records[0])[1:] {
		if i := strings.IndexAny(term, "=:/"); i >= 0 && term[i] == '=' {
			continue
		}
		term = strings.TrimLeft(term, "+-~?")
		name, arg, _ := strings.Cut(term, ":")
		name, _, _ = strings.Cut(name, "/")
		switch strings.ToLower(name) {
		case "all":
			return
		case "include":
			if !a.countTerm() {
				return
			}
			a.dependency(arg)
		case "a", "mx", "ptr", "exists":
			if !a.countTerm() {
				return
			}
			a.limit("Address mechanisms (a, mx, ptr, exists) and their void-lookup limits require further evaluation.")
		}
		if a.out.LookupLimitExceeded {
			return
		}
	}
	if record.All == "" && record.Redirect != "" && a.countTerm() {
		a.dependency(record.Redirect)
	}
}

func (a *spfAudit) countTerm() bool {
	a.out.LookupTerms++
	if a.out.LookupTerms > maxSPFLookupTerms {
		a.out.LookupLimitExceeded = true
		a.limit("The conservative dependency walk exceeds SPF's 10 DNS-causing terms. The actual path depends on the sender; further expansion stopped.")
		return false
	}
	return true
}

func (a *spfAudit) dependency(raw string) {
	if strings.Contains(raw, "%") {
		a.limit("Macro-based SPF dependencies cannot be resolved without a sender context.")
		return
	}
	name := strings.ToLower(strings.TrimSuffix(raw, "."))
	if !literalDNSName(name) {
		a.issue(fmt.Sprintf("Dependency %q is not a usable DNS name.", raw))
		return
	}
	if a.active[name] {
		a.issue(fmt.Sprintf("Circular SPF dependency through %s; a sender reaching this cycle can exceed the lookup limit.", name))
		return
	}
	record, ok := a.records[name]
	if !ok {
		a.out.Queries = append(a.out.Queries, name)
		fetched := inspectSPF(name, a.lookup)
		record = &fetched
		a.records[name] = record
	}
	switch record.State {
	case scan.DNSRecordAbsent:
		a.issue(fmt.Sprintf("No SPF policy at %s; an include or redirect reaching it returns an SPF error.", name))
	case scan.DNSRecordInvalid:
		a.issue(fmt.Sprintf("Invalid SPF policy at %s; review its TXT records.", name))
	case scan.DNSRecordUnavailable:
		a.limit(fmt.Sprintf("DNS for dependency %s was unavailable; its policy could not be checked.", name))
	case scan.DNSRecordObserved:
		if len(record.Warnings) > 0 {
			a.limit(fmt.Sprintf("Dependency %s has policy warnings: %s", name, strings.Join(record.Warnings, " ")))
		}
		a.walk(name, record)
	}
}

func (a *spfAudit) issue(message string) {
	a.out.Issues = appendUnique(a.out.Issues, message)
}

func (a *spfAudit) limit(message string) {
	a.out.Limitations = appendUnique(a.out.Limitations, message)
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

// Dependencies are absolute DNS names, never URLs or IP connection targets.
func literalDNSName(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}
