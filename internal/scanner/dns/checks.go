package dns

import (
	"context"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/Jomar/websec101/internal/checks"
)

// Check IDs.
const (
	IDDNSSECMissing  = "DNS-DNSSEC-MISSING"
	IDDNSSECWeakAlgo = "DNS-DNSSEC-WEAK-ALGO"
	IDDNSSECBroken   = "DNS-DNSSEC-BROKEN"
	IDCAAMissing     = "DNS-CAA-MISSING"
	IDCAANoIODEF     = "DNS-CAA-NO-IODEF"
	IDAAAAMissing    = "DNS-AAAA-MISSING"
	IDWildcardDetect = "DNS-WILDCARD-DETECTED"
	IDDanglingCNAME  = "DNS-DANGLING-CNAME"
	IDNSDiversityLow = "DNS-NS-DIVERSITY-LOW"
	IDTTLAberrant    = "DNS-TTL-ABERRANT"
)

// Register adds every DNS check to r.
func Register(r *checks.Registry) {
	r.Register(dnssecMissingCheck{})
	r.Register(dnssecWeakAlgoCheck{})
	r.Register(dnssecBrokenCheck{})
	r.Register(caaMissingCheck{})
	r.Register(caaNoIODEFCheck{})
	r.Register(aaaaMissingCheck{})
	r.Register(wildcardCheck{})
	r.Register(danglingCNAMECheck{})
	r.Register(nsDiversityCheck{})
	r.Register(ttlAberrantCheck{})
}

func errFinding(id string, sev checks.Severity, err error) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyDNS, Severity: sev,
		Status: checks.StatusError, Title: "dns: probe error", Description: err.Error(),
	}
}
func skipped(id string, sev checks.Severity, reason string) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyDNS, Severity: sev,
		Status: checks.StatusSkipped, Title: "skipped: " + reason,
	}
}
func pass(id string, sev checks.Severity, title string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyDNS, Severity: sev,
		Status: checks.StatusPass, Title: title, Evidence: ev,
	}
}
func fail(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyDNS, Severity: sev,
		Status: checks.StatusFail, Title: title, Description: desc, Evidence: ev,
	}
}
func warn(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyDNS, Severity: sev,
		Status: checks.StatusWarn, Title: title, Description: desc, Evidence: ev,
	}
}

// --- DNS-DNSSEC-MISSING ----------------------------------------------

type dnssecMissingCheck struct{}

func (dnssecMissingCheck) ID() string                       { return IDDNSSECMissing }
func (dnssecMissingCheck) Family() checks.Family            { return checks.FamilyDNS }
func (dnssecMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (dnssecMissingCheck) Title() string                    { return "Zone is signed with DNSSEC" }
func (dnssecMissingCheck) Description() string {
	return "DNSSEC (RFC 4033/4034/4035) authenticates DNS responses end-to-end. A DS record at the parent zone is the indicator of a signed zone."
}
func (dnssecMissingCheck) RFCRefs() []string { return []string{"RFC 4033", "RFC 4034", "RFC 4035"} }

func (dnssecMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDNSSECMissing, checks.SeverityMedium, err), nil
	}
	if len(r.DS) == 0 {
		return fail(IDDNSSECMissing, checks.SeverityMedium,
			"no DS record at the parent zone",
			"Enable DNSSEC at your registrar and publish a DS record.", nil), nil
	}
	return pass(IDDNSSECMissing, checks.SeverityMedium,
		"DNSSEC is enabled (DS records present)",
		map[string]any{"ds_count": len(r.DS)}), nil
}

// --- DNS-DNSSEC-WEAK-ALGO --------------------------------------------

// weakDSAlgo lists DNSKEY algorithm IDs deprecated by RFC 8624.
var weakDSAlgo = map[uint8]string{
	1: "RSAMD5",
	3: "DSA",
	5: "RSASHA1",
	6: "DSA-NSEC3-SHA1",
	7: "RSASHA1-NSEC3-SHA1",
}

type dnssecWeakAlgoCheck struct{}

func (dnssecWeakAlgoCheck) ID() string                       { return IDDNSSECWeakAlgo }
func (dnssecWeakAlgoCheck) Family() checks.Family            { return checks.FamilyDNS }
func (dnssecWeakAlgoCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (dnssecWeakAlgoCheck) Title() string                    { return "DNSSEC uses a modern signing algorithm" }
func (dnssecWeakAlgoCheck) Description() string {
	return "RFC 8624 forbids RSAMD5/DSA/RSASHA1; modern zones use ECDSA-P256 (alg 13) or Ed25519 (alg 15)."
}
func (dnssecWeakAlgoCheck) RFCRefs() []string { return []string{"RFC 8624"} }

func (dnssecWeakAlgoCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDNSSECWeakAlgo, checks.SeverityHigh, err), nil
	}
	if len(r.DS) == 0 {
		return skipped(IDDNSSECWeakAlgo, checks.SeverityHigh, "no DNSSEC"), nil
	}
	var weak []string
	for _, ds := range r.DS {
		if name, isWeak := weakDSAlgo[ds.Algorithm]; isWeak {
			weak = append(weak, name)
		}
	}
	if len(weak) > 0 {
		return fail(IDDNSSECWeakAlgo, checks.SeverityHigh,
			"DNSSEC uses a deprecated algorithm",
			"Re-sign with ECDSA-P256 (alg 13) or Ed25519 (alg 15).",
			map[string]any{"weak_algos": weak}), nil
	}
	return pass(IDDNSSECWeakAlgo, checks.SeverityHigh,
		"DNSSEC algorithms are modern", nil), nil
}

// --- DNS-DNSSEC-BROKEN -----------------------------------------------

type dnssecBrokenCheck struct{}

func (dnssecBrokenCheck) ID() string                       { return IDDNSSECBroken }
func (dnssecBrokenCheck) Family() checks.Family            { return checks.FamilyDNS }
func (dnssecBrokenCheck) DefaultSeverity() checks.Severity { return checks.SeverityCritical }
func (dnssecBrokenCheck) Title() string                    { return "DNSSEC validation succeeds" }
func (dnssecBrokenCheck) Description() string {
	return "When DS records exist but a validating resolver returns SERVFAIL or no AD bit, the zone is broken."
}
func (dnssecBrokenCheck) RFCRefs() []string { return []string{"RFC 4035"} }

func (dnssecBrokenCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDNSSECBroken, checks.SeverityCritical, err), nil
	}
	if len(r.DS) == 0 {
		return skipped(IDDNSSECBroken, checks.SeverityCritical, "no DNSSEC"), nil
	}
	if r.SOAErr != nil {
		// A SERVFAIL from a validating resolver IS the symptom we want
		// to flag; the lookup error is part of the finding, not a fault.
		return fail(IDDNSSECBroken, checks.SeverityCritical, //nolint:nilerr // intentional
			"validating resolver returned an error",
			r.SOAErr.Error(), nil), nil
	}
	if !r.AD {
		return fail(IDDNSSECBroken, checks.SeverityCritical,
			"validating resolver did not set the AD flag",
			"DNSSEC chain validation appears to be broken.", nil), nil
	}
	return pass(IDDNSSECBroken, checks.SeverityCritical,
		"DNSSEC validation succeeded (AD set)", nil), nil
}

// --- DNS-CAA-MISSING & DNS-CAA-NO-IODEF -------------------------------

type caaMissingCheck struct{}

func (caaMissingCheck) ID() string                       { return IDCAAMissing }
func (caaMissingCheck) Family() checks.Family            { return checks.FamilyDNS }
func (caaMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (caaMissingCheck) Title() string                    { return "Zone declares CAA records" }
func (caaMissingCheck) Description() string {
	return "CAA (RFC 8659) lists which CAs may issue certs for the domain — defence in depth against rogue issuance."
}
func (caaMissingCheck) RFCRefs() []string { return []string{"RFC 8659"} }

func (caaMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCAAMissing, checks.SeverityLow, err), nil
	}
	if len(r.CAA) == 0 {
		return fail(IDCAAMissing, checks.SeverityLow,
			"no CAA records",
			"Add CAA `issue \"<your-CA>\";` so other CAs refuse to issue.", nil), nil
	}
	return pass(IDCAAMissing, checks.SeverityLow,
		"CAA records present",
		map[string]any{"count": len(r.CAA)}), nil
}

type caaNoIODEFCheck struct{}

func (caaNoIODEFCheck) ID() string                       { return IDCAANoIODEF }
func (caaNoIODEFCheck) Family() checks.Family            { return checks.FamilyDNS }
func (caaNoIODEFCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (caaNoIODEFCheck) Title() string                    { return "CAA includes an iodef contact" }
func (caaNoIODEFCheck) Description() string {
	return "Add `iodef \"mailto:abuse@…\"` so CAs can report mis-issuance attempts."
}
func (caaNoIODEFCheck) RFCRefs() []string { return []string{"RFC 8659"} }

func (caaNoIODEFCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCAANoIODEF, checks.SeverityInfo, err), nil
	}
	if len(r.CAA) == 0 {
		return skipped(IDCAANoIODEF, checks.SeverityInfo, "no CAA"), nil
	}
	for _, c := range r.CAA {
		if strings.EqualFold(c.Tag, "iodef") {
			return pass(IDCAANoIODEF, checks.SeverityInfo,
				"CAA iodef contact present",
				map[string]any{"value": c.Value}), nil
		}
	}
	return fail(IDCAANoIODEF, checks.SeverityInfo,
		"CAA records have no iodef tag", "", nil), nil
}

// --- DNS-AAAA-MISSING ------------------------------------------------

type aaaaMissingCheck struct{}

func (aaaaMissingCheck) ID() string                       { return IDAAAAMissing }
func (aaaaMissingCheck) Family() checks.Family            { return checks.FamilyDNS }
func (aaaaMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (aaaaMissingCheck) Title() string                    { return "Hostname publishes IPv6" }
func (aaaaMissingCheck) Description() string {
	return "Many networks (mobile carriers, enterprise, ISP regions) are IPv6-only or IPv6-preferred."
}
func (aaaaMissingCheck) RFCRefs() []string { return nil }

func (aaaaMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDAAAAMissing, checks.SeverityLow, err), nil
	}
	if len(r.AAAA) == 0 {
		return fail(IDAAAAMissing, checks.SeverityLow,
			"no AAAA records",
			"Add IPv6 connectivity (`AAAA`) to reach IPv6-only networks.", nil), nil
	}
	return pass(IDAAAAMissing, checks.SeverityLow,
		"IPv6 reachable",
		map[string]any{"count": len(r.AAAA)}), nil
}

// --- DNS-WILDCARD-DETECTED -------------------------------------------

type wildcardCheck struct{}

func (wildcardCheck) ID() string                       { return IDWildcardDetect }
func (wildcardCheck) Family() checks.Family            { return checks.FamilyDNS }
func (wildcardCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (wildcardCheck) Title() string                    { return "Zone does not wildcard-resolve" }
func (wildcardCheck) Description() string {
	return "A wildcard A record absorbs typo-squatting traffic and complicates monitoring."
}
func (wildcardCheck) RFCRefs() []string { return nil }

func (wildcardCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDWildcardDetect, checks.SeverityInfo, err), nil
	}
	if r.Wildcard == nil {
		return skipped(IDWildcardDetect, checks.SeverityInfo, "wildcard probe failed"), nil
	}
	if r.Wildcard.Resolved {
		return warn(IDWildcardDetect, checks.SeverityInfo,
			"a randomised subdomain resolves",
			"This usually means a wildcard is in place. Audit it.",
			map[string]any{"probe": r.Wildcard.QueryName}), nil
	}
	return pass(IDWildcardDetect, checks.SeverityInfo,
		"random subdomain returned NXDOMAIN", nil), nil
}

// --- DNS-DANGLING-CNAME ----------------------------------------------

// danglingPatterns lists CNAME suffixes that point at popular SaaS
// platforms. If we see such a CNAME and the target itself fails to
// resolve, the domain is at risk of subdomain takeover.
//
// Source of inspiration: EdOverflow/can-i-take-over-xyz.
var danglingPatterns = []string{
	".s3.amazonaws.com",
	".s3-website-",
	".github.io",
	".herokuapp.com",
	".azurewebsites.net",
	".cloudapp.net",
	".netlify.app",
	".vercel.app",
	".fastly.net",
	".myshopify.com",
	".tumblr.com",
	".zendesk.com",
}

type danglingCNAMECheck struct{}

func (danglingCNAMECheck) ID() string                       { return IDDanglingCNAME }
func (danglingCNAMECheck) Family() checks.Family            { return checks.FamilyDNS }
func (danglingCNAMECheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (danglingCNAMECheck) Title() string                    { return "No dangling CNAME (subdomain takeover risk)" }
func (danglingCNAMECheck) Description() string {
	return "A CNAME pointing at a SaaS host whose backend is unclaimed lets attackers re-register and serve content under your domain."
}
func (danglingCNAMECheck) RFCRefs() []string { return []string{"EdOverflow/can-i-take-over-xyz"} }

func (danglingCNAMECheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDanglingCNAME, checks.SeverityHigh, err), nil
	}
	if len(r.CNAME) == 0 {
		return skipped(IDDanglingCNAME, checks.SeverityHigh, "no CNAME on the apex"), nil
	}
	for _, target := range r.CNAME {
		matched := ""
		lower := strings.ToLower(target)
		for _, p := range danglingPatterns {
			if strings.Contains(lower, p) {
				matched = p
				break
			}
		}
		if matched == "" {
			continue
		}
		// CNAME points at a SaaS pattern. Re-resolve target → if NXDOMAIN
		// or empty, dangling.
		resp, qerr := query(ctx, resolverAddr(t), target, mdns.TypeA, false)
		if qerr != nil {
			return warn(IDDanglingCNAME, checks.SeverityHigh,
				"CNAME target resolution failed",
				qerr.Error(),
				map[string]any{"cname_target": target, "matched": matched}), nil
		}
		if resp == nil || resp.Rcode == mdns.RcodeNameError || len(resp.Answer) == 0 {
			return fail(IDDanglingCNAME, checks.SeverityHigh,
				"CNAME points at an unclaimed SaaS endpoint",
				"The CNAME target is NXDOMAIN or empty — re-register or remove the CNAME.",
				map[string]any{"cname_target": target, "matched": matched}), nil
		}
	}
	return pass(IDDanglingCNAME, checks.SeverityHigh,
		"all CNAMEs resolve",
		map[string]any{"cnames": r.CNAME}), nil
}

// --- DNS-NS-DIVERSITY-LOW --------------------------------------------

type nsDiversityCheck struct{}

func (nsDiversityCheck) ID() string                       { return IDNSDiversityLow }
func (nsDiversityCheck) Family() checks.Family            { return checks.FamilyDNS }
func (nsDiversityCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (nsDiversityCheck) Title() string                    { return "Zone has ≥ 2 distinct nameservers" }
func (nsDiversityCheck) Description() string {
	return "RFC 2182 recommends at least two authoritative NS hostnames on different networks."
}
func (nsDiversityCheck) RFCRefs() []string { return []string{"RFC 2182"} }

func (nsDiversityCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDNSDiversityLow, checks.SeverityLow, err), nil
	}
	uniq := map[string]struct{}{}
	for _, ns := range r.NS {
		uniq[strings.ToLower(ns)] = struct{}{}
	}
	if len(uniq) < 2 {
		return fail(IDNSDiversityLow, checks.SeverityLow,
			"fewer than 2 distinct nameservers",
			"Publish at least two NS hostnames per RFC 2182.",
			map[string]any{"ns": r.NS}), nil
	}
	return pass(IDNSDiversityLow, checks.SeverityLow,
		"≥ 2 distinct nameservers",
		map[string]any{"ns": r.NS}), nil
}

// --- DNS-TTL-ABERRANT ------------------------------------------------

const (
	ttlMin = 60        // 1 minute
	ttlMax = 86400 * 7 // 7 days
)

type ttlAberrantCheck struct{}

func (ttlAberrantCheck) ID() string                       { return IDTTLAberrant }
func (ttlAberrantCheck) Family() checks.Family            { return checks.FamilyDNS }
func (ttlAberrantCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (ttlAberrantCheck) Title() string                    { return "A/AAAA TTL is in a sensible range" }
func (ttlAberrantCheck) Description() string {
	return "TTL < 60s causes unnecessary lookup load; TTL > 7d makes incident rotation slow."
}
func (ttlAberrantCheck) RFCRefs() []string { return nil }

func (ttlAberrantCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDTTLAberrant, checks.SeverityInfo, err), nil
	}
	ttl := r.ATTL
	if ttl == 0 {
		ttl = r.AAAATTL
	}
	if ttl == 0 {
		return skipped(IDTTLAberrant, checks.SeverityInfo, "no A/AAAA records"), nil
	}
	ev := map[string]any{"ttl_seconds": ttl}
	if ttl < ttlMin {
		return warn(IDTTLAberrant, checks.SeverityInfo,
			"TTL is unusually low",
			"Sub-minute TTLs hammer your DNS bill and don't help most rotation use-cases.", ev), nil
	}
	if ttl > ttlMax {
		return warn(IDTTLAberrant, checks.SeverityInfo,
			"TTL is unusually high",
			"Long TTLs slow down emergency rotations.", ev), nil
	}
	return pass(IDTTLAberrant, checks.SeverityInfo,
		"TTL is in a sensible range", ev), nil
}
