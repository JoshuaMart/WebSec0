package tls

import (
	"regexp"
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// DeriveWeaknesses turns the observed TLS protocols + ciphers and the
// HTTP Server header into a list of presence-based vulnerability findings.
// Active-probing-only weaknesses are emitted as info-level placeholders so
// the report stays exhaustive.
//
// The function is called by the scan orchestrator after both the TLS and
// headers probes complete, because Heartbleed and Ticketbleed need the
// HTTP Server header to fingerprint the running software.
func DeriveWeaknesses(protocols []scan.ProtocolSupport, ciphers []scan.Cipher, serverHeader string) []scan.VulnerabilityFinding {
	has := map[string]bool{}
	for _, p := range protocols {
		if p.Offered {
			has[p.Name] = true
		}
	}

	var has3DES, hasRC4, hasLegacyCBC bool
	for _, c := range ciphers {
		name := c.Name
		if strings.Contains(name, "3DES") || strings.Contains(name, "_DES_") {
			has3DES = true
		}
		if strings.Contains(name, "RC4") {
			hasRC4 = true
		}
		if !c.AEAD && (c.Protocol == "TLS 1.0" || c.Protocol == "TLS 1.1") {
			hasLegacyCBC = true
		}
	}

	heartbleed := isHeartbleedVulnerable(serverHeader)
	ticketbleed := isF5BigIP(serverHeader)

	return []scan.VulnerabilityFinding{
		// Actively detected.
		finding("POODLE", "CVE-2014-3566", has["SSL 3.0"],
			"SSLv3 is enabled — POODLE is exploitable.",
			"SSLv3 is disabled."),
		finding("DROWN", "CVE-2016-0800", has["SSL 2.0"],
			"SSLv2 is enabled on this service.",
			"SSLv2 is disabled."),
		finding("BEAST", "CVE-2011-3389", has["TLS 1.0"],
			"TLS 1.0 is enabled — CBC paths are exploitable.",
			"TLS 1.0 is disabled."),
		finding("Sweet32", "CVE-2016-2183", has3DES,
			"A 3DES cipher is offered (64-bit block).",
			"No 3DES cipher offered."),
		finding("RC4 weakness", "CVE-2015-2808", hasRC4,
			"RC4 cipher is offered.",
			"RC4 cipher is not offered."),
		finding("Heartbleed", "CVE-2014-0160", heartbleed,
			"Server advertises an OpenSSL version in the 1.0.1–1.0.1f range (Heartbleed-vulnerable).",
			"No vulnerable OpenSSL version advertised in the Server header."),
		finding("Lucky13", "CVE-2013-0169", hasLegacyCBC,
			"TLS 1.0/1.1 with a CBC cipher is offered — vulnerable to padding-oracle timing.",
			"No CBC ciphers offered on TLS 1.0/1.1."),
		suspectFinding("Ticketbleed", "CVE-2016-9244", ticketbleed,
			"F5 BIG-IP detected via Server header. Confirm the running version is patched (>= 12.0.0 HF2 / >= 11.6.1 HF1).",
			"Server header does not advertise F5 BIG-IP."),

		// Still placeholders — see TODO.md Phase 4 for the breakdown of why.
		infoFinding("CRIME", "CVE-2012-4929",
			"TLS compression inspection requires raw probing — not implemented in v1."),
		infoFinding("FREAK", "CVE-2015-0204",
			"Export-grade cipher detection requires raw ClientHello — stdlib does not enumerate export suites."),
		infoFinding("Logjam", "CVE-2015-4000",
			"DH group inspection in ServerKeyExchange not implemented in v1."),
		infoFinding("Raccoon Attack", "CVE-2020-1968",
			"DH-share comparison across multiple handshakes not implemented in v1."),
	}
}

// heartbleedOpenSSL matches an OpenSSL version string in the
// Heartbleed-vulnerable range: 1.0.1 (no suffix) and 1.0.1a..1.0.1f.
// The trailing class enforces a version-boundary so 1.0.1g+, 1.0.10+ or
// surprising things like "1.0.1fips" do not match.
var heartbleedOpenSSL = regexp.MustCompile(`(?i)openssl/1\.0\.1([a-f])?([^a-z0-9]|$)`)

func isHeartbleedVulnerable(serverHeader string) bool {
	if serverHeader == "" {
		return false
	}
	return heartbleedOpenSSL.MatchString(serverHeader)
}

func isF5BigIP(serverHeader string) bool {
	return strings.Contains(strings.ToUpper(serverHeader), "BIG-IP")
}

func finding(id, cve string, vulnerable bool, badBody, goodBody string) scan.VulnerabilityFinding {
	if vulnerable {
		return scan.VulnerabilityFinding{
			ID: id, CVE: cve, State: "Vulnerable",
			Level: scan.SeverityBad, Body: badBody,
		}
	}
	return scan.VulnerabilityFinding{
		ID: id, CVE: cve, State: "Not vulnerable",
		Level: scan.SeverityGood, Body: goodBody,
	}
}

// suspectFinding emits a warn-level finding when the detection is a
// heuristic that cannot fully prove vulnerability — typically a
// fingerprint that narrows the suspect surface (e.g. F5 BIG-IP).
func suspectFinding(id, cve string, suspect bool, suspectBody, goodBody string) scan.VulnerabilityFinding {
	if suspect {
		return scan.VulnerabilityFinding{
			ID: id, CVE: cve, State: "Potentially vulnerable",
			Level: scan.SeverityWarn, Body: suspectBody,
		}
	}
	return scan.VulnerabilityFinding{
		ID: id, CVE: cve, State: "Not vulnerable",
		Level: scan.SeverityGood, Body: goodBody,
	}
}

func infoFinding(id, cve, body string) scan.VulnerabilityFinding {
	return scan.VulnerabilityFinding{
		ID: id, CVE: cve, State: "Not assessed",
		Level: scan.SeverityInfo, Body: body,
	}
}
