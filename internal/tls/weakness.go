package tls

import (
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// deriveWeaknesses turns the observed protocols + ciphers into a list of
// presence-based vulnerability findings. Items that require active probing
// or deeper protocol inspection (Heartbleed, ROBOT, CRIME, FREAK, Logjam,
// Lucky13, Raccoon, Ticketbleed) are emitted as info-level placeholders so
// the report stays exhaustive — they will be upgraded in a future iteration.
func deriveWeaknesses(protocols []scan.ProtocolSupport, ciphers []scan.Cipher) []scan.VulnerabilityFinding {
	has := map[string]bool{}
	for _, p := range protocols {
		if p.Offered {
			has[p.Name] = true
		}
	}

	var has3DES, hasRC4 bool
	for _, c := range ciphers {
		n := c.Name
		if strings.Contains(n, "3DES") || strings.Contains(n, "_DES_") {
			has3DES = true
		}
		if strings.Contains(n, "RC4") {
			hasRC4 = true
		}
	}

	return []scan.VulnerabilityFinding{
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
		infoFinding("Heartbleed", "CVE-2014-0160",
			"Detection requires active probing not performed in passive mode."),
		infoFinding("ROBOT", "CVE-2017-13099",
			"Detection requires active probing not performed in passive mode."),
		infoFinding("CRIME", "CVE-2012-4929",
			"TLS compression inspection not implemented in v1."),
		infoFinding("FREAK", "CVE-2015-0204",
			"Export-grade cipher detection not implemented in v1."),
		infoFinding("Logjam", "CVE-2015-4000",
			"DH parameter inspection not implemented in v1."),
		infoFinding("Lucky13", "CVE-2013-0169",
			"CBC timing analysis not performed in passive mode."),
		infoFinding("Raccoon Attack", "CVE-2020-1968",
			"DH-share comparison across handshakes not implemented in v1."),
		infoFinding("Ticketbleed", "CVE-2016-9244",
			"F5 fingerprinting not implemented in v1."),
	}
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

func infoFinding(id, cve, body string) scan.VulnerabilityFinding {
	return scan.VulnerabilityFinding{
		ID: id, CVE: cve, State: "Not assessed",
		Level: scan.SeverityInfo, Body: body,
	}
}
