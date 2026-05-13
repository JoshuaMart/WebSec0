package scoring

import (
	"strings"

	"github.com/JoshuaMart/websec0/internal/headers"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// TLSFinal combines the four sub-scores via the formula, applies
// trust/protocol/cipher floors and finally enforces the HSTS-preload
// requirement for A+. A nil HeadersReport caps the grade at A even when
// the score would otherwise reach A+ (preload eligibility is unknown).
//
//	final = (cert × 0.30) + (((proto + kx + cipher) / 3) × 0.70)
func TLSFinal(t *scan.TLSReport, h *scan.HeadersReport) (scan.TLSScores, scan.Grade) {
	cert := CertificateScore(t)
	proto := ProtocolSupportScore(t)
	kx := KeyExchangeScore(t)
	cipher := CipherStrengthScore(t)

	final := int(0.30*float64(cert) + 0.70*float64(proto+kx+cipher)/3.0)
	if final < 0 {
		final = 0
	}
	if final > 100 {
		final = 100
	}

	scores := scan.TLSScores{
		Certificate:     cert,
		ProtocolSupport: proto,
		KeyExchange:     kx,
		CipherStrength:  cipher,
		Final:           final,
	}

	grade := TLSThresholds.Grade(final)
	grade = Worst(grade, trustFloor(t.ChainTrust))
	grade = Worst(grade, protocolFloor(t.Protocols))
	grade = Worst(grade, cipherFloor(t.Ciphers))

	if grade == scan.GradeAPlus && !hstsPreloadEligible(h) {
		grade = scan.GradeA
	}
	return scores, grade
}

func trustFloor(trust scan.ChainTrust) scan.Grade {
	switch trust {
	case scan.ChainTrustExpired,
		scan.ChainTrustSelfSigned,
		scan.ChainTrustHostnameMismatch,
		scan.ChainTrustUntrusted:
		return scan.GradeT
	}
	return scan.GradeAPlus
}

func protocolFloor(protocols []scan.ProtocolSupport) scan.Grade {
	has := map[string]bool{}
	for _, p := range protocols {
		if p.Offered {
			has[p.Name] = true
		}
	}
	if has["SSL 2.0"] || has["SSL 3.0"] {
		return scan.GradeF
	}
	if has["TLS 1.0"] || has["TLS 1.1"] {
		return scan.GradeC
	}
	return scan.GradeAPlus
}

func cipherFloor(ciphers []scan.Cipher) scan.Grade {
	if len(ciphers) == 0 {
		return scan.GradeAPlus
	}
	anyPFS := false
	var has3DES, hasRC4, hasAnon, hasExport bool
	for _, c := range ciphers {
		if c.PFS {
			anyPFS = true
		}
		n := strings.ToUpper(c.Name)
		if strings.Contains(n, "3DES") {
			has3DES = true
		}
		if strings.Contains(n, "RC4") {
			hasRC4 = true
		}
		if strings.Contains(n, "_ANON") {
			hasAnon = true
		}
		if strings.Contains(n, "EXPORT") {
			hasExport = true
		}
	}
	if hasRC4 || hasAnon || hasExport {
		return scan.GradeF
	}
	if has3DES || !anyPFS {
		return scan.GradeC
	}
	return scan.GradeAPlus
}

// hstsPreloadEligible returns true when HSTS is configured strongly enough
// to be admissible to the HSTS preload list (max-age ≥ 1y, includeSubDomains
// and preload directives present).
func hstsPreloadEligible(h *scan.HeadersReport) bool {
	if h == nil {
		return false
	}
	r, ok := h.Core["strict-transport-security"]
	if !ok || !r.Present || r.Value == "" {
		return false
	}
	p := headers.ParseHSTS(r.Value)
	return p.MaxAge >= 31536000 && p.IncludeSubDomains && p.Preload
}
