package scoring

import (
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// CertificateScore returns a 0–100 score derived from the leaf certificate's
// properties: key algorithm and validity window. Trust failures (untrusted
// chain, hostname mismatch, expired) are encoded as a grade floor in
// TLSFinal — they intentionally do not zero this sub-score here, because
// the per-category breakdown remains informative even when chain trust
// fails (a strong key inside an untrusted chain is still a strong key).
//
// Future iterations will read the actual public-key bit count from
// scan.Certificate. For v1 we approximate via the algorithm name.
func CertificateScore(t *scan.TLSReport) int {
	if len(t.CertificateChain) == 0 {
		return 0
	}
	leaf := t.CertificateChain[0]

	if leaf.DaysLeft < 0 {
		return 0
	}

	base := 60
	switch {
	case strings.Contains(leaf.KeyAlg, "ECDSA"),
		strings.Contains(leaf.KeyAlg, "Ed25519"):
		base = 100
	case strings.Contains(leaf.KeyAlg, "RSA"):
		base = 80
	case strings.Contains(leaf.KeyAlg, "DSA"):
		base = 60
	}

	if leaf.DaysLeft < 30 {
		base = base * 80 / 100
	}
	return base
}
