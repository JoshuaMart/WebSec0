package scoring

import "github.com/JoshuaMart/websec0/internal/scan"

// CipherStrengthScore is (best + worst) / 2 across all offered cipher
// suites. Strength is mapped via a bit-count → score table to keep the
// computation independent of any particular cipher catalog.
func CipherStrengthScore(t *scan.TLSReport) int {
	if len(t.Ciphers) == 0 {
		return 0
	}
	scores := make([]int, 0, len(t.Ciphers))
	for _, c := range t.Ciphers {
		scores = append(scores, cipherBitsScore(c.Strength))
	}
	minV, maxV := scores[0], scores[0]
	for _, s := range scores {
		if s < minV {
			minV = s
		}
		if s > maxV {
			maxV = s
		}
	}
	return (minV + maxV) / 2
}

func cipherBitsScore(bits int) int {
	switch {
	case bits <= 0, bits < 80:
		return 0
	case bits < 128:
		return 40
	case bits < 192:
		return 80
	default:
		return 100
	}
}
