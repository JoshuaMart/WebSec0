package scoring

import "github.com/JoshuaMart/websec0/internal/scan"

// KeyExchangeScore is deliberately coarse in v1: 90 if at least one offered
// cipher provides forward secrecy, 40 otherwise, and 0 when no ciphers were
// enumerated. A finer-grained scoring (DH group bit-count, curve strength)
// requires data the probe does not yet expose — deferred to v1.1.
func KeyExchangeScore(t *scan.TLSReport) int {
	if len(t.Ciphers) == 0 {
		return 0
	}
	for _, c := range t.Ciphers {
		if c.PFS {
			return 90
		}
	}
	return 40
}
