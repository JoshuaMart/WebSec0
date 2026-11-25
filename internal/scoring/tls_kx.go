package scoring

import "github.com/JoshuaMart/websec0/internal/scan"

// KeyExchangeScore rewards forward secrecy across the whole cipher list:
// 100 when every offered suite provides it, 90 when only some do (the
// others use static RSA key exchange), 40 when none does, and 0 when no
// ciphers were enumerated. A finer-grained scoring (DH group bit-count,
// curve strength) requires data the probe does not yet expose.
func KeyExchangeScore(t *scan.TLSReport) int {
	if len(t.Ciphers) == 0 {
		return 0
	}
	pfs := 0
	for _, c := range t.Ciphers {
		if c.PFS {
			pfs++
		}
	}
	switch pfs {
	case len(t.Ciphers):
		return 100
	case 0:
		return 40
	default:
		return 90
	}
}
