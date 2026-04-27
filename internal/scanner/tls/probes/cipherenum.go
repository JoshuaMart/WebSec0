package probes

import "context"

// EnumerateCipherSuites returns all cipher suites from candidates that the
// server at addr accepts for maxVersion, in server preference order
// (most-preferred first).
//
// Algorithm: send ClientHello with all remaining candidates → server selects
// its most-preferred matching cipher → record it, remove from candidates →
// repeat until the server rejects (no matching cipher left).
//
// Connection budget: at most len(candidates)+1 TCP connections.
func EnumerateCipherSuites(ctx context.Context, addr string, maxVersion uint16, candidates []uint16) []uint16 {
	remaining := make([]uint16, len(candidates))
	copy(remaining, candidates)

	var accepted []uint16

	for len(remaining) > 0 {
		r, err := ProbeTLSHello(ctx, addr, maxVersion, remaining)
		if err != nil || !r.Accepted {
			break
		}
		// Only count if the server negotiated the exact version we requested.
		if r.NegotiatedVersion != maxVersion {
			break
		}
		// Find the selected cipher in remaining and remove it.
		removed := false
		for i, c := range remaining {
			if c == r.NegotiatedCipher {
				accepted = append(accepted, c)
				remaining = append(remaining[:i], remaining[i+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			// Server chose a cipher we did not offer — bail out.
			break
		}
	}
	return accepted
}
