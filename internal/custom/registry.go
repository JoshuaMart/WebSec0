// Package custom hosts the non-scoring "additional findings" checks. Each
// check is small, focused and self-contained; new ones plug in by adding
// an entry to All(). Findings never contribute to the TLS or Headers
// grade — they surface as the `custom` array in the scan response.
package custom

import (
	"context"
	"sync"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// Check is the pluggable interface every custom check implements.
type Check interface {
	// ID returns the check identifier used in API payloads and the catalog
	// (e.g. "custom.security_txt").
	ID() string
	// Run executes the check against target and returns its finding.
	// Implementations must never return an error — transport failures are
	// folded into the finding (typically as fail or info).
	Run(ctx context.Context, target *safehttp.Target) scan.CustomFinding
}

// All returns the ordered list of registered checks. The order is preserved
// in the API output, which keeps the report deterministic.
func All() []Check {
	return []Check{
		SecurityTxt{},
		RobotsTxt{},
	}
}

// RunAll executes every registered check in parallel and returns the
// findings in registration order.
func RunAll(ctx context.Context, target *safehttp.Target) []scan.CustomFinding {
	checks := All()
	out := make([]scan.CustomFinding, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			out[i] = c.Run(ctx, target)
		}(i, c)
	}
	wg.Wait()
	return out
}
