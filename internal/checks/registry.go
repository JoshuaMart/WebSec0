package checks

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Check is the contract every individual security check fulfils. ID is
// the stable SCREAMING-KEBAB-CASE identifier (e.g. TLS-PROTOCOL-LEGACY-SSL3).
//
// Run must:
//   - return a *Finding describing the outcome (one Finding per check,
//     even for "pass" status — pass results power the catalog/coverage UI),
//   - or return a non-nil error if the check itself failed to execute (the
//     orchestrator turns that into a synthetic Finding with status=error).
type Check interface {
	ID() string
	Family() Family
	DefaultSeverity() Severity
	Run(ctx context.Context, target *Target) (*Finding, error)
}

// Registry is the in-memory catalogue of available checks. A process-wide
// default Registry exposes Default() for self-registration from check
// packages' init() functions.
type Registry struct {
	mu     sync.RWMutex
	checks map[string]Check
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{checks: make(map[string]Check)}
}

// Register adds c. It panics on duplicate id (a programmer error: every
// check has a stable, unique identifier).
func (r *Registry) Register(c Check) {
	if c == nil {
		panic("checks: Register(nil)")
	}
	id := c.ID()
	if id == "" {
		panic("checks: Register: empty ID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.checks[id]; exists {
		panic(fmt.Sprintf("checks: duplicate ID %q", id))
	}
	r.checks[id] = c
}

// Get returns the check with the given id and whether it exists.
func (r *Registry) Get(id string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[id]
	return c, ok
}

// All returns all registered checks sorted by ID.
func (r *Registry) All() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Check, 0, len(r.checks))
	for _, c := range r.checks {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Len returns the count of registered checks.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checks)
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide registry used by self-registering
// check packages.
func Default() *Registry { return defaultRegistry }

// Register is a convenience for c.Default().Register(c).
func Register(c Check) { defaultRegistry.Register(c) }
