package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// RunnerConfig parameterises Run. Zero values fall back to safe defaults
// matching SPECIFICATIONS.md §4.5.
type RunnerConfig struct {
	// MaxConcurrent caps the number of checks running in parallel inside
	// a single scan. Defaults to 10.
	MaxConcurrent int
	// PerCheckTimeout is the wall-clock budget for any single check.
	// Defaults to 8s.
	PerCheckTimeout time.Duration
}

func (c RunnerConfig) withDefaults() RunnerConfig {
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 10
	}
	if c.PerCheckTimeout <= 0 {
		c.PerCheckTimeout = 8 * time.Second
	}
	return c
}

// Runner orchestrates a set of Checks against a single Target.
type Runner struct {
	registry *checks.Registry
	cfg      RunnerConfig
}

// NewRunner returns a Runner that pulls checks from registry. registry
// must not be nil.
func NewRunner(registry *checks.Registry, cfg RunnerConfig) *Runner {
	return &Runner{registry: registry, cfg: cfg.withDefaults()}
}

// Subscriber receives events as the scan progresses. Send is best-effort:
// the runner never blocks on a slow subscriber, it drops events instead.
type Subscriber interface {
	Send(Event)
}

// Run executes all registered checks against target and streams events to
// sub. It returns the full slice of findings in completion order. The
// returned error is non-nil only on context cancellation; per-check
// failures are reported as Findings with Status=error.
//
// globalSem, if non-nil, must be acquired (weight 1) before the scan can
// start — this is the process-wide concurrency cap.
func (r *Runner) Run(
	ctx context.Context,
	target *checks.Target,
	sub Subscriber,
	globalSem *semaphore.Weighted,
) ([]checks.Finding, error) {
	all := r.registry.All()
	total := len(all)

	if globalSem != nil {
		if err := globalSem.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("acquire global semaphore: %w", err)
		}
		defer globalSem.Release(1)
	}

	emit(sub, Event{Kind: EventProgress, Progress: &Progress{Total: total, Completed: 0}})

	var (
		mu       sync.Mutex
		findings = make([]checks.Finding, 0, total)
		done     int
	)

	// Special case: an empty registry is valid (Phase 4 ships before any
	// check). Emit a single completed event and return.
	if total == 0 {
		emit(sub, Event{Kind: EventCompleted})
		return findings, nil
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(r.cfg.MaxConcurrent)

	for _, c := range all {
		g.Go(func() error {
			f := r.runOne(gctx, c, target)

			mu.Lock()
			findings = append(findings, *f)
			done++
			progress := Progress{Total: total, Completed: done, CurrentPhase: string(c.Family())}
			mu.Unlock()

			emit(sub, Event{Kind: EventFinding, Finding: f})
			emit(sub, Event{Kind: EventProgress, Progress: &progress})
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		emit(sub, Event{Kind: EventFailed, Error: err.Error()})
		return findings, err
	}

	emit(sub, Event{Kind: EventCompleted})
	return findings, nil
}

// runOne executes a single check under a per-check timeout. It always
// returns a non-nil Finding; failures are converted into Status=error
// records (errors.Join discipline — see §4.5).
func (r *Runner) runOne(ctx context.Context, c checks.Check, target *checks.Target) *checks.Finding {
	cctx, cancel := context.WithTimeout(ctx, r.cfg.PerCheckTimeout)
	defer cancel()

	f, err := c.Run(cctx, target)
	if err != nil {
		return &checks.Finding{
			ID:          c.ID(),
			Family:      c.Family(),
			Severity:    c.DefaultSeverity(),
			Status:      checks.StatusError,
			Title:       "check error",
			Description: err.Error(),
		}
	}
	if f == nil {
		return &checks.Finding{
			ID:       c.ID(),
			Family:   c.Family(),
			Severity: c.DefaultSeverity(),
			Status:   checks.StatusError,
			Title:    "check returned nil finding",
		}
	}
	// Backfill identity fields if the check was lazy.
	if f.ID == "" {
		f.ID = c.ID()
	}
	if f.Family == "" {
		f.Family = c.Family()
	}
	return f
}

func emit(s Subscriber, e Event) {
	if s == nil {
		return
	}
	s.Send(e)
}
