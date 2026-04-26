package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/semaphore"

	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/report"
	"github.com/Jomar/websec101/internal/storage"
	"github.com/Jomar/websec101/internal/version"
)

// Manager owns the asynchronous lifecycle of scans: creation, kickoff in
// a background goroutine, store updates, and event broadcasting to SSE
// subscribers.
type Manager struct {
	store     storage.ScanStore
	runner    *Runner
	logger    *slog.Logger
	globalSem *semaphore.Weighted
	ttl       time.Duration

	subMu sync.Mutex
	subs  map[string]*broker
}

// ManagerConfig holds the knobs that map onto the YAML scanner config.
type ManagerConfig struct {
	MaxConcurrentScans         int
	MaxConcurrentChecksPerScan int
	PerCheckTimeout            time.Duration
	PerScanTimeout             time.Duration
	StorageTTL                 time.Duration
}

func (c ManagerConfig) withDefaults() ManagerConfig {
	if c.MaxConcurrentScans <= 0 {
		c.MaxConcurrentScans = 50
	}
	if c.MaxConcurrentChecksPerScan <= 0 {
		c.MaxConcurrentChecksPerScan = 10
	}
	if c.PerCheckTimeout <= 0 {
		c.PerCheckTimeout = 8 * time.Second
	}
	if c.PerScanTimeout <= 0 {
		c.PerScanTimeout = 120 * time.Second
	}
	if c.StorageTTL <= 0 {
		c.StorageTTL = 24 * time.Hour
	}
	return c
}

// NewManager returns a Manager wired to the given store, registry, and
// config. logger may be nil to disable structured logging.
func NewManager(
	store storage.ScanStore,
	registry *checks.Registry,
	cfg ManagerConfig,
	logger *slog.Logger,
) *Manager {
	cfg = cfg.withDefaults()
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(noopWriter{}, nil))
	}
	return &Manager{
		store: store,
		runner: NewRunner(registry, RunnerConfig{
			MaxConcurrent:   cfg.MaxConcurrentChecksPerScan,
			PerCheckTimeout: cfg.PerCheckTimeout,
		}),
		logger:    logger,
		globalSem: semaphore.NewWeighted(int64(cfg.MaxConcurrentScans)),
		ttl:       cfg.StorageTTL,
		subs:      make(map[string]*broker),
	}
}

// CreateScan persists a new Scan in StatusQueued, kicks off a goroutine
// that performs the work, and returns the freshly minted record. The
// caller is responsible for echoing the appropriate 202 / Location
// response to the HTTP client.
func (m *Manager) CreateScan(ctx context.Context, target *checks.Target, scanTimeout time.Duration) (*storage.Scan, error) {
	id := uuid.NewString()
	scan := &storage.Scan{
		ID:        id,
		Status:    storage.StatusQueued,
		Target:    target.Hostname,
		StartedAt: time.Now().UTC(),
		Progress:  storage.Progress{Total: m.runner.registry.Len()},
	}
	if err := m.store.Put(ctx, scan, m.ttl); err != nil {
		return nil, fmt.Errorf("manager: store put: %w", err)
	}

	br := newBroker(64)
	m.subMu.Lock()
	m.subs[id] = br
	m.subMu.Unlock()

	go m.run(id, target, br, scanTimeout)
	return scan, nil
}

// Subscribe returns a channel that receives events for the given scan id,
// plus a cancel func the caller must invoke when done. Returns ErrNotFound
// if the scan is unknown or already finalised.
func (m *Manager) Subscribe(id string) (<-chan Event, func(), error) {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	br, ok := m.subs[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	return br.subscribe()
}

// ErrNotFound is returned when a scan id is unknown to the Manager. Note
// it is distinct from storage.ErrNotFound to keep concerns decoupled.
var ErrNotFound = errors.New("scanner: scan not found")

func (m *Manager) run(id string, target *checks.Target, br *broker, scanTimeout time.Duration) {
	defer func() {
		if rec := recover(); rec != nil {
			m.logger.Error("scan panic", "id", id, "panic", rec)
			_ = m.store.UpdateStatus(context.Background(), id, func(s *storage.Scan) error {
				s.Status = storage.StatusFailed
				s.Error = fmt.Sprintf("panic: %v", rec)
				now := time.Now().UTC()
				s.CompletedAt = &now
				return nil
			})
			br.publish(Event{Kind: EventFailed, Error: fmt.Sprintf("panic: %v", rec)})
		}
		br.close()
		m.subMu.Lock()
		delete(m.subs, id)
		m.subMu.Unlock()
	}()

	if err := m.store.UpdateStatus(context.Background(), id, func(s *storage.Scan) error {
		s.Status = storage.StatusRunning
		return nil
	}); err != nil {
		m.logger.Error("set running", "id", id, "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	storeSub := &storeSubscriber{store: m.store, id: id, broker: br, logger: m.logger}

	findings, err := m.runner.Run(ctx, target, storeSub, m.globalSem)

	finalise := func(s *storage.Scan) error {
		now := time.Now().UTC()
		s.CompletedAt = &now
		s.Findings = findings
		if err != nil {
			s.Status = storage.StatusFailed
			s.Error = err.Error()
		} else {
			s.Status = storage.StatusCompleted
			s.Report = report.Build(
				s.ID, s.Target, s.StartedAt, now, findings,
				report.BuildOptions{ScannerVersion: version.Version},
			)
		}
		return nil
	}
	if uerr := m.store.UpdateStatus(context.Background(), id, finalise); uerr != nil {
		m.logger.Error("finalise scan", "id", id, "err", uerr)
	}
}

// storeSubscriber persists progress/finding events into the ScanStore as
// they arrive, then forwards them to the broker for SSE clients.
type storeSubscriber struct {
	store  storage.ScanStore
	id     string
	broker *broker
	logger *slog.Logger
}

func (s *storeSubscriber) Send(e Event) {
	switch e.Kind {
	case EventProgress:
		if e.Progress != nil {
			p := storage.Progress{
				Total:        e.Progress.Total,
				Completed:    e.Progress.Completed,
				CurrentPhase: e.Progress.CurrentPhase,
			}
			if err := s.store.UpdateStatus(context.Background(), s.id, func(sc *storage.Scan) error {
				sc.Progress = p
				return nil
			}); err != nil {
				s.logger.Warn("progress update", "id", s.id, "err", err)
			}
		}
	case EventFinding, EventCompleted, EventFailed:
		// Findings are persisted as a batch on completion; intermediate
		// updates are kept SSE-only to avoid hammering the store.
	}
	s.broker.publish(e)
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }
