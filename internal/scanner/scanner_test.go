package scanner

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/storage"
	"github.com/JoshuaMart/websec0/internal/storage/memory"
)

// --- mock check ----------------------------------------------------------

// mockCheck is a minimal Check whose Run is a closure. Useful for
// driving the orchestrator through specific edge cases (slow check,
// erroring check, nil-returning check, …) without wiring real probes.
type mockCheck struct {
	id       string
	family   checks.Family
	severity checks.Severity
	run      func(context.Context, *checks.Target) (*checks.Finding, error)
}

func (m mockCheck) ID() string                       { return m.id }
func (m mockCheck) Family() checks.Family            { return m.family }
func (m mockCheck) DefaultSeverity() checks.Severity { return m.severity }
func (m mockCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return m.run(ctx, t)
}

// passingCheck returns a Pass finding with the given ID.
func passingCheck(id string) mockCheck {
	return mockCheck{
		id:       id,
		family:   checks.FamilyTLS,
		severity: checks.SeverityLow,
		run: func(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
			return &checks.Finding{ID: id, Family: checks.FamilyTLS, Status: checks.StatusPass}, nil
		},
	}
}

// --- recordingSub --------------------------------------------------------

type recordingSub struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingSub) Send(e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recordingSub) byKind(k EventKind) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Kind == k {
			n++
		}
	}
	return n
}

// --- Runner --------------------------------------------------------------

func TestRunner_RunsAllChecksAndEmitsEvents(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(passingCheck("CHK-A"))
	r.Register(passingCheck("CHK-B"))
	r.Register(passingCheck("CHK-C"))

	runner := NewRunner(r, RunnerConfig{})
	sub := &recordingSub{}
	tgt, err := checks.NewTarget("example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := runner.Run(context.Background(), tgt, sub, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}
	if got := sub.byKind(EventFinding); got != 3 {
		t.Errorf("EventFinding count = %d, want 3", got)
	}
	if got := sub.byKind(EventCompleted); got != 1 {
		t.Errorf("EventCompleted count = %d, want 1", got)
	}
	if got := sub.byKind(EventProgress); got < 4 {
		t.Errorf("EventProgress count = %d, want ≥ 4 (initial + 3)", got)
	}
}

func TestRunner_EmptyRegistry(t *testing.T) {
	r := checks.NewRegistry()
	runner := NewRunner(r, RunnerConfig{})
	sub := &recordingSub{}
	tgt, _ := checks.NewTarget("example.com", nil)

	findings, err := runner.Run(context.Background(), tgt, sub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
	if sub.byKind(EventCompleted) != 1 {
		t.Errorf("expected one Completed event for empty registry")
	}
}

func TestRunner_CheckErrorBecomesStatusError(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(mockCheck{
		id: "ERR", family: checks.FamilyTLS, severity: checks.SeverityHigh,
		run: func(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
			return nil, errors.New("synthetic failure")
		},
	})
	runner := NewRunner(r, RunnerConfig{})
	tgt, _ := checks.NewTarget("example.com", nil)

	findings, err := runner.Run(context.Background(), tgt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Status != checks.StatusError {
		t.Errorf("Status = %s, want error", f.Status)
	}
	if f.ID != "ERR" {
		t.Errorf("ID = %s, want ERR", f.ID)
	}
}

func TestRunner_NilFindingBecomesStatusError(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(mockCheck{
		id: "NIL", family: checks.FamilyTLS, severity: checks.SeverityLow,
		run: func(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
			return nil, nil
		},
	})
	runner := NewRunner(r, RunnerConfig{})
	tgt, _ := checks.NewTarget("example.com", nil)
	findings, _ := runner.Run(context.Background(), tgt, nil, nil)
	if len(findings) != 1 || findings[0].Status != checks.StatusError {
		t.Errorf("nil finding not converted to error: %+v", findings)
	}
}

func TestRunner_BackfillsIDAndFamily(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(mockCheck{
		id: "BACKFILL", family: checks.FamilyHeaders, severity: checks.SeverityMedium,
		run: func(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
			// Lazy: returns finding with empty ID/Family.
			return &checks.Finding{Status: checks.StatusPass}, nil
		},
	})
	runner := NewRunner(r, RunnerConfig{})
	tgt, _ := checks.NewTarget("example.com", nil)
	findings, _ := runner.Run(context.Background(), tgt, nil, nil)
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	if findings[0].ID != "BACKFILL" || findings[0].Family != checks.FamilyHeaders {
		t.Errorf("backfill missing: %+v", findings[0])
	}
}

func TestRunner_PerCheckTimeoutHonoured(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(mockCheck{
		id: "SLOW", family: checks.FamilyTLS, severity: checks.SeverityMedium,
		run: func(ctx context.Context, _ *checks.Target) (*checks.Finding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	runner := NewRunner(r, RunnerConfig{PerCheckTimeout: 30 * time.Millisecond})
	tgt, _ := checks.NewTarget("example.com", nil)
	start := time.Now()
	findings, _ := runner.Run(context.Background(), tgt, nil, nil)
	dur := time.Since(start)
	if dur > 500*time.Millisecond {
		t.Errorf("Run took %s, expected < 500ms (per-check timeout broken?)", dur)
	}
	if findings[0].Status != checks.StatusError {
		t.Errorf("status = %s, want error (timed out)", findings[0].Status)
	}
}

func TestRunner_GlobalSemaphoreBlocksUntilReleased(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(passingCheck("X"))
	runner := NewRunner(r, RunnerConfig{})
	tgt, _ := checks.NewTarget("example.com", nil)

	sem := semaphore.NewWeighted(1)
	if err := sem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}

	// Cancellation while waiting on the global semaphore must surface.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := runner.Run(ctx, tgt, nil, sem)
	if err == nil {
		t.Error("expected context error while semaphore is held")
	}
}

// --- broker --------------------------------------------------------------

func TestBroker_DeliversAndReplaysHistory(t *testing.T) {
	b := newBroker(8)
	b.publish(Event{Kind: EventProgress})
	b.publish(Event{Kind: EventFinding})

	// Late subscriber must replay the two queued events.
	ch, cancel, err := b.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	got := drainNonBlocking(ch, 2)
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	if got[0].Kind != EventProgress || got[1].Kind != EventFinding {
		t.Errorf("history out of order: %+v", got)
	}
}

func TestBroker_LiveDelivery(t *testing.T) {
	b := newBroker(8)
	ch, cancel, _ := b.subscribe()
	defer cancel()
	b.publish(Event{Kind: EventCompleted})

	select {
	case e := <-ch:
		if e.Kind != EventCompleted {
			t.Errorf("got %s, want completed", e.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("event not delivered within 1s")
	}
}

func TestBroker_ClosedReplaysAndCloses(t *testing.T) {
	b := newBroker(0) // bufferLen ≤ 0 → defaults to 32
	b.publish(Event{Kind: EventCompleted})
	b.close()
	// Idempotent close.
	b.close()

	ch, _, _ := b.subscribe()
	collected := drainNonBlocking(ch, 4)
	if len(collected) != 1 || collected[0].Kind != EventCompleted {
		t.Errorf("late subscriber on closed broker did not replay: %+v", collected)
	}
	// Channel must be closed for downstream to detect end-of-stream.
	if _, ok := <-ch; ok {
		t.Error("channel from closed broker should be closed after history drains")
	}
}

func TestBroker_PublishAfterCloseIsNoop(t *testing.T) {
	b := newBroker(8)
	b.close()
	b.publish(Event{Kind: EventProgress}) // must not panic
}

func TestBroker_SubscriberDropOnSlowness(t *testing.T) {
	b := newBroker(2)
	ch, cancel, _ := b.subscribe()
	defer cancel()
	for i := 0; i < 10; i++ {
		b.publish(Event{Kind: EventProgress})
	}
	// We do not assert how many were dropped (depends on scheduling) — only
	// that the publisher never blocked and the subscriber stayed open.
	got := drainNonBlocking(ch, 10)
	if len(got) == 0 {
		t.Error("expected at least one event delivered")
	}
}

func drainNonBlocking(ch <-chan Event, max int) []Event {
	out := make([]Event, 0, max)
	for i := 0; i < max; i++ {
		select {
		case e, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, e)
		case <-time.After(50 * time.Millisecond):
			return out
		}
	}
	return out
}

// --- Manager -------------------------------------------------------------

func TestManager_CreateScan_FullLifecycle(t *testing.T) {
	store := memory.New(time.Hour)
	r := checks.NewRegistry()
	r.Register(passingCheck("CHK-1"))
	r.Register(passingCheck("CHK-2"))

	mgr := NewManager(store, r, ManagerConfig{
		MaxConcurrentScans:         8,
		MaxConcurrentChecksPerScan: 4,
		PerCheckTimeout:            500 * time.Millisecond,
		PerScanTimeout:             5 * time.Second,
	}, nil)

	tgt, _ := checks.NewTarget("example.com", nil)
	scan, err := mgr.CreateScan(context.Background(), tgt, 5*time.Second)
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if scan.Status != storage.StatusQueued {
		t.Errorf("initial status = %s, want queued", scan.Status)
	}
	if scan.Progress.Total != 2 {
		t.Errorf("Progress.Total = %d, want 2", scan.Progress.Total)
	}
	if scan.ID == "" {
		t.Error("scan id is empty")
	}

	// Wait until the manager finalises the scan.
	if !waitForCompletion(t, store, scan.ID, 3*time.Second) {
		t.Fatal("scan did not complete within 3s")
	}
	got, err := store.Get(context.Background(), scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != storage.StatusCompleted {
		t.Errorf("final status = %s, want completed", got.Status)
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt not set")
	}
	if got.Report == nil {
		t.Error("Report not built")
	}
}

func TestManager_Subscribe_DeliversEvents(t *testing.T) {
	store := memory.New(time.Hour)
	r := checks.NewRegistry()
	// Use a check that takes long enough for subscribe-before-finalise.
	var counter int32
	r.Register(mockCheck{
		id: "SLOW", family: checks.FamilyTLS, severity: checks.SeverityLow,
		run: func(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
			atomic.AddInt32(&counter, 1)
			time.Sleep(50 * time.Millisecond)
			return &checks.Finding{ID: "SLOW", Family: checks.FamilyTLS, Status: checks.StatusPass}, nil
		},
	})

	mgr := NewManager(store, r, ManagerConfig{}, nil)
	tgt, _ := checks.NewTarget("example.com", nil)
	scan, err := mgr.CreateScan(context.Background(), tgt, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ch, cancel, err := mgr.Subscribe(scan.ID)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer cancel()

	gotCompleted := false
	timeout := time.After(3 * time.Second)
loop:
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				break loop
			}
			if e.Kind == EventCompleted {
				gotCompleted = true
				break loop
			}
		case <-timeout:
			t.Fatal("subscription timed out")
		}
	}
	if !gotCompleted {
		t.Error("did not receive Completed event")
	}
}

func TestManager_Subscribe_UnknownIDReturnsErr(t *testing.T) {
	mgr := NewManager(memory.New(time.Hour), checks.NewRegistry(), ManagerConfig{}, nil)
	if _, _, err := mgr.Subscribe("does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Subscribe(unknown) err = %v, want ErrNotFound", err)
	}
}

// waitForCompletion polls the store until status is terminal or timeout
// elapses. Returns true if the scan reached a terminal state.
func waitForCompletion(t *testing.T, store storage.ScanStore, id string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s, err := store.Get(context.Background(), id)
		if err == nil &&
			(s.Status == storage.StatusCompleted || s.Status == storage.StatusFailed) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
