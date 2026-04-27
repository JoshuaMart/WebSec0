package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/storage"
)

func newScan(id string) *storage.Scan {
	return &storage.Scan{
		ID:        id,
		Status:    storage.StatusQueued,
		Target:    "example.com",
		StartedAt: time.Now(),
	}
}

func TestPutGet(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	ctx := context.Background()

	if err := s.Put(ctx, newScan("a"), 0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "a" || got.Target != "example.com" {
		t.Errorf("unexpected scan: %+v", got)
	}
}

func TestGetMissing(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	ctx := context.Background()
	_ = s.Put(ctx, newScan("a"), 0)

	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "a"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("after delete, Get err = %v", err)
	}
	if err := s.Delete(ctx, "a"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("delete-missing err = %v", err)
	}
}

func TestUpdateStatus(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	ctx := context.Background()
	_ = s.Put(ctx, newScan("a"), 0)

	err := s.UpdateStatus(ctx, "a", func(sc *storage.Scan) error {
		sc.Status = storage.StatusRunning
		sc.Progress.Total = 10
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, _ := s.Get(ctx, "a")
	if got.Status != storage.StatusRunning || got.Progress.Total != 10 {
		t.Errorf("update not applied: %+v", got)
	}
}

func TestUpdateStatusFnErrorIsPropagated(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	ctx := context.Background()
	_ = s.Put(ctx, newScan("a"), 0)

	sentinel := errors.New("boom")
	err := s.UpdateStatus(ctx, "a", func(*storage.Scan) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

func TestUpdateStatusMissing(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	err := s.UpdateStatus(context.Background(), "nope", func(*storage.Scan) error { return nil })
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestTTLExpiration(t *testing.T) {
	t.Parallel()
	s := New(time.Hour)
	ctx := context.Background()

	if err := s.Put(ctx, newScan("short"), 30*time.Millisecond); err != nil {
		t.Fatalf("Put: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := s.Get(ctx, "short"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("after TTL, Get err = %v", err)
	}
}

func TestPutInvalid(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	if err := s.Put(context.Background(), nil, 0); err == nil {
		t.Error("expected error for nil scan")
	}
	if err := s.Put(context.Background(), &storage.Scan{}, 0); err == nil {
		t.Error("expected error for empty id")
	}
}

func TestConcurrentUpdateStatus(t *testing.T) {
	t.Parallel()
	s := New(time.Minute)
	ctx := context.Background()
	_ = s.Put(ctx, newScan("a"), 0)

	const N = 200
	var wg sync.WaitGroup
	var fail atomic.Int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.UpdateStatus(ctx, "a", func(sc *storage.Scan) error {
				sc.Progress.Completed++
				return nil
			}); err != nil {
				fail.Add(1)
			}
		}()
	}
	wg.Wait()
	if fail.Load() != 0 {
		t.Fatalf("%d concurrent updates failed", fail.Load())
	}
	got, _ := s.Get(ctx, "a")
	if got.Progress.Completed != N {
		t.Errorf("Progress.Completed = %d, want %d (lost updates)", got.Progress.Completed, N)
	}
}
