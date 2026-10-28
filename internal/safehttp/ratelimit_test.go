package safehttp

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiter_AllowsBurstThenDenies(t *testing.T) {
	l := NewLimiter(3, time.Hour)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	if l.Allow("k") {
		t.Error("4th call should be denied")
	}
}

func TestLimiter_KeysAreIndependent(t *testing.T) {
	l := NewLimiter(1, time.Hour)
	if !l.Allow("alice") {
		t.Error("alice/1: should allow")
	}
	if l.Allow("alice") {
		t.Error("alice/2: should deny")
	}
	if !l.Allow("bob") {
		t.Error("bob/1: independent key should allow")
	}
}

func TestLimiter_ZeroCountIsPermissive(t *testing.T) {
	l := NewLimiter(0, time.Hour)
	for i := 0; i < 5; i++ {
		if !l.Allow("k") {
			t.Errorf("call %d should be allowed under permissive limiter", i)
		}
	}
}

func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func TestLimiter_EvictsRefilledBuckets(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(2, time.Hour)
	l.now = func() time.Time { return now }

	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprintf("k%d", i))
	}
	l.Allow("busy")
	l.Allow("busy")
	if got := l.size(); got != 101 {
		t.Fatalf("live buckets: got %d, want 101", got)
	}

	// Half a period later the single-use buckets are full again; "busy"
	// is still one token short and must survive with its debt intact.
	now = now.Add(30 * time.Minute)
	l.Allow("trigger")
	if got := l.size(); got != 2 {
		t.Fatalf("after sweep: got %d buckets, want busy+trigger", got)
	}
	if !l.Allow("busy") {
		t.Fatal("busy: one token should have refilled")
	}
	if l.Allow("busy") {
		t.Fatal("busy: eviction must not reset an active bucket")
	}
}
