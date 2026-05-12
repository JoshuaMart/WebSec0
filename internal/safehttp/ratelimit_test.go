package safehttp

import (
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
