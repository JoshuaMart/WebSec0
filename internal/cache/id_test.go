package cache

import (
	"testing"
	"time"
)

func TestNewID_FormatIsHex32(t *testing.T) {
	id := NewID("example.com", time.Now())
	if len(id) != 32 {
		t.Fatalf("id len: got %d, want 32", len(id))
	}
	for i, c := range id {
		hexChar := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !hexChar {
			t.Errorf("id[%d] = %q is not lowercase hex", i, c)
		}
	}
}

func TestNewID_UniqueAcross1000Calls(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		id := NewID("example.com", now)
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id at iter %d: %s", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestNewID_DifferentHostsProduceDifferentIDs(t *testing.T) {
	now := time.Now()
	a := NewID("example.com", now)
	b := NewID("other.com", now)
	if a == b {
		t.Error("different hosts should not produce the same ID (nonce dominates entropy, but inputs still differ)")
	}
}
