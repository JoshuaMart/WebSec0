package cache

import (
	"testing"
	"time"
)

func TestCache_PutGet(t *testing.T) {
	c := New[int](100, time.Hour)
	c.Put("foo", 42)
	v, ok := c.Get("foo")
	if !ok || v != 42 {
		t.Errorf("Get foo: got (%d, %v), want (42, true)", v, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Error("Get missing should report false")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := New[string](100, 50*time.Millisecond)
	c.Put("k", "v")
	if _, ok := c.Get("k"); !ok {
		t.Fatal("entry missing before expiry")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("entry should have expired")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := New[int](2, time.Hour)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3) // should evict "a"
	if _, ok := c.Get("a"); ok {
		t.Error("a should have been evicted")
	}
	if v, ok := c.Get("b"); !ok || v != 2 {
		t.Errorf("b: got (%d, %v), want (2, true)", v, ok)
	}
	if v, ok := c.Get("c"); !ok || v != 3 {
		t.Errorf("c: got (%d, %v), want (3, true)", v, ok)
	}
}

func TestCache_GetRefreshesLRURecency(t *testing.T) {
	c := New[int](2, time.Hour)
	c.Put("a", 1)
	c.Put("b", 2)
	// Touch "a" so it becomes the most-recently-used.
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a missing")
	}
	c.Put("c", 3) // should evict "b" now, not "a"
	if _, ok := c.Get("b"); ok {
		t.Error("b should have been evicted (a was touched)")
	}
	if _, ok := c.Get("a"); !ok {
		t.Error("a should remain")
	}
}

func TestCache_LenAndPurge(t *testing.T) {
	c := New[int](100, time.Hour)
	c.Put("a", 1)
	c.Put("b", 2)
	if c.Len() != 2 {
		t.Errorf("len: got %d, want 2", c.Len())
	}
	c.Purge()
	if c.Len() != 0 {
		t.Errorf("len after purge: got %d, want 0", c.Len())
	}
}

func TestCache_ZeroMaxEntriesUsesDefault(t *testing.T) {
	c := New[int](0, time.Hour)
	c.Put("a", 1)
	if _, ok := c.Get("a"); !ok {
		t.Error("entry should be retrievable with maxEntries=0 default")
	}
}
