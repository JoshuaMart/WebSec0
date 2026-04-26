// Package memory provides an in-process ScanStore backed by patrickmn/go-cache.
// This is the MVP default backend (single instance, TTL-based eviction).
package memory

import (
	"context"
	"sync"
	"time"

	gocache "github.com/patrickmn/go-cache"

	"github.com/Jomar/websec101/internal/storage"
)

// gcInterval is how often expired entries are reaped. SPECIFICATIONS.md §9.3.
const gcInterval = 5 * time.Minute

// Store is a memory-backed ScanStore.
type Store struct {
	c *gocache.Cache
	// mu serialises read-modify-write in UpdateStatus. go-cache itself is
	// thread-safe per call, but it has no CAS primitive.
	mu sync.Mutex
}

// New returns a memory ScanStore with the given default TTL. Pass
// storage.TTL from config; callers may still override per-Put via the ttl
// argument to Put.
func New(defaultTTL time.Duration) *Store {
	return &Store{c: gocache.New(defaultTTL, gcInterval)}
}

// Put inserts or replaces the scan. A ttl of 0 falls back to the default.
// The store keeps a private copy: callers may continue to mutate the
// supplied *Scan after Put returns without affecting the stored entry.
func (s *Store) Put(_ context.Context, scan *storage.Scan, ttl time.Duration) error {
	if scan == nil || scan.ID == "" {
		return errInvalidScan
	}
	exp := ttl
	if exp <= 0 {
		exp = gocache.DefaultExpiration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.c.Set(scan.ID, cloneScan(scan), exp)
	return nil
}

func (s *Store) Get(_ context.Context, id string) (*storage.Scan, error) {
	// We hold the same mutex as UpdateStatus so callers always observe a
	// consistent snapshot — the underlying *Scan is mutated in place by
	// UpdateStatus, so we must clone before returning.
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.c.Get(id)
	if !ok {
		return nil, storage.ErrNotFound
	}
	scan, ok := v.(*storage.Scan)
	if !ok {
		return nil, errInvalidScan
	}
	return cloneScan(scan), nil
}

func (s *Store) Delete(_ context.Context, id string) error {
	if _, ok := s.c.Get(id); !ok {
		return storage.ErrNotFound
	}
	s.c.Delete(id)
	return nil
}

// UpdateStatus loads the scan, applies fn, and writes it back atomically.
// If fn returns an error the scan is not modified.
func (s *Store) UpdateStatus(_ context.Context, id string, fn func(*storage.Scan) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, exp, ok := s.c.GetWithExpiration(id)
	if !ok {
		return storage.ErrNotFound
	}
	scan, ok := v.(*storage.Scan)
	if !ok {
		return errInvalidScan
	}
	if err := fn(scan); err != nil {
		return err
	}

	ttl := gocache.DefaultExpiration
	if !exp.IsZero() {
		if remaining := time.Until(exp); remaining > 0 {
			ttl = remaining
		}
	}
	s.c.Set(id, scan, ttl)
	return nil
}
