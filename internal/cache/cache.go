// Package cache provides a thread-safe TTL + LRU cache used to retain
// recently completed scan results. Values are bounded both by entry count
// (LRU eviction) and by age (time expiry). See SPEC §7 (cache.ttl,
// cache.max_entries) and §3 (no persistent storage — restart loses cache).
package cache

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Cache is a thread-safe TTL + LRU cache keyed by string. Constructed via New.
type Cache[V any] struct {
	inner *expirable.LRU[string, V]
}

// New builds a Cache. A non-positive maxEntries falls back to 1000 to avoid
// the underlying lib's "always full" behaviour at size 0. A zero ttl
// disables time-based expiry (LRU only).
func New[V any](maxEntries int, ttl time.Duration) *Cache[V] {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return &Cache[V]{
		inner: expirable.NewLRU[string, V](maxEntries, nil, ttl),
	}
}

// Put stores value under key.
func (c *Cache[V]) Put(key string, value V) {
	c.inner.Add(key, value)
}

// Get returns the value under key and a presence boolean. A returned
// false means either the key was never stored or its TTL has elapsed.
func (c *Cache[V]) Get(key string) (V, bool) {
	return c.inner.Get(key)
}

// Len returns the number of currently-stored entries.
func (c *Cache[V]) Len() int { return c.inner.Len() }

// Purge removes all entries.
func (c *Cache[V]) Purge() { c.inner.Purge() }
