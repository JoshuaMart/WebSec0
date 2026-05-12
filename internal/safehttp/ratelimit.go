package safehttp

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a per-key token-bucket limiter. Buckets are materialised on
// the first call for a given key and live for the lifetime of the process —
// acceptable in v1 (a future janitor can evict idle buckets if it becomes
// a memory pressure point).
type Limiter struct {
	limit   rate.Limit
	burst   int
	buckets sync.Map // key string → *rate.Limiter
}

// NewLimiter returns a Limiter that allows up to count events per period
// per distinct key. A zero or negative count yields a permissive limiter
// that always allows.
func NewLimiter(count int, period time.Duration) *Limiter {
	if count <= 0 || period <= 0 {
		return &Limiter{limit: rate.Inf, burst: 1}
	}
	return &Limiter{
		limit: rate.Limit(float64(count) / period.Seconds()),
		burst: count,
	}
}

// Allow consumes one token for key and reports whether the action is allowed.
func (l *Limiter) Allow(key string) bool {
	if v, ok := l.buckets.Load(key); ok {
		return v.(*rate.Limiter).Allow()
	}
	fresh := rate.NewLimiter(l.limit, l.burst)
	actual, _ := l.buckets.LoadOrStore(key, fresh)
	return actual.(*rate.Limiter).Allow()
}
