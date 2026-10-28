package safehttp

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterSweepInterval bounds how often Allow scans for idle buckets.
const limiterSweepInterval = time.Minute

// Limiter is a per-key token-bucket limiter. Buckets are materialised on
// the first call for a given key and evicted once they have refilled to
// their burst: a full bucket behaves exactly like a fresh one, so eviction
// never grants extra tokens, and memory stays bounded by the keys seen
// within one refill period.
type Limiter struct {
	limit rate.Limit
	burst int

	mu        sync.Mutex
	buckets   map[string]*rate.Limiter
	lastSweep time.Time
	now       func() time.Time
}

// NewLimiter returns a Limiter that allows up to count events per period
// per distinct key. A zero or negative count yields a permissive limiter
// that always allows.
func NewLimiter(count int, period time.Duration) *Limiter {
	if count <= 0 || period <= 0 {
		return &Limiter{limit: rate.Inf, burst: 1}
	}
	return &Limiter{
		limit:   rate.Limit(float64(count) / period.Seconds()),
		burst:   count,
		buckets: make(map[string]*rate.Limiter),
		now:     time.Now,
	}
}

// Allow consumes one token for key and reports whether the action is allowed.
func (l *Limiter) Allow(key string) bool {
	if l.limit == rate.Inf {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.lastSweep) >= limiterSweepInterval {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		b = rate.NewLimiter(l.limit, l.burst)
		l.buckets[key] = b
	}
	return b.AllowN(now, 1)
}

// sweep drops buckets that have refilled to their burst. Callers hold mu.
func (l *Limiter) sweep(now time.Time) {
	l.lastSweep = now
	for k, b := range l.buckets {
		if b.TokensAt(now) >= float64(l.burst) {
			delete(l.buckets, k)
		}
	}
}
