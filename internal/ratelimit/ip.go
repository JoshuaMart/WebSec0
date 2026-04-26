// Package ratelimit implements per-IP token-bucket rate limiting and
// per-target cooldown / recent-scan cache.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPLimiter is a per-source-IP token bucket. The map of buckets is
// trimmed lazily — entries unused for cleanupAfter are evicted on the
// next Allow() call. No background goroutine.
type IPLimiter struct {
	rate         rate.Limit
	burst        int
	cleanupAfter time.Duration

	mu       sync.Mutex
	buckets  map[string]*entry
	lastSwep time.Time
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewIPLimiter returns a limiter that enforces N requests per period
// with a small burst. period=0 → 1 minute default.
func NewIPLimiter(maxPerPeriod int, period time.Duration) *IPLimiter {
	if period <= 0 {
		period = time.Minute
	}
	if maxPerPeriod <= 0 {
		maxPerPeriod = 60
	}
	return &IPLimiter{
		rate:         rate.Every(period / time.Duration(maxPerPeriod)),
		burst:        maxPerPeriod,
		cleanupAfter: 30 * time.Minute,
		buckets:      map[string]*entry{},
	}
}

// Allow records one event from src and reports whether it fits inside
// the per-IP budget.
func (l *IPLimiter) Allow(src string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSwep) > l.cleanupAfter {
		l.sweep(now)
		l.lastSwep = now
	}
	e, ok := l.buckets[src]
	if !ok {
		e = &entry{lim: rate.NewLimiter(l.rate, l.burst)}
		l.buckets[src] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

func (l *IPLimiter) sweep(now time.Time) {
	for k, e := range l.buckets {
		if now.Sub(e.seen) > l.cleanupAfter {
			delete(l.buckets, k)
		}
	}
}

// ClientIP extracts a stable source identifier from r. Honours one hop
// of `X-Forwarded-For` so a deployment behind a single trusted reverse
// proxy still counts the right IPs. Anything beyond that is the
// operator's responsibility (auth proxy, mTLS, …).
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := xff
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			first = xff[:comma]
		}
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// Middleware enforces the per-IP budget on every request. On overflow
// it returns 429 with a JSON envelope.
func (l *IPLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r)
			if !l.Allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"code":"rate_limited","message":"too many requests from this IP"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
