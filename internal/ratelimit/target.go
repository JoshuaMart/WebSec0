package ratelimit

import (
	"strings"
	"sync"
	"time"
)

// TargetTracker enforces the per-hostname cooldown, the 24h cached-scan
// reuse window, and the per-IP fan-out abuse heuristic.
type TargetTracker struct {
	cooldown time.Duration
	cacheTTL time.Duration
	abuseLim int // max distinct hostnames per IP per window
	abuseWin time.Duration

	mu       sync.Mutex
	lastScan map[string]time.Time
	cache    map[string]cacheEntry
	abuse    map[string][]abuseRecord
}

type cacheEntry struct {
	scanID string
	at     time.Time
}

type abuseRecord struct {
	host string
	at   time.Time
}

// NewTargetTracker — zero values fall back to sensible defaults.
func NewTargetTracker(cooldown, cacheTTL time.Duration, abuseLim int, abuseWin time.Duration) *TargetTracker {
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	if abuseLim <= 0 {
		abuseLim = 5
	}
	if abuseWin <= 0 {
		abuseWin = 5 * time.Minute
	}
	return &TargetTracker{
		cooldown: cooldown,
		cacheTTL: cacheTTL,
		abuseLim: abuseLim,
		abuseWin: abuseWin,
		lastScan: map[string]time.Time{},
		cache:    map[string]cacheEntry{},
		abuse:    map[string][]abuseRecord{},
	}
}

// PreScan inspects the (ip, host) pair before a new scan is launched.
// Returns the pre-existing scan ID when a fresh-enough cache entry
// exists and refresh is false.
type PreScanDecision struct {
	CachedScanID string        // non-empty → reuse this scan instead of creating one
	CooldownLeft time.Duration // > 0 → 429 with Retry-After
	AbuseFlagged bool
}

// PreScan registers the request and returns its decision.
func (t *TargetTracker) PreScan(ip, host string, refresh bool) PreScanDecision {
	host = strings.ToLower(strings.TrimSpace(host))
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	t.gcLocked(now)

	dec := PreScanDecision{}

	// Abuse: trim records older than the window, then count distinct
	// hostnames for this IP.
	recs := t.abuse[ip]
	cut := now.Add(-t.abuseWin)
	out := recs[:0]
	for _, r := range recs {
		if r.at.After(cut) {
			out = append(out, r)
		}
	}
	out = append(out, abuseRecord{host: host, at: now})
	t.abuse[ip] = out
	hosts := map[string]struct{}{}
	for _, r := range out {
		hosts[r.host] = struct{}{}
	}
	if len(hosts) > t.abuseLim {
		dec.AbuseFlagged = true
		// We still go on to compute cache/cooldown so the caller can
		// emit a single best-fit response.
	}

	// Cache hit takes precedence over cooldown — it's the friendly
	// outcome (return the existing scan body, no work).
	if !refresh {
		if e, ok := t.cache[host]; ok && now.Sub(e.at) < t.cacheTTL {
			dec.CachedScanID = e.scanID
			return dec
		}
	}

	// Cooldown.
	if last, ok := t.lastScan[host]; ok {
		if elapsed := now.Sub(last); elapsed < t.cooldown {
			dec.CooldownLeft = t.cooldown - elapsed
			return dec
		}
	}

	t.lastScan[host] = now
	return dec
}

// Record registers the freshly created scan ID against host so future
// requests can reuse it for the cacheTTL window.
func (t *TargetTracker) Record(host, scanID string) {
	host = strings.ToLower(strings.TrimSpace(host))
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cache[host] = cacheEntry{scanID: scanID, at: time.Now()}
}

// gcLocked trims stale cache + abuse rows. Caller holds t.mu.
func (t *TargetTracker) gcLocked(now time.Time) {
	cacheCut := now.Add(-t.cacheTTL)
	for k, v := range t.cache {
		if v.at.Before(cacheCut) {
			delete(t.cache, k)
		}
	}
	cdCut := now.Add(-t.cooldown)
	for k, v := range t.lastScan {
		if v.Before(cdCut) {
			delete(t.lastScan, k)
		}
	}
	abuseCut := now.Add(-t.abuseWin)
	for k, recs := range t.abuse {
		out := recs[:0]
		for _, r := range recs {
			if r.at.After(abuseCut) {
				out = append(out, r)
			}
		}
		if len(out) == 0 {
			delete(t.abuse, k)
		} else {
			t.abuse[k] = out
		}
	}
}
