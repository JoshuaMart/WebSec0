// Package history maintains the opt-in, in-memory list of recently
// completed public scans. Only one-line summaries are stored — the full
// scan body lives in internal/cache. Entries older than the configured
// retention are purged lazily on Add and List. See SPEC §7 (history.*).
package history

import (
	"sync"
	"time"

	"github.com/JoshuaMart/websec0/internal/scoring"
)

// Entry is a single row of the "Recent scans" landing strip.
type Entry struct {
	ID          string        `json:"id"`
	Host        string        `json:"host"`
	ScannedAt   time.Time     `json:"scanned_at"`
	TLSGrade    scoring.Grade `json:"tls_grade"`
	HeaderGrade scoring.Grade `json:"headers_grade"`
}

// History is a thread-safe time-bounded list, newest first.
type History struct {
	retention time.Duration
	now       func() time.Time
	mu        sync.Mutex
	entries   []Entry
}

// New returns a History that drops entries older than retention.
func New(retention time.Duration) *History {
	return &History{retention: retention, now: time.Now}
}

// Add prepends e and purges anything that has aged out.
func (h *History) Add(e Entry) { //nolint:gocritic // Entry is value-typed by design; the copy cost is negligible at history-strip scale.
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append([]Entry{e}, h.entries...)
	h.purgeLocked(h.now())
}

// List returns up to limit entries, newest first. A limit ≤ 0 returns all.
func (h *History) List(limit int) []Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.purgeLocked(h.now())
	n := len(h.entries)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Entry, n)
	copy(out, h.entries)
	return out
}

// Len returns the current number of retained entries (after lazy purge).
func (h *History) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.purgeLocked(h.now())
	return len(h.entries)
}

// purgeLocked drops entries with ScannedAt at or before now-retention.
// The slice is newest-first, so we truncate at the first too-old entry.
func (h *History) purgeLocked(now time.Time) {
	cutoff := now.Add(-h.retention)
	for i, e := range h.entries {
		if !e.ScannedAt.After(cutoff) {
			h.entries = h.entries[:i]
			return
		}
	}
}
