// Package history maintains the opt-in, in-memory list of recently
// completed public scans. Only one-line summaries are stored — the full
// scan body lives in internal/cache. Entries older than the configured
// retention are purged lazily on Add and List.
package history

import (
	"sync"
	"time"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// Entry is a single row of the "Recent scans" landing strip.
type Entry struct {
	ID          string     `json:"id"`
	Host        string     `json:"host"`
	ScannedAt   time.Time  `json:"scanned_at"`
	TLSGrade    scan.Grade `json:"tls_grade"`
	HeaderGrade scan.Grade `json:"headers_grade"`
	// HighestTLS is the best protocol version offered by the target,
	// shown as the subtitle in the landing strip. Empty when no TLS
	// version is offered or the probe failed.
	HighestTLS string `json:"highest_tls,omitempty"`
}

// History is a thread-safe time-bounded list in reverse publication order.
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

// Add lists a report once and purges entries that have aged out.
func (h *History) Add(e Entry) { //nolint:gocritic // Entry is value-typed by design; the copy cost is negligible at history-strip scale.
	h.mu.Lock()
	defer h.mu.Unlock()
	h.purgeLocked(h.now())
	for _, existing := range h.entries {
		if existing.ID == e.ID {
			return
		}
	}
	if !e.ScannedAt.After(h.now().Add(-h.retention)) {
		return
	}
	h.entries = append([]Entry{e}, h.entries...)
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
// Completion order need not match ScannedAt when scans run concurrently.
func (h *History) purgeLocked(now time.Time) {
	cutoff := now.Add(-h.retention)
	kept := 0
	for i := range h.entries {
		if h.entries[i].ScannedAt.After(cutoff) {
			if kept != i {
				h.entries[kept] = h.entries[i]
			}
			kept++
		}
	}
	clear(h.entries[kept:])
	h.entries = h.entries[:kept]
}
