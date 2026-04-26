// Package storage defines the ScanStore abstraction used by the API layer
// and concrete backends (memory, ristretto, redis).
package storage

import (
	"context"
	"errors"
	"time"

	"github.com/Jomar/websec101/internal/checks"
)

// ErrNotFound is returned by Get/Delete/UpdateStatus when the scan id
// does not exist (or has expired). Callers should errors.Is on this.
var ErrNotFound = errors.New("storage: scan not found")

// Status is the lifecycle state of a Scan. Values match the API contract
// documented in SPECIFICATIONS.md §5.5.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Progress is the live view of an in-flight scan, surfaced via SSE and on
// GET /scans/{guid}.
type Progress struct {
	Total        int    `json:"total"`
	Completed    int    `json:"completed"`
	CurrentPhase string `json:"current_phase,omitempty"`
}

// Scan is the full unit-of-storage. The Report field is only populated once
// Status == StatusCompleted; it is left as `any` until the report engine
// (Phase 12) defines the canonical struct.
type Scan struct {
	ID          string     `json:"id"`
	Status      Status     `json:"status"`
	Target      string     `json:"target"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Progress    Progress   `json:"progress"`

	// PrivateToken is non-empty for private scans. Returned once on creation,
	// never serialized via the public JSON path.
	PrivateToken string `json:"-"`

	// Findings is appended-to as checks complete. Order matches completion
	// time, not check ID.
	Findings []checks.Finding `json:"findings,omitempty"`

	// Report holds the final report payload (set when Status == completed).
	Report any `json:"report,omitempty"`

	// Error holds the failure reason when Status == failed.
	Error string `json:"error,omitempty"`
}

// ScanStore is the persistence contract for scans. All methods must be
// safe for concurrent use. UpdateStatus must apply fn atomically with
// respect to other Put/UpdateStatus calls on the same id.
type ScanStore interface {
	Put(ctx context.Context, scan *Scan, ttl time.Duration) error
	Get(ctx context.Context, id string) (*Scan, error)
	Delete(ctx context.Context, id string) error
	UpdateStatus(ctx context.Context, id string, fn func(*Scan) error) error
}
