// Package scanner orchestrates the execution of all registered checks
// against a Target.
package scanner

import "github.com/JoshuaMart/websec0/internal/checks"

// EventKind enumerates the asynchronous events emitted during a scan.
// Mirrors the SSE event names defined in SPECIFICATIONS.md §5.6.
type EventKind string

const (
	EventProgress  EventKind = "progress"
	EventFinding   EventKind = "finding"
	EventCompleted EventKind = "completed"
	EventFailed    EventKind = "failed"
)

// Event is the structured payload pushed to subscribers.
type Event struct {
	Kind     EventKind       `json:"-"`
	Progress *Progress       `json:"progress,omitempty"`
	Finding  *checks.Finding `json:"finding,omitempty"`
	Grade    string          `json:"grade,omitempty"`
	Score    int             `json:"score,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Progress is the live counter pair surfaced via SSE and on
// GET /api/v1/scans/{guid}.
type Progress struct {
	Total        int    `json:"total"`
	Completed    int    `json:"completed"`
	CurrentPhase string `json:"current_phase,omitempty"`
}
