package api

import (
	"net/http"
	"strconv"

	"github.com/JoshuaMart/websec0/internal/history"
)

const (
	defaultHistoryLimit = 20
	maxHistoryLimit     = 100
)

// historyHandler serves the opt-in "Recent scans" list. Only scans that
// were submitted with `list_in_history: true` reach this endpoint, and
// only as long as they are inside the configured retention window
// (see the history.* block in websec0.yaml.example).
func historyHandler(s ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := defaultHistoryLimit
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed <= 0 {
				writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be a positive integer")
				return
			}
			if parsed > maxHistoryLimit {
				parsed = maxHistoryLimit
			}
			limit = parsed
		}
		entries := s.History(limit)
		if entries == nil {
			entries = []history.Entry{}
		}
		writeJSON(w, http.StatusOK, entries)
	}
}
