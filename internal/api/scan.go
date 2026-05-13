package api

import (
	"encoding/json"
	"net/http"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/go-chi/chi/v5"
)

// scanRequest is the JSON body accepted by POST /api/v1/scan.
type scanRequest struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	ListInHistory bool   `json:"list_in_history"`
	Fresh         bool   `json:"fresh"`
}

// scanPostHandler runs a scan and returns the full result.
func scanPostHandler(s ScanService, perHost *safehttp.Limiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req scanRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}

		if req.Host == "" {
			writeError(w, http.StatusBadRequest, "invalid_host", "host is required")
			return
		}
		if !perHost.Allow(req.Host) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "per-host rate limit exceeded")
			return
		}

		result, err := s.Run(r.Context(), scanner.Request{
			Host:          req.Host,
			Port:          req.Port,
			ListInHistory: req.ListInHistory,
			Fresh:         req.Fresh,
		})
		if err != nil {
			status, code, msg := mapError(err)
			writeError(w, status, code, msg)
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}

// scanGetHandler returns a previously-cached scan by ID, or 404.
func scanGetHandler(s ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_id", "id is required")
			return
		}
		result, ok := s.Get(id)
		if !ok {
			writeError(w, http.StatusNotFound, "not_found", "scan not found or expired")
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
