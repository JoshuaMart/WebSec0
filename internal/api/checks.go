package api

import (
	"encoding/json"
	"net/http"
)

// checksPayload is the v1 placeholder catalog. Phase 10 will replace this
// with an //go:embed-loaded JSON file containing every check the scanner
// performs (TLS, headers, custom) along with its remediation snippet.
type checksPayload struct {
	Version string `json:"version"`
	Checks  []any  `json:"checks"`
}

// checksHandler serves a stable JSON catalog of checks. The current payload
// is a placeholder; the real catalog lands in Phase 10.
func checksHandler() http.HandlerFunc {
	payload := checksPayload{
		Version: "1.0.0-draft",
		Checks:  []any{},
	}
	body, _ := json.Marshal(payload)

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}
}
