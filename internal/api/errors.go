package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scanner"
)

// errorBody is the JSON shape returned on every error.
type errorBody struct {
	Error errorInner `json:"error"`
}

type errorInner struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError emits the typed JSON error response and sets the status.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errorInner{Code: code, Message: message}})
}

// mapError translates a domain error to an HTTP status, a stable error code
// and a user-facing message. Unknown errors are surfaced as 500 with a
// generic message — the underlying detail goes to the request log.
func mapError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, scanner.ErrEmptyHost):
		return http.StatusBadRequest, "invalid_host", err.Error()
	case errors.Is(err, safehttp.ErrInvalidScheme):
		return http.StatusBadRequest, "invalid_scheme", err.Error()
	case errors.Is(err, safehttp.ErrIPLiteral):
		return http.StatusBadRequest, "ip_literal", err.Error()
	case errors.Is(err, safehttp.ErrUserInfo):
		return http.StatusBadRequest, "userinfo_in_url", err.Error()
	case errors.Is(err, safehttp.ErrInvalidHost):
		return http.StatusBadRequest, "invalid_host", err.Error()
	case errors.Is(err, safehttp.ErrCustomPortBlocked):
		return http.StatusForbidden, "custom_port_blocked", err.Error()
	case errors.Is(err, safehttp.ErrPrivateTargetBlocked):
		return http.StatusForbidden, "private_target_blocked", err.Error()
	case errors.Is(err, safehttp.ErrNoAllowedIP):
		return http.StatusBadGateway, "no_allowed_ip", err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusRequestTimeout, "scan_timeout", "scan exceeded the configured budget"
	default:
		return http.StatusInternalServerError, "internal_error", "unexpected error"
	}
}
