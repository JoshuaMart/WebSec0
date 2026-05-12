package api

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/go-chi/chi/v5/middleware"
)

// slogRequestLogger emits one structured info log per request once the
// downstream handler has returned. Includes method, path, status,
// duration and the chi request ID.
func slogRequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info(
				"request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)
		})
	}
}

// perIPRateLimit enforces a per-IP token bucket. The bucket key is the
// remote IP derived from RemoteAddr — trusted-proxy / X-Forwarded-For
// handling is deferred to v1.1 (requires the operator to declare a
// trusted-proxy list to be safe).
func perIPRateLimit(l *safehttp.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.Allow(clientIP(r)) {
				writeError(w, http.StatusTooManyRequests, "rate_limited", "per-IP rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP returns the IP portion of r.RemoteAddr, stripping the port.
func clientIP(r *http.Request) string {
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}
