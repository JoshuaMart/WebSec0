package api

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/JoshuaMart/websec0/internal/logsafe"
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
				slog.String("method", logsafe.SingleLine(r.Method)),
				slog.String("path", logsafe.SingleLine(r.URL.Path)),
				slog.Int("status", ww.Status()),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.String("request_id", logsafe.SingleLine(middleware.GetReqID(r.Context()))),
			)
		})
	}
}

// apiCSP is the policy for responses that are not frontend pages: JSON
// never needs to load anything or be framed. The frontend handler replaces
// it with the page policy on everything it serves.
const apiCSP = "default-src 'none'; frame-ancestors 'none'"

// securityHeaders sets the browser security headers WebSec0 itself grades,
// so every deployment sends them without proxy configuration. HSTS is left
// to the TLS-terminating proxy, which knows whether HTTPS is in use.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", apiCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
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
