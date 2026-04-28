// Package middleware exposes the chi-compatible middlewares used by the
// WebSec0 HTTP server: request-id, panic recovery, slog access log,
// and a CORS allowlist.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// requestIDKey is the context key under which the per-request id is stored.
type requestIDKey struct{}

// RequestIDFromContext returns the request id assigned by RequestID middleware.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey{}).(string)
	return v
}

// srcIPKey is the context key for the per-request source IP.
type srcIPKey struct{}

// SourceIP wraps next so the handler can read the (single-hop XFF aware)
// source IP via SourceIPFromContext.
func SourceIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractSourceIP(r)
		ctx := context.WithValue(r.Context(), srcIPKey{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SourceIPFromContext returns the IP captured by SourceIP middleware.
func SourceIPFromContext(ctx context.Context) string {
	v, _ := ctx.Value(srcIPKey{}).(string)
	return v
}

func extractSourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := xff
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			first = xff[:comma]
		}
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	if host, _, err := splitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// splitHostPort wraps net.SplitHostPort without pulling net into the
// public surface (helper kept here so this file's imports stay tight).
func splitHostPort(addr string) (host, port string, err error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", nil
	}
	return addr[:i], addr[i+1:], nil
}

// RequestID generates a 16-byte hex id for each incoming request, attaches
// it to the request context, and echoes it on the response via the
// X-Request-ID header. Any client-supplied X-Request-ID is honoured if it
// is short enough and only contains safe characters.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Recover wraps next so that any panic is logged with the stack trace and
// converted to a 500 JSON response. The request id is included in the log.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic recovered",
						"request_id", RequestIDFromContext(r.Context()),
						"path", r.URL.Path,
						"method", r.Method,
						"panic", rec,
						"stack", string(debug.Stack()),
					)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"code":"internal_error","message":"internal server error"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog logs one structured line per request. The target hostname is
// only logged when logTargets is true (privacy by design — see §9.4).
func AccessLog(log *slog.Logger, logTargets bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			attrs := []any{
				"request_id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
			}
			if logTargets && r.URL.RawQuery != "" {
				attrs = append(attrs, "query", r.URL.RawQuery)
			}
			log.Info("http", attrs...)
		})
	}
}

// CORSOptions configures the CORS middleware.
type CORSOptions struct {
	// AllowedOrigins is the explicit allowlist. "*" disables CORS protection
	// and is only acceptable for fully public read-only deployments.
	AllowedOrigins []string
}

// CORS returns a chi-compatible CORS middleware with sane defaults for an
// API + same-origin frontend deployment.
func CORS(opts CORSOptions) func(http.Handler) http.Handler {
	origins := opts.AllowedOrigins
	if len(origins) == 0 {
		origins = []string{"https://*"}
	}
	return cors.Handler(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID", "Location", "Retry-After"},
		AllowCredentials: false,
		MaxAge:           300,
	})
}

// JoinOriginList parses a comma-separated env-style origin list.
func JoinOriginList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
