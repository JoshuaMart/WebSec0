// Package audit writes anonymised scan-event records to an
// append-only log. Operators rotate the file via logrotate / journald;
// the package itself only cares about anonymisation and serialization.
//
// SPECIFICATIONS.md §9.4 (privacy by design):
//   - source IP is masked: IPv4 last octet zeroed, IPv6 last 64 bits zeroed
//   - hostname is hashed (SHA-256, 16-hex-char prefix), never written in clear
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Logger appends scan-event records to a writer. Concurrent-safe.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger returns a Logger writing to w. Pass os.Stderr or open a
// rotating file. nil disables auditing (Logger.Record becomes a no-op).
func NewLogger(w io.Writer) *Logger {
	return &Logger{w: w}
}

// FromPath opens path in append mode. Returns a no-op Logger when path
// is empty.
func FromPath(path string) (*Logger, error) {
	if path == "" {
		return NewLogger(nil), nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //#nosec G304 -- caller-supplied audit path
	if err != nil {
		return nil, err
	}
	return NewLogger(f), nil
}

// Event is a structured scan record. Decision is one of "accepted",
// "blocked", "cached", "cooldown", "rate_limited", "abuse_flagged".
type Event struct {
	TimestampUTC time.Time `json:"ts"`
	Decision     string    `json:"decision"`
	HostHash     string    `json:"host_hash"`
	IPMasked     string    `json:"ip_masked"`
	ScanID       string    `json:"scan_id,omitempty"`
	Reason       string    `json:"reason,omitempty"`
}

// Record writes one event. Errors are swallowed — auditing must never
// break the request path.
func (l *Logger) Record(e Event) {
	if l == nil || l.w == nil {
		return
	}
	if e.TimestampUTC.IsZero() {
		e.TimestampUTC = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(b)
	_, _ = l.w.Write([]byte("\n"))
}

// HashHost returns the first 16 hex chars of SHA-256(host) — enough
// entropy to dedupe but not enough to brute-force back from a leaked
// log file.
func HashHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(host))
	return hex.EncodeToString(sum[:8])
}

// MaskIP applies SPECIFICATIONS.md §9.5: IPv4 last octet zeroed, IPv6
// reduced to its /64 prefix. Inputs that don't parse return "invalid".
func MaskIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return "invalid"
	}
	if v4 := ip.To4(); v4 != nil {
		out := make(net.IP, 4)
		copy(out, v4)
		out[3] = 0
		return out.String()
	}
	out := make(net.IP, 16)
	copy(out, ip)
	for i := 8; i < 16; i++ {
		out[i] = 0
	}
	return out.String()
}
