package tls

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
)

// defaultHandshakeTimeout caps a single attempt. The orchestrator combines
// many attempts under one budget; each individual handshake is kept short
// so a single slow protocol does not starve the others.
const defaultHandshakeTimeout = 3 * time.Second

type handshakeOpts struct {
	MinVersion   uint16
	MaxVersion   uint16
	CipherSuites []uint16
}

// probeSeq is a process-wide handshake counter, used by the per-handshake
// diagnostic log emitted from attemptHandshake. The log is silenced unless
// the binary is started with WEBSEC0_DEBUG_HANDSHAKES=1, but the counter
// always runs (atomic, near-zero cost) so a debug session can correlate
// the bascule to a specific protocol/cipher pair without re-deploying.
var probeSeq atomic.Int64

// attemptHandshake performs one TLS handshake against the pinned target
// using the supplied options. InsecureSkipVerify is always true at this
// layer — cert validation is performed separately in cert.go so we can
// observe the chain even when validation would fail.
func attemptHandshake(ctx context.Context, target *safehttp.Target, opts handshakeOpts) (state stdtls.ConnectionState, err error) {
	seq := probeSeq.Add(1)
	start := time.Now()

	// Per-handshake diagnostic log, emitted at Debug level so it stays out
	// of normal stderr. Toggled on by `log.debug_handshakes: true` in
	// websec0.yaml (wired in cmd/websec0/main.go).
	defer func() {
		attrs := []any{
			slog.Int64("seq", seq),
			slog.String("host", target.Host),
			slog.Int("port", target.Port),
			slog.String("min_version", versionLabel(opts.MinVersion)),
			slog.String("max_version", versionLabel(opts.MaxVersion)),
			slog.Bool("cipher_pinned", len(opts.CipherSuites) > 0),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("err_kind", classifyErr(err)),
		}
		if len(opts.CipherSuites) == 1 {
			attrs = append(attrs, slog.String("cipher_id", fmt.Sprintf("0x%04X", opts.CipherSuites[0])))
		}
		if err != nil {
			msg := err.Error()
			if len(msg) > 120 {
				msg = msg[:120]
			}
			attrs = append(attrs, slog.String("err_msg", msg))
		}
		slog.Debug("handshake", attrs...)
	}()

	timeout := defaultHandshakeTimeout
	rawConn, derr := safehttp.PinnedDialer(target, timeout).DialContext(ctx, "tcp", target.Address())
	if derr != nil {
		err = derr
		return
	}
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	cfg := &stdtls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true, //nolint:gosec // chain trust is recorded separately in cert.go
		MinVersion:         opts.MinVersion,
		MaxVersion:         opts.MaxVersion,
		CipherSuites:       opts.CipherSuites,
	}

	tlsConn := stdtls.Client(rawConn, cfg)
	if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
		_ = tlsConn.Close()
		err = hsErr
		return
	}
	state = tlsConn.ConnectionState()
	_ = tlsConn.Close()
	return
}

// versionLabel renders a stdlib TLS version constant as the same string
// used by modernProtocols, so log lines align with the report payload.
func versionLabel(v uint16) string {
	switch v {
	case stdtls.VersionTLS13:
		return "TLS 1.3"
	case stdtls.VersionTLS12:
		return "TLS 1.2"
	case stdtls.VersionTLS11:
		return "TLS 1.1"
	case stdtls.VersionTLS10:
		return "TLS 1.0"
	case 0:
		return "any"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

// classifyErr buckets a handshake error into one of a small set of kinds.
// The TLS-alert match is heuristic (stdlib does not export an alert error
// type) but is good enough to tell "server replied with handshake_failure"
// apart from "connection got blackholed" — the distinction the banDetector
// relies on to avoid tripping on legitimate RSTs.
func classifyErr(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "ctx_cancel"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	msg := err.Error()
	if strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "handshake failure") ||
		strings.Contains(msg, "no cipher suite") ||
		strings.Contains(msg, "protocol version") {
		return "tls_alert"
	}
	return "other"
}
