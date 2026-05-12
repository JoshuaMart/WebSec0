package tls

import (
	"context"
	stdtls "crypto/tls"
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

// attemptHandshake performs one TLS handshake against the pinned target
// using the supplied options. InsecureSkipVerify is always true at this
// layer — cert validation is performed separately in cert.go so we can
// observe the chain even when validation would fail.
func attemptHandshake(ctx context.Context, target *safehttp.Target, opts handshakeOpts) (stdtls.ConnectionState, error) {
	timeout := defaultHandshakeTimeout
	rawConn, err := safehttp.PinnedDialer(target, timeout).DialContext(ctx, "tcp", target.Address())
	if err != nil {
		return stdtls.ConnectionState{}, err
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
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return stdtls.ConnectionState{}, err
	}
	state := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	return state, nil
}
