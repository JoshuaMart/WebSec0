// Package sslv3 detects whether a server speaks SSLv3 by sending a
// TLS-framed ClientHello with version 0x0300 and classifying the response.
// See SPEC §9.2.
package sslv3

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
)

// DefaultTimeout is used when Probe is called with a zero timeout.
const DefaultTimeout = 5 * time.Second

// Probe sends an SSLv3 ClientHello to target and returns whether the
// server replied with a ServerHello announcing SSLv3 (0x0300). Any I/O
// failure or alternative response is interpreted as "not supported".
func Probe(ctx context.Context, target *safehttp.Target, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	dialer := safehttp.PinnedDialer(target, timeout)
	conn, err := dialer.DialContext(ctx, "tcp", target.Address())
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hello, err := buildClientHello()
	if err != nil {
		return false
	}
	if _, err := conn.Write(hello); err != nil {
		return false
	}
	return readAndClassify(conn)
}

func readAndClassify(conn net.Conn) bool {
	buf := make([]byte, 5)
	n, err := io.ReadAtLeast(conn, buf, 3)
	if err != nil && n < 3 {
		return false
	}
	return classify(buf[:n])
}

// buildClientHello assembles a 54-byte TLS record carrying an SSLv3
// ClientHello that advertises three classic SSLv3 cipher suites.
func buildClientHello() ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	hello := []byte{
		// record header
		0x16,       // handshake
		0x03, 0x00, // record version = SSLv3
		0x00, 0x31, // record length = 49 (4 hs header + 45 hs body)

		// handshake header
		0x01,             // ClientHello
		0x00, 0x00, 0x2d, // handshake length = 45

		// client_hello body
		0x03, 0x00, // SSLv3 version
	}
	hello = append(hello, random...) // 32-byte random
	hello = append(hello,
		0x00,       // session_id_length
		0x00, 0x06, // cipher_suites_length: 6 (3 suites)
		0x00, 0x05, // RSA_WITH_RC4_128_SHA
		0x00, 0x0A, // RSA_WITH_3DES_EDE_CBC_SHA
		0x00, 0x35, // RSA_WITH_AES_256_CBC_SHA
		0x01, // compression_methods_length
		0x00, // null compression
	)
	return hello, nil
}

// classify maps the first 3+ bytes of the server response to a yes/no.
//
//   - 0x16 0x03 0x00 …  → ServerHello with SSLv3 negotiated → supported.
//   - 0x15 …            → TLS alert (protocol_version, handshake_failure) → not supported.
//   - 0x16 0x03 0x01+ … → server insists on a higher version → not SSLv3.
//   - anything else / short read → not supported.
func classify(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	if b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x00 {
		return true
	}
	return false
}
