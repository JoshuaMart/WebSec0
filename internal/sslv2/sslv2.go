// Package sslv2 detects whether a server speaks the obsolete SSLv2
// protocol. The Go stdlib has no SSLv2 support, so we forge a CLIENT-HELLO
// at the raw TCP layer and classify the first bytes of the response. See
// Protocol reference: draft-hickman-netscape-ssl-00 §1.5 (CLIENT-HELLO)
// and §1.6 (SERVER-HELLO).
package sslv2

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

// Probe sends an SSLv2 CLIENT-HELLO to target and returns whether the
// server replied with an SSLv2 SERVER-HELLO. Any I/O failure (refused,
// reset, timeout, unexpected framing) is interpreted as "not supported" —
// the function never returns an error.
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

// buildClientHello assembles a 48-byte SSLv2 CLIENT-HELLO advertising seven
// cipher specs (RC4, RC2, IDEA, DES, 3DES) and a fresh 16-byte challenge.
func buildClientHello() ([]byte, error) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	hello := []byte{
		0x80, 0x2e, // record length (high bit + 46 bytes follow)
		0x01,       // CLIENT-HELLO message type
		0x00, 0x02, // SSLv2 version
		0x00, 0x15, // cipher_spec_length: 21 (7 specs × 3 bytes)
		0x00, 0x00, // session_id_length
		0x00, 0x10, // challenge_length
		// cipher specs (each 3 bytes — kind code + 2-byte cipher id):
		0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
		0x02, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
		0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
		0x04, 0x00, 0x80, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
		0x05, 0x00, 0x80, // SSL_CK_IDEA_128_CBC_WITH_MD5
		0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
		0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	}
	return append(hello, challenge...), nil
}

// classify maps the first response bytes to a yes/no decision.
// - TLS handshake framing (0x16 0x03 *) or TLS alert (0x15 0x03 *) →
// the server speaks TLS, not SSLv2.
// - SSLv2 record framing (high bit of byte 0 set) followed by message
// type 0x04 (SERVER-HELLO) → SSLv2 supported.
// - Anything else, including a short read → not supported.
func classify(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	if (b[0] == 0x16 || b[0] == 0x15) && b[1] == 0x03 {
		return false
	}
	// 2-byte SSLv2 length form: byte 0 has top bit set.
	if b[0]&0x80 != 0 && b[2] == 0x04 {
		return true
	}
	// 3-byte SSLv2 length form: byte 0 has 0x40 bit set, message type at offset 3.
	if b[0]&0x80 == 0 && b[0]&0x40 != 0 && len(b) >= 4 && b[3] == 0x04 {
		return true
	}
	return false
}
