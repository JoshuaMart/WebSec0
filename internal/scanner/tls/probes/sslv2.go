package probes

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// sslv2Ciphers is the list of SSL 2.0 cipher kinds (3 bytes each) we advertise.
var sslv2Ciphers = []byte{
	0x07, 0x00, 0x85, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	0x05, 0x00, 0x80, // SSL_CK_DES_64_CBC_WITH_MD5
	0x03, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
	0x01, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
	0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_SHA
}

// craftSSLv2ClientHello returns an SSL 2.0 ClientHello using the 2-byte
// record-header variant (MSB of first byte set, no padding).
//
// SSLv2 record format (2-byte header):
//
//	header[0] = 0x80 | (length >> 8)
//	header[1] = length & 0xFF
//	body:
//	  msg_type (1)       = 0x01 (client_hello)
//	  version  (2)       = 0x0002 (SSL 2.0)
//	  cipher_specs_len (2)
//	  session_id_len (2) = 0
//	  challenge_len (2)  = 16
//	  cipher_specs
//	  challenge
func craftSSLv2ClientHello() []byte {
	challenge := make([]byte, 16)
	_, _ = rand.Read(challenge)

	var body []byte
	body = append(body, 0x01)                                              // msg_type = client_hello
	body = append(body, 0x00, 0x02)                                        // version = SSL 2.0
	body = binary.BigEndian.AppendUint16(body, uint16(len(sslv2Ciphers))) // cipher_specs_length
	body = append(body, 0x00, 0x00)                                        // session_id_length = 0
	body = append(body, 0x00, 0x10)                                        // challenge_length = 16
	body = append(body, sslv2Ciphers...)
	body = append(body, challenge...)

	// 2-byte header: MSB set, length in lower 15 bits
	bodyLen := uint16(len(body))
	pkt := []byte{
		byte(0x80 | (bodyLen >> 8)),
		byte(bodyLen),
	}
	return append(pkt, body...)
}

// ProbeSSLv2 sends an SSL 2.0 ClientHello to addr ("host:port") and reports
// whether the server accepts it.
//
// Detection logic:
//   - SSLv2 ServerHello (msg_type=0x04) → StatusAccepted
//   - TCP RST / EOF / error record     → StatusRejected
//   - Parse error                       → StatusUnknown
func ProbeSSLv2(ctx context.Context, addr string) (ProtocolStatus, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return StatusUnknown, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(craftSSLv2ClientHello()); err != nil {
		return StatusUnknown, err
	}

	// Read first 2 bytes to determine header type and body length.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return StatusRejected, nil
		}
		return StatusUnknown, err
	}

	var bodyLen int
	if hdr[0]&0x80 != 0 {
		// 2-byte header: length = (hdr[0] & 0x7F)<<8 | hdr[1]
		bodyLen = int(hdr[0]&0x7F)<<8 | int(hdr[1])
	} else {
		// 3-byte header: read the padding byte, length in lower 14 bits
		extra := make([]byte, 1)
		if _, err := io.ReadFull(conn, extra); err != nil {
			return StatusUnknown, err
		}
		bodyLen = int(hdr[0]&0x3F)<<8 | int(hdr[1])
		// extra[0] is the padding byte, ignored
	}

	if bodyLen == 0 {
		return StatusRejected, nil
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return StatusUnknown, err
	}

	// First byte of the SSLv2 body is the message type.
	// 0x04 = server_hello → server accepted SSLv2.
	if len(body) > 0 && body[0] == 0x04 {
		return StatusAccepted, nil
	}
	return StatusRejected, nil
}
