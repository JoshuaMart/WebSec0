// Package probes implements raw-socket TLS probes for legacy protocols.
// None of these probes depend on the Go crypto/tls standard library, allowing
// detection of protocols that stdlib no longer supports (SSLv2, SSLv3, TLS 1.0/1.1).
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

// ProtocolStatus is the result of a raw-socket legacy protocol probe.
type ProtocolStatus int

const (
	// StatusRejected means the server refused the protocol (Alert or EOF).
	StatusRejected ProtocolStatus = iota
	// StatusAccepted means the server sent a ServerHello at the probed version.
	StatusAccepted
	// StatusUnknown means the result is inconclusive (timeout, parse error, etc.).
	StatusUnknown
)

// craftSSLv3ClientHello returns a well-formed SSLv3 ClientHello record
// advertising historical ciphers (3DES, RC4, DES, EXPORT).
func craftSSLv3ClientHello() []byte {
	var body []byte

	// Client version: SSLv3 (0x0300)
	body = append(body, 0x03, 0x00)

	// Random (32 bytes)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)

	// Session ID length = 0
	body = append(body, 0x00)

	// Cipher suites targeting SSLv3-era servers
	ciphers := []uint16{
		0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
		0x0004, // TLS_RSA_WITH_RC4_128_MD5
		0x0009, // TLS_RSA_WITH_DES_CBC_SHA
		0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		body = binary.BigEndian.AppendUint16(body, c)
	}

	// Compression methods: [1, null]
	body = append(body, 0x01, 0x00)

	// Handshake message: type=ClientHello(0x01) + 3-byte length
	var hs []byte
	hs = append(hs, 0x01)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record: type=Handshake(0x16) + version SSLv3(0x0300) + 2-byte length
	var rec []byte
	rec = append(rec, 0x16, 0x03, 0x00)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

// ProbeSSLv3 sends an SSLv3 ClientHello to addr ("host:port") and reports
// whether the server accepts the connection.
//
// Detection logic:
//   - ServerHello at version 0x0300 → StatusAccepted
//   - Alert record (0x15)           → StatusRejected
//   - TCP RST / EOF                 → StatusRejected
//   - Anything else                 → StatusUnknown
func ProbeSSLv3(ctx context.Context, addr string) (ProtocolStatus, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return StatusUnknown, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(craftSSLv3ClientHello()); err != nil {
		return StatusUnknown, err
	}

	// Read the 5-byte TLS record header.
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return StatusRejected, nil
		}
		return StatusUnknown, err
	}

	recordType := header[0]
	version := binary.BigEndian.Uint16(header[1:3])

	switch recordType {
	case 0x16: // Handshake — success if server echoed SSLv3 version
		if version == 0x0300 {
			return StatusAccepted, nil
		}
		return StatusRejected, nil
	case 0x15: // Alert
		return StatusRejected, nil
	default:
		return StatusUnknown, nil
	}
}
