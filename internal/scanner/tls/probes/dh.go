package probes

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// ProbeDHKeySize connects to addr with DHE-only cipher suites (TLS 1.2) and
// returns the DH prime length in bits by parsing the ServerKeyExchange message.
// Returns 0 if the server does not support DHE or the probe fails.
func ProbeDHKeySize(ctx context.Context, addr string) (int, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	pkt := craftTLSClientHello(0x0303, DHECipherSuites)
	if _, err := conn.Write(pkt); err != nil {
		return 0, err
	}

	r := &tlsRecordReader{conn: conn}

	// Expect ServerHello first.
	msgType, body, err := r.nextHandshake()
	if err != nil || msgType != 0x02 {
		return 0, nil
	}

	// Parse cipher from ServerHello to confirm DHE was selected.
	if len(body) < 35 {
		return 0, nil
	}
	sidLen := int(body[34])
	if len(body) < 35+sidLen+2 {
		return 0, nil
	}
	chosen := binary.BigEndian.Uint16(body[35+sidLen : 35+sidLen+2])
	if !isDHECipher(chosen) {
		return 0, nil // server selected a non-DHE suite
	}

	// Read records until ServerKeyExchange (0x0C) or ServerHelloDone (0x0E).
	for {
		msgType, body, err = r.nextHandshake()
		if err != nil {
			return 0, nil
		}
		switch msgType {
		case 0x0B: // Certificate — skip
			continue
		case 0x0C: // ServerKeyExchange
			return parseDHPrimeBits(body), nil
		case 0x0E: // ServerHelloDone (no SKE — shouldn't happen with DHE)
			return 0, nil
		}
	}
}

// parseDHPrimeBits extracts the DH prime length in bits from a ServerKeyExchange body.
//
// DHE ServerKeyExchange wire format (TLS 1.2):
//
//	dh_p_length (2 bytes) + dh_p + dh_g_length (2 bytes) + dh_g + dh_Ys_length (2) + dh_Ys
//	[ signature_algorithm (2) + signature_length (2) + signature ]
func parseDHPrimeBits(body []byte) int {
	if len(body) < 2 {
		return 0
	}
	primeBytes := int(binary.BigEndian.Uint16(body[0:2]))
	return primeBytes * 8
}

// isDHECipher reports whether suite is in DHECipherSuites.
func isDHECipher(id uint16) bool {
	for _, c := range DHECipherSuites {
		if c == id {
			return true
		}
	}
	return false
}

// tlsRecordReader reads successive TLS handshake messages from a connection,
// transparently buffering across multi-message records.
type tlsRecordReader struct {
	conn net.Conn
	buf  []byte // unconsumed bytes from the last Handshake record
}

// nextHandshake returns the next handshake message type and body.
// It silently skips ChangeCipherSpec (0x14) and ApplicationData (0x17) records.
// An Alert (0x15) record is returned as an error.
func (r *tlsRecordReader) nextHandshake() (msgType byte, body []byte, err error) {
	for {
		// If the buffer holds a complete message, consume it.
		if len(r.buf) >= 4 {
			t := r.buf[0]
			mlen := int(uint32(r.buf[1])<<16 | uint32(r.buf[2])<<8 | uint32(r.buf[3]))
			if len(r.buf) >= 4+mlen {
				msgType = t
				body = r.buf[4 : 4+mlen]
				r.buf = r.buf[4+mlen:]
				return msgType, body, nil
			}
		}

		// Need more data — read the next TLS record.
		hdr := make([]byte, 5)
		if _, err = io.ReadFull(r.conn, hdr); err != nil {
			return 0, nil, fmt.Errorf("tls record header: %w", err)
		}

		recType := hdr[0]
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		data := make([]byte, recLen)
		if _, err = io.ReadFull(r.conn, data); err != nil {
			return 0, nil, fmt.Errorf("tls record body: %w", err)
		}

		switch recType {
		case 0x15: // Alert
			return 0, nil, fmt.Errorf("server sent TLS alert")
		case 0x16: // Handshake — accumulate into buffer
			r.buf = append(r.buf, data...)
		default:
			// ChangeCipherSpec, ApplicationData — skip
		}
	}
}
