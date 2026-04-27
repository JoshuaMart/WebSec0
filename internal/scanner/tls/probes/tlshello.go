package probes

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// TLSHelloResult is the outcome of sending a TLS ClientHello.
type TLSHelloResult struct {
	// Accepted is true when the server replied with a Handshake/ServerHello record.
	Accepted bool
	// NegotiatedVersion is the TLS version from the ServerHello body (e.g. 0x0301).
	NegotiatedVersion uint16
	// NegotiatedCipher is the cipher suite the server selected.
	NegotiatedCipher uint16
}

// ProbeTLSHello sends a raw TLS ClientHello to addr ("host:port") and reads
// the first server record back. It does NOT complete the handshake.
//
//   - maxVersion sets the client_version field (e.g. 0x0301 for TLS 1.0).
//   - cipherSuites is the set of suites to advertise; nil uses broadCipherSuites.
func ProbeTLSHello(ctx context.Context, addr string, maxVersion uint16, cipherSuites []uint16) (TLSHelloResult, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSHelloResult{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	if _, err := conn.Write(craftTLSClientHello(maxVersion, cipherSuites)); err != nil {
		return TLSHelloResult{}, err
	}
	return readTLSServerHello(conn)
}

// craftTLSClientHello builds a minimal TLS ClientHello record.
// Per RFC 5246 §6.2.1 the record-layer version is always 0x0301.
func craftTLSClientHello(maxVersion uint16, cipherSuites []uint16) []byte {
	if len(cipherSuites) == 0 {
		cipherSuites = broadCipherSuites
	}

	var body []byte
	// client_version: highest TLS version we advertise
	body = binary.BigEndian.AppendUint16(body, maxVersion)
	// random (32 bytes)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)
	// session_id: empty
	body = append(body, 0x00)
	// cipher_suites + TLS_EMPTY_RENEGOTIATION_INFO_SCSV sentinel
	suites := append(append([]uint16{}, cipherSuites...), 0x00FF)
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)*2))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	// compression_methods: [1, null]
	body = append(body, 0x01, 0x00)

	// Handshake message header: ClientHello (0x01) + 3-byte length
	var hs []byte
	hs = append(hs, 0x01)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record header: Handshake (0x16) + version 0x0301 + 2-byte length
	var rec []byte
	rec = append(rec, 0x16, 0x03, 0x01)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

// readTLSServerHello reads the first TLS record from conn and parses a ServerHello.
func readTLSServerHello(conn net.Conn) (TLSHelloResult, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return TLSHelloResult{}, nil // connection closed = rejected
	}

	recordType := hdr[0]
	recordLen := binary.BigEndian.Uint16(hdr[3:5])
	if recordLen == 0 {
		return TLSHelloResult{}, nil
	}

	body := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return TLSHelloResult{}, nil
	}

	switch recordType {
	case 0x16: // Handshake
		return parseServerHelloHandshake(body), nil
	case 0x15: // Alert
		return TLSHelloResult{Accepted: false}, nil
	default:
		return TLSHelloResult{Accepted: false}, nil
	}
}

// parseServerHelloHandshake scans a Handshake record body for a ServerHello
// message and extracts the negotiated version and cipher suite.
func parseServerHelloHandshake(body []byte) TLSHelloResult {
	for len(body) >= 4 {
		msgType := body[0]
		msgLen := int(uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3]))
		if 4+msgLen > len(body) {
			break
		}
		msg := body[4 : 4+msgLen]

		if msgType == 0x02 { // ServerHello
			// ServerHello body: version(2) + random(32) + session_id_len(1) + cipher(2) + ...
			if len(msg) < 35 {
				break
			}
			version := binary.BigEndian.Uint16(msg[0:2])
			sidLen := int(msg[34])
			if len(msg) < 35+sidLen+2 {
				break
			}
			cipher := binary.BigEndian.Uint16(msg[35+sidLen : 35+sidLen+2])
			return TLSHelloResult{
				Accepted:          true,
				NegotiatedVersion: version,
				NegotiatedCipher:  cipher,
			}
		}
		body = body[4+msgLen:]
	}
	return TLSHelloResult{Accepted: false}
}

// broadCipherSuites is used for protocol-version probes when no specific
// cipher set is requested. It covers RSA and ECDHE suites typical of TLS 1.0/1.1 servers.
var broadCipherSuites = []uint16{
	0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x0005, // TLS_RSA_WITH_RC4_128_SHA
}

// Cipher suite groups for weak-cipher detection.
// Each group is offered exclusively so we can detect whether the server accepts
// that category. A successful ServerHello means the server supports those ciphers.

// NullCipherSuites provide no encryption whatsoever.
var NullCipherSuites = []uint16{
	0x0000, // TLS_NULL_WITH_NULL_NULL
	0x0001, // TLS_RSA_WITH_NULL_MD5
	0x0002, // TLS_RSA_WITH_NULL_SHA
	0x003B, // TLS_RSA_WITH_NULL_SHA256
}

// ExportCipherSuites use intentionally weakened key material (FREAK attack).
var ExportCipherSuites = []uint16{
	0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
	0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
	0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x000B, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
	0x000E, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
	0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
	0x0017, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
	0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
}

// RC4CipherSuites use the cryptographically broken RC4 stream cipher.
var RC4CipherSuites = []uint16{
	0x0005, // TLS_RSA_WITH_RC4_128_SHA
	0x0004, // TLS_RSA_WITH_RC4_128_MD5
	0xC011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
	0xC007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	0x0018, // TLS_DH_anon_WITH_RC4_128_MD5
}

// DESCipherSuites use single DES (broken, 56-bit effective key).
var DESCipherSuites = []uint16{
	0x0009, // TLS_RSA_WITH_DES_CBC_SHA
	0x000C, // TLS_DH_DSS_WITH_DES_CBC_SHA
	0x000F, // TLS_DH_RSA_WITH_DES_CBC_SHA
	0x0012, // TLS_DHE_DSS_WITH_DES_CBC_SHA
	0x0015, // TLS_DHE_RSA_WITH_DES_CBC_SHA
	0x001A, // TLS_DH_anon_WITH_DES_CBC_SHA
}

// TripleDESCipherSuites use 3DES (Sweet32 birthday attack, CVE-2016-2183).
var TripleDESCipherSuites = []uint16{
	0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x000D, // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
	0x0010, // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
	0x0013, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
	0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	0x001B, // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
	0xC012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	0xC008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
}

// CBCCipherSuites are CBC-mode ciphers that are vulnerable to BEAST when
// used with TLS 1.0 (pass maxVersion=0x0301 to ProbeTLSHello).
var CBCCipherSuites = []uint16{
	0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

// DHECipherSuites are finite-field Diffie-Hellman ephemeral suites used to
// probe the server's DH parameter size (see ProbeDHKeySize).
var DHECipherSuites = []uint16{
	0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
}
