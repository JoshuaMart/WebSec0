package probes_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scanner/tls/probes"
)

// ---- helpers ----------------------------------------------------------------

func serveTCP(t *testing.T, handler func(net.Conn)) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
	}()
	return ln.Addr().String()
}

// tlsRecordHeader builds the 5-byte header for a TLS record.
func tlsRecordHeader(recType byte, recVersion uint16, bodyLen int) []byte {
	hdr := make([]byte, 5)
	hdr[0] = recType
	binary.BigEndian.PutUint16(hdr[1:3], recVersion)
	binary.BigEndian.PutUint16(hdr[3:5], uint16(bodyLen))
	return hdr
}

// buildServerHelloRecord builds a minimal TLS ServerHello record.
func buildServerHelloRecord(recVersion, helloVersion, cipher uint16) []byte {
	random := make([]byte, 32)
	_, _ = rand.Read(random)

	var shBody []byte
	shBody = binary.BigEndian.AppendUint16(shBody, helloVersion)
	shBody = append(shBody, random...)
	shBody = append(shBody, 0x00)                            // session_id_length = 0
	shBody = binary.BigEndian.AppendUint16(shBody, cipher)  // cipher suite
	shBody = append(shBody, 0x00)                            // compression = null

	var hs []byte
	hs = append(hs, 0x02) // ServerHello
	hs = append(hs, byte(len(shBody)>>16), byte(len(shBody)>>8), byte(len(shBody)))
	hs = append(hs, shBody...)

	rec := tlsRecordHeader(0x16, recVersion, len(hs))
	return append(rec, hs...)
}

// buildTLSAlert builds a TLS Alert record.
func buildTLSAlert(recVersion uint16) []byte {
	rec := tlsRecordHeader(0x15, recVersion, 2)
	return append(rec, 0x02, 0x28) // fatal, handshake_failure
}

// discardClientHello reads and discards one TLS record (ClientHello).
func discardClientHello(conn net.Conn) {
	hdr := make([]byte, 5)
	_, _ = io.ReadFull(conn, hdr)
	if len(hdr) < 5 {
		return
	}
	bodyLen := binary.BigEndian.Uint16(hdr[3:5])
	body := make([]byte, bodyLen)
	_, _ = io.ReadFull(conn, body)
}

// ---- SSLv3 tests ------------------------------------------------------------

func TestProbeSSLv3_Accepted(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildServerHelloRecord(0x0300, 0x0300, 0x000A))
	})

	status, err := probes.ProbeSSLv3(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != probes.StatusAccepted {
		t.Errorf("got %v, want StatusAccepted", status)
	}
}

func TestProbeSSLv3_RejectedAlert(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildTLSAlert(0x0301))
	})

	status, err := probes.ProbeSSLv3(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != probes.StatusRejected {
		t.Errorf("got %v, want StatusRejected", status)
	}
}

func TestProbeSSLv3_RejectedClose(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		// close without writing anything → server rejects
	})

	status, _ := probes.ProbeSSLv3(context.Background(), addr)
	if status != probes.StatusRejected {
		t.Errorf("got %v, want StatusRejected", status)
	}
}

func TestProbeSSLv3_TLS12ServerHello(t *testing.T) {
	// Server replies with TLS 1.2 record version → should NOT count as SSLv3 accepted.
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildServerHelloRecord(0x0303, 0x0303, 0x002F))
	})

	status, _ := probes.ProbeSSLv3(context.Background(), addr)
	if status != probes.StatusRejected {
		t.Errorf("got %v, want StatusRejected (TLS 1.2 record version should not match SSLv3)", status)
	}
}

// ---- SSLv2 tests ------------------------------------------------------------

func buildSSLv2ServerHello() []byte {
	cert := []byte{0x30, 0x00, 0x00} // minimal dummy cert
	cipher := []byte{0x03, 0x00, 0x80}
	connID := []byte{0xAB, 0xCD}

	var body []byte
	body = append(body, 0x04)                                             // server_hello
	body = append(body, 0x00)                                             // session_id_hit = 0
	body = append(body, 0x01)                                             // certificate_type = X509
	body = append(body, 0x00, 0x02)                                       // server_version = SSL 2.0
	body = binary.BigEndian.AppendUint16(body, uint16(len(cert)))         // certificate_length
	body = binary.BigEndian.AppendUint16(body, uint16(len(cipher)))       // cipher_specs_length
	body = binary.BigEndian.AppendUint16(body, uint16(len(connID)))       // connection_id_length
	body = append(body, cert...)
	body = append(body, cipher...)
	body = append(body, connID...)

	bodyLen := uint16(len(body))
	pkt := []byte{byte(0x80 | (bodyLen >> 8)), byte(bodyLen)}
	return append(pkt, body...)
}

func TestProbeSSLv2_Accepted(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		// Discard SSLv2 ClientHello (2-byte header)
		hdr := make([]byte, 2)
		_, _ = io.ReadFull(conn, hdr)
		bodyLen := int(hdr[0]&0x7F)<<8 | int(hdr[1])
		body := make([]byte, bodyLen)
		_, _ = io.ReadFull(conn, body)

		_, _ = conn.Write(buildSSLv2ServerHello())
	})

	status, err := probes.ProbeSSLv2(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != probes.StatusAccepted {
		t.Errorf("got %v, want StatusAccepted", status)
	}
}

func TestProbeSSLv2_RejectedClose(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		conn.Close() // immediate close
	})

	status, _ := probes.ProbeSSLv2(context.Background(), addr)
	if status != probes.StatusRejected {
		t.Errorf("got %v, want StatusRejected", status)
	}
}

// ---- TLSHello tests ---------------------------------------------------------

func TestProbeTLSHello_TLS10Accepted(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildServerHelloRecord(0x0301, 0x0301, 0x002F))
	})

	res, err := probes.ProbeTLSHello(context.Background(), addr, 0x0301, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Accepted {
		t.Fatal("expected Accepted=true")
	}
	if res.NegotiatedVersion != 0x0301 {
		t.Errorf("got version 0x%04X, want 0x0301", res.NegotiatedVersion)
	}
	if res.NegotiatedCipher != 0x002F {
		t.Errorf("got cipher 0x%04X, want 0x002F", res.NegotiatedCipher)
	}
}

func TestProbeTLSHello_RejectedAlert(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildTLSAlert(0x0303))
	})

	res, err := probes.ProbeTLSHello(context.Background(), addr, 0x0301, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Accepted {
		t.Error("expected Accepted=false")
	}
}

func TestProbeTLSHello_WeakCipherAccepted(t *testing.T) {
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		// Server selects RC4 cipher
		_, _ = conn.Write(buildServerHelloRecord(0x0303, 0x0303, 0x0005))
	})

	res, err := probes.ProbeTLSHello(context.Background(), addr, 0x0303, probes.RC4CipherSuites)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Accepted {
		t.Fatal("expected Accepted=true")
	}
	if res.NegotiatedCipher != 0x0005 {
		t.Errorf("got cipher 0x%04X, want 0x0005 (RC4)", res.NegotiatedCipher)
	}
}

// ---- DHE key size test ------------------------------------------------------

func buildCertificateRecord() []byte {
	cert := []byte{0x30, 0x03, 0x01, 0x02, 0x03} // minimal ASN.1 SEQUENCE
	var body []byte
	// certificate_list: 3-byte list length + per-cert (3-byte length + DER)
	listLen := 3 + len(cert)
	body = append(body, byte(listLen>>16), byte(listLen>>8), byte(listLen))
	body = append(body, byte(len(cert)>>16), byte(len(cert)>>8), byte(len(cert)))
	body = append(body, cert...)

	var hs []byte
	hs = append(hs, 0x0B) // Certificate
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := tlsRecordHeader(0x16, 0x0303, len(hs))
	return append(rec, hs...)
}

func buildDHEServerKeyExchange(dhPrimeBytes int) []byte {
	prime := make([]byte, dhPrimeBytes)
	_, _ = rand.Read(prime)
	prime[0] |= 0x80 // ensure MSB set (valid prime format)

	g := []byte{0x02}                 // generator = 2
	Ys := make([]byte, dhPrimeBytes)  // server public value
	_, _ = rand.Read(Ys)
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)

	var ske []byte
	ske = binary.BigEndian.AppendUint16(ske, uint16(len(prime)))
	ske = append(ske, prime...)
	ske = binary.BigEndian.AppendUint16(ske, uint16(len(g)))
	ske = append(ske, g...)
	ske = binary.BigEndian.AppendUint16(ske, uint16(len(Ys)))
	ske = append(ske, Ys...)
	ske = append(ske, 0x04, 0x01) // signature_algorithm: sha256, rsa
	ske = binary.BigEndian.AppendUint16(ske, uint16(len(sig)))
	ske = append(ske, sig...)

	var hs []byte
	hs = append(hs, 0x0C) // ServerKeyExchange
	hs = append(hs, byte(len(ske)>>16), byte(len(ske)>>8), byte(len(ske)))
	hs = append(hs, ske...)

	rec := tlsRecordHeader(0x16, 0x0303, len(hs))
	return append(rec, hs...)
}

func buildServerHelloDone() []byte {
	hs := []byte{0x0E, 0x00, 0x00, 0x00} // ServerHelloDone, length=0
	rec := tlsRecordHeader(0x16, 0x0303, len(hs))
	return append(rec, hs...)
}

func TestProbeDHKeySize_1024bit(t *testing.T) {
	const primeBytes = 128 // 1024-bit prime
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildServerHelloRecord(0x0303, 0x0303, 0x0033)) // DHE_RSA_AES_128_CBC_SHA
		_, _ = conn.Write(buildCertificateRecord())
		_, _ = conn.Write(buildDHEServerKeyExchange(primeBytes))
		_, _ = conn.Write(buildServerHelloDone())
	})

	bits, err := probes.ProbeDHKeySize(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bits != primeBytes*8 {
		t.Errorf("got %d bits, want %d", bits, primeBytes*8)
	}
}

func TestProbeDHKeySize_2048bit(t *testing.T) {
	const primeBytes = 256 // 2048-bit prime
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildServerHelloRecord(0x0303, 0x0303, 0x0033))
		_, _ = conn.Write(buildCertificateRecord())
		_, _ = conn.Write(buildDHEServerKeyExchange(primeBytes))
		_, _ = conn.Write(buildServerHelloDone())
	})

	bits, err := probes.ProbeDHKeySize(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bits != primeBytes*8 {
		t.Errorf("got %d bits, want %d", bits, primeBytes*8)
	}
}

// ---- EnumerateCipherSuites tests -------------------------------------------

// servePickingCiphers returns a mock server that accepts connections, reads
// one ClientHello, and replies with a ServerHello selecting the FIRST cipher
// from the offered list that matches one in acceptSet (server preference order
// = acceptSet order). Returns Alert if none match.
func servePickingCiphers(t *testing.T, acceptSet []uint16) string {
	t.Helper()
	return serveTCP(t, func(conn net.Conn) {
		defer conn.Close()

		// Read and parse the ClientHello to find offered ciphers.
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		recLen := binary.BigEndian.Uint16(hdr[3:5])
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		// Parse offered cipher suites from the ClientHello body.
		// body[0]=HandshakeType, body[1:4]=length, body[4:6]=version, body[6:38]=random,
		// body[38]=session_id_len, then 2-byte cipher_suites_len, then suites.
		if len(body) < 43 {
			_, _ = conn.Write(buildTLSAlert(0x0303))
			return
		}
		sidLen := int(body[38])
		base := 39 + sidLen
		if len(body) < base+2 {
			_, _ = conn.Write(buildTLSAlert(0x0303))
			return
		}
		csLen := int(binary.BigEndian.Uint16(body[base : base+2]))
		base += 2
		if len(body) < base+csLen {
			_, _ = conn.Write(buildTLSAlert(0x0303))
			return
		}
		var offered []uint16
		for i := 0; i+1 < csLen; i += 2 {
			offered = append(offered, binary.BigEndian.Uint16(body[base+i:base+i+2]))
		}

		// Pick the first acceptSet cipher that appears in offered.
		chosen := uint16(0)
		for _, want := range acceptSet {
			for _, got := range offered {
				if got == want {
					chosen = want
					break
				}
			}
			if chosen != 0 {
				break
			}
		}
		if chosen == 0 {
			_, _ = conn.Write(buildTLSAlert(0x0303))
			return
		}
		_, _ = conn.Write(buildServerHelloRecord(0x0303, 0x0303, chosen))
	})
}

func TestEnumerateCipherSuites_ServerPreferenceTwoSuites(t *testing.T) {
	// Server accepts 0xC02F and 0x002F (in that preference order).
	accepted := []uint16{0xC02F, 0x002F}

	// We need a fresh listener per call because serveTCP only accepts one connection.
	// Wrap servePickingCiphers to handle multiple sequential connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				recLen := binary.BigEndian.Uint16(hdr[3:5])
				body := make([]byte, recLen)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				if len(body) < 43 {
					_, _ = c.Write(buildTLSAlert(0x0303))
					return
				}
				sidLen := int(body[38])
				base := 39 + sidLen
				if len(body) < base+2 {
					_, _ = c.Write(buildTLSAlert(0x0303))
					return
				}
				csLen := int(binary.BigEndian.Uint16(body[base : base+2]))
				base += 2
				if len(body) < base+csLen {
					_, _ = c.Write(buildTLSAlert(0x0303))
					return
				}
				var offered []uint16
				for i := 0; i+1 < csLen; i += 2 {
					offered = append(offered, binary.BigEndian.Uint16(body[base+i:base+i+2]))
				}
				chosen := uint16(0)
				for _, want := range accepted {
					for _, got := range offered {
						if got == want {
							chosen = want
							break
						}
					}
					if chosen != 0 {
						break
					}
				}
				if chosen == 0 {
					_, _ = c.Write(buildTLSAlert(0x0303))
					return
				}
				_, _ = c.Write(buildServerHelloRecord(0x0303, 0x0303, chosen))
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	result := probes.EnumerateCipherSuites(context.Background(), addr, 0x0303, []uint16{0x002F, 0xC02F, 0x0035})

	if len(result) != 2 {
		t.Fatalf("got %d ciphers, want 2: %v", len(result), result)
	}
	// Server preference: 0xC02F first, then 0x002F
	if result[0] != 0xC02F {
		t.Errorf("first accepted cipher = 0x%04X, want 0xC02F", result[0])
	}
	if result[1] != 0x002F {
		t.Errorf("second accepted cipher = 0x%04X, want 0x002F", result[1])
	}
}

func TestEnumerateCipherSuites_NoneAccepted(t *testing.T) {
	// Server always sends Alert.
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildTLSAlert(0x0303))
	})

	result := probes.EnumerateCipherSuites(context.Background(), addr, 0x0303, []uint16{0xC02F, 0x002F})
	if len(result) != 0 {
		t.Errorf("got %v, want empty slice", result)
	}
}

func TestProbeDHKeySize_NoDHE(t *testing.T) {
	// Server responds with a non-DHE cipher (ECDHE) → should return 0.
	addr := serveTCP(t, func(conn net.Conn) {
		defer conn.Close()
		discardClientHello(conn)
		_, _ = conn.Write(buildServerHelloRecord(0x0303, 0x0303, 0xC02F)) // ECDHE cipher
	})

	bits, err := probes.ProbeDHKeySize(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bits != 0 {
		t.Errorf("got %d bits, want 0 (non-DHE cipher)", bits)
	}
}
