package probes

import (
	stdtls "crypto/tls"
	"testing"
)

// Benchmarks for the hot deterministic parts of the TLS probe path:
// ClientHello crafting and ServerHello parsing. Network-dependent
// probes (Probe* functions) are excluded — they belong in the
// integration suite under the `integration` build tag.
//
// Run:
//
//	go test -run NONE -bench . -benchmem ./internal/scanner/tls/probes/

// BenchmarkCraftSSLv3ClientHello measures the cost of crafting an
// SSLv3 ClientHello record. This is the path used by every SSLv3
// probe; it must stay cheap because the orchestrator can issue ~50
// probes per scan.
func BenchmarkCraftSSLv3ClientHello(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = craftSSLv3ClientHello()
	}
}

// BenchmarkCraftSSLv2ClientHello measures the SSLv2 (Netscape record
// format) ClientHello crafting cost.
func BenchmarkCraftSSLv2ClientHello(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = craftSSLv2ClientHello()
	}
}

// BenchmarkCraftTLSClientHello_TLS12 measures the cost of crafting a
// TLS 1.2 ClientHello with the full set of legacy ciphers used during
// cipher enumeration.
func BenchmarkCraftTLSClientHello_TLS12(b *testing.B) {
	suites := []uint16{
		stdtls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		stdtls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		stdtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		stdtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		stdtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		stdtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		stdtls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		stdtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = craftTLSClientHello(stdtls.VersionTLS12, suites)
	}
}

// BenchmarkParseServerHelloHandshake measures the parsing cost of a
// ServerHello + Certificate handshake bundle. We feed a representative
// pre-built record (TLS 1.2 + ECDHE-RSA-AES256-GCM, single cert, no
// extensions). This is the hot path during cipher enumeration where
// hundreds of ServerHello messages are parsed per scan.
func BenchmarkParseServerHelloHandshake(b *testing.B) {
	body := buildServerHelloFixture()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseServerHelloHandshake(body)
	}
}

// buildServerHelloFixture produces a minimal valid ServerHello (no
// extensions) at TLS 1.2 with cipher 0xc030 (ECDHE-RSA-AES256-GCM-SHA384).
// It is *not* a valid full handshake — only the fields the parser
// reads. Kept inline so the bench has no external dependency.
func buildServerHelloFixture() []byte {
	const (
		msgServerHello = 0x02
	)
	body := make([]byte, 0, 64)

	// Handshake msg type + 24-bit length placeholder.
	body = append(body, msgServerHello, 0, 0, 0)

	// ServerHello body.
	hello := make([]byte, 0, 64)
	hello = append(hello, 0x03, 0x03)          // legacy_version = TLS 1.2
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0x00)                // session_id len = 0
	hello = append(hello, 0xc0, 0x30)          // cipher_suite
	hello = append(hello, 0x00)                // compression_method
	hello = append(hello, 0x00, 0x00)          // extensions len = 0

	// Patch the 24-bit length.
	n := len(hello)
	body[1] = byte(n >> 16)
	body[2] = byte(n >> 8)
	body[3] = byte(n)
	return append(body, hello...)
}
