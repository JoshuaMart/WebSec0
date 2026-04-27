package tls

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/tls/probes"
)

const cipherEnumCacheKey = "tls.cipherenum"

// CipherEnumResult holds the cipher suites accepted by the server for each
// protocol version, in server preference order.
type CipherEnumResult struct {
	// TLS12Accepted lists accepted TLS 1.2 cipher suite IDs, most-preferred first.
	// Derived by iterative raw-socket probing (one connection per accepted suite).
	TLS12Accepted []uint16

	// TLS13Cipher is the cipher suite negotiated in the TLS 1.3 handshake,
	// taken from the memoised HandshakeResult. 0 means TLS 1.3 was not probed
	// or not supported.
	TLS13Cipher uint16
}

// HasForwardSecrecy12 reports whether at least one accepted TLS 1.2 cipher
// provides forward secrecy (ECDHE or DHE key exchange).
func (r *CipherEnumResult) HasForwardSecrecy12() bool {
	for _, c := range r.TLS12Accepted {
		if isForwardSecretCipher(c) {
			return true
		}
	}
	return false
}

// CipherNames returns human-readable names for the accepted TLS 1.2 ciphers.
// Unknown IDs are formatted as "0xXXXX".
func (r *CipherEnumResult) CipherNames() []string {
	names := make([]string, len(r.TLS12Accepted))
	for i, id := range r.TLS12Accepted {
		if n := stdtls.CipherSuiteName(id); n != "" {
			names[i] = n
		} else if info, ok := legacyCipherNames[id]; ok {
			names[i] = info
		} else {
			names[i] = fmt.Sprintf("0x%04X", id)
		}
	}
	return names
}

// CipherEnumFetch performs (or memoises) TLS 1.2 cipher suite enumeration for
// the target. It uses at most len(tls12CandidateSuites)+1 TCP connections.
func CipherEnumFetch(ctx context.Context, t *checks.Target) (*CipherEnumResult, error) {
	v, err := t.CacheValue(cipherEnumCacheKey, func() (any, error) {
		return doCipherEnum(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	res, _ := v.(*CipherEnumResult)
	if res == nil {
		return nil, errors.New("tls: nil cipher enum result")
	}
	return res, nil
}

func doCipherEnum(ctx context.Context, t *checks.Target) *CipherEnumResult {
	res := &CipherEnumResult{}

	// Reuse the already-memoised TLS handshake to get the TLS 1.3 cipher.
	if hr, err := Fetch(ctx, t); err == nil {
		if p := hr.Probes[stdtls.VersionTLS13]; p != nil && p.Supported {
			res.TLS13Cipher = p.NegotiatedCS
		}
	}

	// Enumerate TLS 1.2 cipher suites via raw ClientHello probes.
	addr := t.DialAddress("443")
	res.TLS12Accepted = probes.EnumerateCipherSuites(ctx, addr, 0x0303, tls12CandidateSuites)
	return res
}

// isForwardSecretCipher reports whether id uses ephemeral key exchange
// (ECDHE or DHE), providing forward secrecy.
func isForwardSecretCipher(id uint16) bool {
	_, ok := forwardSecretSet[id]
	return ok
}

// forwardSecretSet contains all ECDHE and DHE cipher suite IDs.
var forwardSecretSet = map[uint16]struct{}{
	// ECDHE-ECDSA
	0xC02B: {}, 0xC02C: {}, 0xCCA9: {},
	0xC023: {}, 0xC024: {},
	0xC009: {}, 0xC00A: {},
	0xC007: {}, 0xC008: {},
	// ECDHE-RSA
	0xC02F: {}, 0xC030: {}, 0xCCA8: {},
	0xC027: {}, 0xC028: {},
	0xC013: {}, 0xC014: {},
	0xC011: {}, 0xC012: {},
	// DHE-RSA
	0x009E: {}, 0x009F: {}, 0xCCAA: {},
	0x0067: {}, 0x006B: {},
	0x0033: {}, 0x0039: {},
	0x0016: {},
	// DHE-DSS
	0x0032: {}, 0x0038: {},
	0x0013: {}, 0x001B: {},
}

// tls12CandidateSuites is the ordered set of TLS 1.2 cipher suites probed
// during enumeration. Strong/modern suites come first so the preference order
// reflected in the result matches a sensibly-configured server.
var tls12CandidateSuites = []uint16{
	// ECDHE-ECDSA GCM/ChaCha (strongest)
	0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	// ECDHE-RSA GCM/ChaCha
	0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	// DHE-RSA GCM/ChaCha
	0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	0xCCAA, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	// RSA GCM (no FS)
	0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
	0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
	// ECDHE-ECDSA CBC
	0xC023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	0xC024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	0xC00A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	// ECDHE-RSA CBC
	0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	// DHE-RSA CBC
	0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	// RSA CBC (no FS)
	0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
	0x003D, // TLS_RSA_WITH_AES_256_CBC_SHA256
	0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	// Weak — FS but broken cipher/hash
	0xC012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	0xC008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
	0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	// Weak — no FS
	0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0xC011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
	0xC007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	0x0005, // TLS_RSA_WITH_RC4_128_SHA
	0x0004, // TLS_RSA_WITH_RC4_128_MD5
}

// legacyCipherNames provides human-readable names for cipher suites not
// present in Go's stdlib (which only covers modern suites).
var legacyCipherNames = map[uint16]string{
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
}
