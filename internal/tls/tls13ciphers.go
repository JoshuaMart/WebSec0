package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// crypto/tls does not let a client choose its TLS 1.3 cipher suites, so a
// stdlib handshake only reveals the one suite the server prefers. To list
// every suite, each one is offered alone in a hand-built TLS 1.3
// ClientHello and the server's first reply is read: a ServerHello (or a
// HelloRetryRequest) that selects the suite means it is accepted, an alert
// means it is not. The handshake is never completed.

const (
	recordTypeAlert     = 0x15
	recordTypeHandshake = 0x16
	maxRecordLen        = 16384 + 2048

	handshakeTypeClientHello = 0x01
	handshakeTypeServerHello = 0x02

	extServerName          = 0x0000
	extSupportedGroups     = 0x000a
	extSignatureAlgorithms = 0x000d
	extSupportedVersions   = 0x002b
	extKeyShare            = 0x0033

	groupX25519    = 0x001d
	groupSecp256r1 = 0x0017
	groupSecp384r1 = 0x0018
)

// tls13SignatureAlgorithms covers every scheme a TLS 1.3 server certificate
// may need, so a server never rejects the hello for lack of one.
var tls13SignatureAlgorithms = []uint16{
	0x0403, 0x0503, 0x0603, // ecdsa_secp256r1_sha256, secp384r1_sha384, secp521r1_sha512
	0x0807, 0x0808, // ed25519, ed448
	0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha256/384/512
	0x0809, 0x080a, 0x080b, // rsa_pss_pss_sha256/384/512
	0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha256/384/512
}

// errSuiteRejected is classified as a TLS alert by classifyErr, so a
// rejected suite never arms the ban detector.
var errSuiteRejected = errors.New("tls: server rejected the offered cipher suite")

// tls13Suites returns the TLS 1.3 suites crypto/tls implements, the same
// catalog enumerateLegacyCiphers uses for older versions.
func tls13Suites() []*stdtls.CipherSuite {
	var out []*stdtls.CipherSuite
	for _, s := range allKnownSuites() {
		if slices.Contains(s.SupportedVersions, stdtls.VersionTLS13) {
			out = append(out, s)
		}
	}
	return out
}

// enumerateTLS13Ciphers offers each TLS 1.3 suite on its own and records the
// ones the server accepts. Every attempt is fed to bd, as in
// enumerateLegacyCiphers.
func enumerateTLS13Ciphers(ctx context.Context, target *safehttp.Target, bd *banDetector) []scan.Cipher {
	var offered []scan.Cipher
	for _, suite := range tls13Suites() {
		if bd.Triggered() {
			break
		}
		accepted, err := offerTLS13Suite(ctx, target, suite.ID)
		bd.Record(err)
		if accepted {
			offered = append(offered, mapCipher(suite, "TLS 1.3"))
		}
	}
	return offered
}

// tls13Ciphers lists the TLS 1.3 suites the server accepts. If the raw
// probe finds none (a server that rejects the hand-built hello for another
// reason), it falls back to the suite a stdlib handshake negotiates, so the
// report never loses the TLS 1.3 row it had before.
func tls13Ciphers(ctx context.Context, target *safehttp.Target, bd *banDetector) []scan.Cipher {
	if ciphers := enumerateTLS13Ciphers(ctx, target, bd); len(ciphers) > 0 {
		return ciphers
	}
	if bd.Triggered() {
		return nil
	}
	return captureTLS13Cipher(ctx, target, bd)
}

// offerTLS13Suite sends a TLS 1.3 ClientHello offering only suite and
// reports whether the server selected it. A nil error means the server
// answered with a ServerHello; errSuiteRejected means it sent an alert.
func offerTLS13Suite(ctx context.Context, target *safehttp.Target, suite uint16) (bool, error) {
	timeout := defaultHandshakeTimeout
	conn, err := safehttp.PinnedDialer(target, timeout).DialContext(ctx, "tcp", target.Address())
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	hello, err := buildTLS13ClientHello(sniHost(target.Host), suite)
	if err != nil {
		return false, err
	}
	if _, err := conn.Write(hello); err != nil {
		return false, err
	}
	selected, err := readServerHelloSuite(conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, err
	}
	if selected != suite {
		return false, fmt.Errorf("tls: server selected suite 0x%04X that was not offered", selected)
	}
	return true, nil
}

// sniHost mirrors crypto/tls: no SNI for IP literals, no trailing dot.
func sniHost(host string) string {
	host = strings.TrimSuffix(host, ".")
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ""
	}
	return host
}

// buildTLS13ClientHello returns one TLS record carrying a ClientHello that
// offers TLS 1.3 only, a single cipher suite and an X25519 key share.
// P-256 and P-384 are also listed, so a server without X25519 answers with
// a HelloRetryRequest, which still names the selected suite.
func buildTLS13ClientHello(serverName string, suite uint16) ([]byte, error) {
	random := make([]byte, 32)
	sessionID := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	if _, err := rand.Read(sessionID); err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var hello cryptobyte.Builder
	hello.AddUint8(handshakeTypeClientHello)
	hello.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(stdtls.VersionTLS12) // legacy_version
		b.AddBytes(random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sessionID) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(suite) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) }) // null compression
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if serverName != "" {
				b.AddUint16(extServerName)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(0) // host_name
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(serverName)) })
					})
				})
			}
			b.AddUint16(extSupportedGroups)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(groupX25519)
					b.AddUint16(groupSecp256r1)
					b.AddUint16(groupSecp384r1)
				})
			})
			b.AddUint16(extSignatureAlgorithms)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, alg := range tls13SignatureAlgorithms {
						b.AddUint16(alg)
					}
				})
			})
			b.AddUint16(extSupportedVersions)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(stdtls.VersionTLS13) })
			})
			b.AddUint16(extKeyShare)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(groupX25519)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
				})
			})
		})
	})
	body, err := hello.Bytes()
	if err != nil {
		return nil, err
	}

	var record cryptobyte.Builder
	record.AddUint8(recordTypeHandshake)
	record.AddUint16(stdtls.VersionTLS10) // legacy_record_version, as clients send it
	record.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
	return record.Bytes()
}

// readServerHelloSuite reads the server's first record and returns the
// cipher suite its ServerHello selects. An alert returns errSuiteRejected.
// A ServerHello that does not negotiate TLS 1.3 is an error: only a TLS 1.3
// suite was offered.
func readServerHelloSuite(r io.Reader) (uint16, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}
	length := int(header[3])<<8 | int(header[4])
	switch {
	case header[0] == recordTypeAlert:
		return 0, errSuiteRejected
	case header[0] != recordTypeHandshake:
		return 0, fmt.Errorf("tls: unexpected record type %d", header[0])
	case length == 0 || length > maxRecordLen:
		return 0, fmt.Errorf("tls: invalid record length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, err
	}
	return parseServerHelloSuite(payload)
}

func parseServerHelloSuite(payload []byte) (uint16, error) {
	errMalformed := errors.New("tls: malformed ServerHello")
	s := cryptobyte.String(payload)
	var msgType uint8
	var msg cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != handshakeTypeServerHello {
		return 0, fmt.Errorf("tls: expected ServerHello, got handshake type %d", msgType)
	}
	if !s.ReadUint24LengthPrefixed(&msg) {
		return 0, errMalformed
	}
	var legacyVersion, suite uint16
	var sessionID, extensions cryptobyte.String
	var compression uint8
	if !msg.ReadUint16(&legacyVersion) ||
		!msg.Skip(32) || // random; a HelloRetryRequest has the same layout
		!msg.ReadUint8LengthPrefixed(&sessionID) ||
		!msg.ReadUint16(&suite) ||
		!msg.ReadUint8(&compression) ||
		!msg.ReadUint16LengthPrefixed(&extensions) {
		return 0, errMalformed
	}
	for !extensions.Empty() {
		var extType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&data) {
			return 0, errMalformed
		}
		var version uint16
		if extType == extSupportedVersions && data.ReadUint16(&version) && version == stdtls.VersionTLS13 {
			return suite, nil
		}
	}
	return 0, errors.New("tls: ServerHello did not negotiate TLS 1.3")
}
