package tls

import (
	"context"
	stdtls "crypto/tls"
	"fmt"
	"slices"
	"strings"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// allKnownSuites returns the union of stdlib's "modern" and "insecure"
// cipher suite tables. TLS 1.3 suites are included.
func allKnownSuites() []*stdtls.CipherSuite {
	out := append([]*stdtls.CipherSuite{}, stdtls.CipherSuites()...)
	return append(out, stdtls.InsecureCipherSuites()...)
}

// enumerateLegacyCiphers iterates all stdlib-known suites applicable to the
// given TLS version, attempts a single-cipher handshake for each, and
// records the ones the server accepts. Only applicable to TLS 1.0–1.2;
// TLS 1.3 cipher suites are not configurable via crypto/tls and are
// captured by captureTLS13Cipher.
//
// Every handshake outcome is fed to bd; the loop aborts as soon as the
// detector flips, so a ban that hits mid-enumeration returns whatever was
// already accepted instead of burning 3s per remaining cipher.
func enumerateLegacyCiphers(ctx context.Context, target *safehttp.Target, version uint16, protoName string, bd *banDetector) []scan.Cipher {
	var offered []scan.Cipher
	for _, suite := range allKnownSuites() {
		if bd.Triggered() {
			break
		}
		if !slices.Contains(suite.SupportedVersions, version) {
			continue
		}
		state, err := attemptHandshake(ctx, target, handshakeOpts{
			MinVersion:   version,
			MaxVersion:   version,
			CipherSuites: []uint16{suite.ID},
		})
		bd.Record(err)
		if err != nil {
			continue
		}
		if state.CipherSuite != suite.ID {
			continue
		}
		offered = append(offered, mapCipher(suite, protoName))
	}
	return offered
}

// captureTLS13Cipher records the single cipher the server negotiates when
// only TLS 1.3 is offered. Full TLS 1.3 cipher enumeration would require
// forging raw ClientHellos and is deferred to a future iteration. The
// handshake outcome is fed to bd so a TLS 1.3 attempt that times out can
// arm the ban detector for downstream versions.
func captureTLS13Cipher(ctx context.Context, target *safehttp.Target, bd *banDetector) []scan.Cipher {
	state, err := attemptHandshake(ctx, target, handshakeOpts{
		MinVersion: stdtls.VersionTLS13,
		MaxVersion: stdtls.VersionTLS13,
	})
	bd.Record(err)
	if err != nil {
		return nil
	}
	suite := lookupSuite(state.CipherSuite)
	if suite == nil {
		return nil
	}
	return []scan.Cipher{mapCipher(suite, "TLS 1.3")}
}

func lookupSuite(id uint16) *stdtls.CipherSuite {
	for _, s := range allKnownSuites() {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func mapCipher(s *stdtls.CipherSuite, protoName string) scan.Cipher {
	return scan.Cipher{
		Protocol: protoName,
		Name:     s.Name,
		Code:     fmt.Sprintf("0x%04X", s.ID),
		Strength: cipherStrength(s.Name),
		AEAD:     isAEAD(s.Name),
		PFS:      hasPFS(s.Name, protoName),
		Level:    cipherSeverity(s),
	}
}

func cipherStrength(name string) int {
	switch {
	case strings.Contains(name, "AES_256"), strings.Contains(name, "AES256"):
		return 256
	case strings.Contains(name, "CHACHA20"):
		return 256
	case strings.Contains(name, "AES_128"), strings.Contains(name, "AES128"):
		return 128
	case strings.Contains(name, "3DES"):
		return 168
	case strings.Contains(name, "RC4"):
		return 128
	default:
		return 0
	}
}

func isAEAD(name string) bool {
	return strings.Contains(name, "GCM") || strings.Contains(name, "CHACHA20")
}

// hasPFS reports whether the suite provides forward secrecy. TLS 1.3 names
// do not encode the key exchange in the suite name; every TLS 1.3 cipher
// uses (EC)DHE by construction, so they are unconditionally PFS.
func hasPFS(name, protoName string) bool {
	if protoName == "TLS 1.3" {
		return true
	}
	return strings.Contains(name, "ECDHE") || strings.Contains(name, "DHE_")
}

func cipherSeverity(s *stdtls.CipherSuite) scan.Severity {
	if s.Insecure {
		return scan.SeverityBad
	}
	if !isAEAD(s.Name) {
		return scan.SeverityWarn
	}
	return scan.SeverityGood
}
