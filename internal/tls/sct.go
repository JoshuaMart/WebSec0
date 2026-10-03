package tls

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"

	"golang.org/x/crypto/cryptobyte"

	"github.com/JoshuaMart/websec0/internal/scan"
)

var oidCertificateSCTs = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func extractCertificateSCTs(chain []*x509.Certificate) *scan.CertificateSCTs {
	if len(chain) == 0 || chain[0] == nil {
		return nil
	}
	out := &scan.CertificateSCTs{SCTSummary: scan.SCTSummary{LogIDs: []string{}}}
	var raw []byte
	for _, ext := range chain[0].Extensions {
		if !ext.Id.Equal(oidCertificateSCTs) {
			continue
		}
		if out.Present {
			out.ParseError = true
			return out
		}
		out.Present = true
		raw = ext.Value
	}
	if !out.Present {
		return out
	}
	entries, ok := parseSCTExtension(raw)
	if !ok {
		out.ParseError = true
		return out
	}
	out.SCTSummary = *summarizeSCTs(entries)
	return out
}

// parseSCTExtension unwraps the DER OCTET STRING and TLS vectors (RFC 6962 §3.3).
// Reject the whole list if its framing is invalid: the entry count is then unknown.
func parseSCTExtension(raw []byte) ([][]byte, bool) {
	var serialized []byte
	rest, err := asn1.Unmarshal(raw, &serialized)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	s := cryptobyte.String(serialized)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() || list.Empty() {
		return nil, false
	}
	var entries [][]byte
	for !list.Empty() {
		var entry cryptobyte.String
		if !list.ReadUint16LengthPrefixed(&entry) || entry.Empty() {
			return nil, false
		}
		entries = append(entries, entry)
	}
	return entries, true
}

func summarizeSCTs(entries [][]byte) *scan.SCTSummary {
	out := &scan.SCTSummary{Count: len(entries), LogIDs: []string{}}
	seen := make(map[string]bool)
	for _, entry := range entries {
		id, ok := sctLogID(entry)
		if !ok {
			out.UnparsedCount++
			continue
		}
		if !seen[id] {
			out.LogIDs = append(out.LogIDs, id)
			seen[id] = true
		}
	}
	return out
}

// sctLogID checks the RFC 6962 §3.2 wire structure, not the signature or log trust.
func sctLogID(raw []byte) (string, bool) {
	s := cryptobyte.String(raw)
	var version uint8
	var id []byte
	var extensions, signature cryptobyte.String
	if !s.ReadUint8(&version) || version != 0 ||
		!s.ReadBytes(&id, 32) || !s.Skip(8) ||
		!s.ReadUint16LengthPrefixed(&extensions) ||
		!s.Skip(2) || !s.ReadUint16LengthPrefixed(&signature) ||
		len(signature) == 0 || !s.Empty() {
		return "", false
	}
	return hex.EncodeToString(id), true
}
