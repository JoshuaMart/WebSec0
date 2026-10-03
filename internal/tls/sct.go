package tls

import (
	"encoding/hex"

	"golang.org/x/crypto/cryptobyte"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func extractHandshakeSCTs(entries [][]byte) *scan.HandshakeSCTs {
	out := &scan.HandshakeSCTs{Count: len(entries), LogIDs: []string{}}
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
