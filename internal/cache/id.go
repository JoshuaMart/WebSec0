package cache

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// NewID returns a 32-hex-character ID derived from host, the scan timestamp,
// and a 12-byte cryptographic nonce. The nonce dominates the entropy so
// two scans of the same host at the same instant still receive distinct
// IDs — the host/timestamp inputs only provide debuggability if a future
// version chooses to make IDs deterministic.
func NewID(host string, t time.Time) string {
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])

	h := sha256.New()
	_, _ = h.Write([]byte(host))
	_, _ = h.Write([]byte{0})
	_ = binary.Write(h, binary.BigEndian, t.UnixNano())
	_, _ = h.Write(nonce[:])

	return hex.EncodeToString(h.Sum(nil)[:16])
}
