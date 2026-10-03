package tls

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// Synthetic v1 wire data: a log ID, timestamp, extensions and opaque signature.
// The signature is deliberately not cryptographically valid.
func fixtureSCT(id byte) []byte {
	raw := append([]byte{0}, bytes.Repeat([]byte{id}, 32)...)
	return append(raw,
		0, 0, 1, 0x8b, 0xcf, 0xe5, 0x68, 0, // timestamp
		0, 2, 0xaa, 0xbb, // extensions
		4, 3, 0, 3, 0x30, 0x01, 0x00, // SHA-256/ECDSA, signature
	)
}

func TestSCTLogID(t *testing.T) {
	valid := fixtureSCT(0xab)
	if id, ok := sctLogID(valid); !ok || id != strings.Repeat("ab", 32) {
		t.Fatalf("valid SCT: got %q, %v", id, ok)
	}
	for n := 0; n < len(valid); n++ {
		t.Run(fmt.Sprintf("truncated_at_%d", n), func(t *testing.T) {
			if id, ok := sctLogID(valid[:n]); ok || id != "" {
				t.Fatalf("truncated SCT yielded %q, %v", id, ok)
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"unknown_version", func(b []byte) []byte { b[0] = 1; return b }},
		{"oversized_extensions", func(b []byte) []byte { b[41], b[42] = 255, 255; return b }},
		{"oversized_signature", func(b []byte) []byte { b[47], b[48] = 255, 255; return b }},
		{"empty_signature", func(b []byte) []byte { b[48] = 0; return b[:49] }},
		{"trailing_bytes", func(b []byte) []byte { return append(b, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if id, ok := sctLogID(tc.edit(bytes.Clone(valid))); ok || id != "" {
				t.Fatalf("invalid SCT yielded %q, %v", id, ok)
			}
		})
	}
	withoutExtensions := append(bytes.Clone(valid[:41]), 0, 0)
	withoutExtensions = append(withoutExtensions, valid[45:]...)
	if _, ok := sctLogID(withoutExtensions); !ok {
		t.Fatal("empty extensions should be accepted")
	}
}

func TestSummarizeSCTs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries [][]byte
		want    scan.SCTSummary
	}{
		{"absent", nil, scan.SCTSummary{LogIDs: []string{}}},
		{"multiple_logs", [][]byte{fixtureSCT(0xab), fixtureSCT(0xcd)}, scan.SCTSummary{
			Count: 2, LogIDs: []string{strings.Repeat("ab", 32), strings.Repeat("cd", 32)},
		}},
		{"mixed_and_duplicates", [][]byte{nil, fixtureSCT(0xab), {1}, fixtureSCT(0xab)}, scan.SCTSummary{
			Count: 4, LogIDs: []string{strings.Repeat("ab", 32)}, UnparsedCount: 2,
		}},
		{"all_unparsed", [][]byte{{1}, {0}}, scan.SCTSummary{
			Count: 2, LogIDs: []string{}, UnparsedCount: 2,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarizeSCTs(tc.entries); !reflect.DeepEqual(*got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestProbeHandshakeSCTs(t *testing.T) {
	// Reuse httptest's certificate in servers configured before starting.
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	cert := seed.TLS.Certificates[0]
	seed.Close()
	for _, version := range []uint16{stdtls.VersionTLS12, stdtls.VersionTLS13} {
		for _, present := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/present=%t", versionLabel(version), present), func(t *testing.T) {
				serverCert := cert
				want := &scan.SCTSummary{LogIDs: []string{}}
				if present {
					serverCert.SignedCertificateTimestamps = [][]byte{fixtureSCT(0xab), {1}}
					want = &scan.SCTSummary{Count: 2, LogIDs: []string{strings.Repeat("ab", 32)}, UnparsedCount: 1}
				}
				srv := httptest.NewUnstartedServer(http.NotFoundHandler())
				srv.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{serverCert}, MinVersion: version, MaxVersion: version}
				srv.StartTLS()
				defer srv.Close()
				report := Probe(context.Background(), makeTargetForServer(t, srv))
				if !reflect.DeepEqual(report.HandshakeSCTs, want) {
					t.Fatalf("got %+v, want %+v", report.HandshakeSCTs, want)
				}
				assertSCTJSON(t, report, "handshake_scts", want)
			})
		}
	}
}

func TestHandshakeSCTsUnavailable(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := Probe(ctx, makeTargetForServer(t, srv))
	if report.HandshakeSCTs != nil {
		t.Fatalf("failed handshake must not report absent SCTs: %+v", report.HandshakeSCTs)
	}
	assertSCTJSON(t, report, "handshake_scts", nil)
	assertSCTJSON(t, report, "certificate_scts", nil)
}

func assertSCTJSON(t *testing.T, report *scan.TLSReport, field string, want any) {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	got, present := payload[field]
	if want == nil {
		if present {
			t.Fatal("unavailable SCT field should be omitted")
		}
		return
	}
	expected, err := json.Marshal(want)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("%s JSON = %s, want %s (err %v)", field, got, expected, err)
	}
}

func FuzzSCTLogID(f *testing.F) {
	f.Add(fixtureSCT(0xab))
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		id, ok := sctLogID(raw)
		if !ok {
			if id != "" {
				t.Fatal("unparsed SCT yielded an ID")
			}
			return
		}
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("invalid log ID: %q", id)
		}
	})
}
