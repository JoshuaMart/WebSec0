package tls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func wrapSCTList(t testing.TB, serialized []byte) []byte {
	t.Helper()
	raw, err := asn1.Marshal(serialized)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixtureSCTExtension(t testing.TB, entries ...[]byte) []byte {
	t.Helper()
	var list []byte
	for _, entry := range entries {
		list = binary.BigEndian.AppendUint16(list, uint16(len(entry)))
		list = append(list, entry...)
	}
	serialized := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	return wrapSCTList(t, append(serialized, list...))
}

func TestParseSCTExtension(t *testing.T) {
	entries := [][]byte{fixtureSCT(0xab), fixtureSCT(0xcd), fixtureSCT(0xab)}
	valid := fixtureSCTExtension(t, entries...)
	if got, ok := parseSCTExtension(valid); !ok || !reflect.DeepEqual(got, entries) {
		t.Fatalf("round trip: got %x, %v", got, ok)
	}
	for n := 0; n < len(valid); n++ {
		t.Run(fmt.Sprintf("truncated_at_%d", n), func(t *testing.T) {
			if got, ok := parseSCTExtension(valid[:n]); ok || got != nil {
				t.Fatal("truncated extension must not yield partial observations")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"wrong_asn1_tag":       {0x05, 0},
		"trailing_der":         append(bytes.Clone(valid), 0),
		"double_octet_string":  wrapSCTList(t, valid),
		"empty_list":           fixtureSCTExtension(t),
		"empty_entry":          fixtureSCTExtension(t, nil),
		"missing_list_length":  wrapSCTList(t, []byte{0}),
		"list_too_short":       wrapSCTList(t, []byte{0, 2, 0, 1, 1}),
		"list_too_long":        wrapSCTList(t, []byte{0, 4, 0, 1, 1}),
		"entry_too_long":       wrapSCTList(t, []byte{0, 3, 0, 2, 1}),
		"partial_entry_length": wrapSCTList(t, []byte{0, 4, 0, 1, 1, 0}),
		"valid_then_empty":     fixtureSCTExtension(t, fixtureSCT(0xab), nil),
		"indefinite_der":       {0x04, 0x80, 0, 3, 0, 1, 1, 0, 0},
		"nonminimal_der":       {0x04, 0x81, 5, 0, 3, 0, 1, 1},
		"bare_tls_list":        {0, 3, 0, 1, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := parseSCTExtension(raw); ok || got != nil {
				t.Fatalf("invalid extension yielded %x, %v", got, ok)
			}
		})
	}
}

func TestExtractCertificateSCTs(t *testing.T) {
	ext := pkix.Extension{Id: oidCertificateSCTs, Value: fixtureSCTExtension(t,
		fixtureSCT(0xab), []byte{1}, fixtureSCT(0xcd), fixtureSCT(0xab), []byte{0},
	)}
	empty := scan.SCTSummary{LogIDs: []string{}}
	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
		want  *scan.CertificateSCTs
	}{
		{"no_chain", nil, nil},
		{"no_leaf", []*x509.Certificate{nil}, nil},
		{"absent", []*x509.Certificate{{}}, &scan.CertificateSCTs{SCTSummary: empty}},
		{"intermediate_only", []*x509.Certificate{{}, {Extensions: []pkix.Extension{ext}}}, &scan.CertificateSCTs{SCTSummary: empty}},
		{"other_extension", []*x509.Certificate{{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: ext.Value}}}}, &scan.CertificateSCTs{SCTSummary: empty}},
		{"mixed_and_duplicates", []*x509.Certificate{{Extensions: []pkix.Extension{ext}}}, &scan.CertificateSCTs{
			Present: true, SCTSummary: scan.SCTSummary{Count: 5, LogIDs: []string{strings.Repeat("ab", 32), strings.Repeat("cd", 32)}, UnparsedCount: 2},
		}},
		{"malformed_extension", []*x509.Certificate{{Extensions: []pkix.Extension{{Id: oidCertificateSCTs, Value: []byte{0}}}}}, &scan.CertificateSCTs{Present: true, ParseError: true, SCTSummary: empty}},
		{"duplicate_extension", []*x509.Certificate{{Extensions: []pkix.Extension{ext, ext}}}, &scan.CertificateSCTs{Present: true, ParseError: true, SCTSummary: empty}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := extractCertificateSCTs(tc.chain)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestProbeCertificateSCTs(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint16{stdtls.VersionTLS12, stdtls.VersionTLS13} {
		for _, tc := range []struct {
			name string
			raw  []byte
			want scan.CertificateSCTs
		}{
			{"absent", nil, scan.CertificateSCTs{SCTSummary: scan.SCTSummary{LogIDs: []string{}}}},
			{"embedded", fixtureSCTExtension(t, fixtureSCT(0xab), fixtureSCT(0xab), []byte{1}), scan.CertificateSCTs{
				Present: true, SCTSummary: scan.SCTSummary{Count: 3, LogIDs: []string{strings.Repeat("ab", 32)}, UnparsedCount: 1},
			}},
			{"malformed", []byte{0}, scan.CertificateSCTs{Present: true, ParseError: true, SCTSummary: scan.SCTSummary{LogIDs: []string{}}}},
		} {
			t.Run(versionLabel(version)+"/"+tc.name, func(t *testing.T) {
				template := &x509.Certificate{
					SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"},
					DNSNames:  []string{"example.test"},
					NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
					NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
					KeyUsage:  x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				}
				if tc.raw != nil {
					template.ExtraExtensions = []pkix.Extension{{Id: oidCertificateSCTs, Value: tc.raw}}
				}
				der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
				if err != nil {
					t.Fatal(err)
				}
				cert := stdtls.Certificate{
					Certificate: [][]byte{der}, PrivateKey: private,
					SignedCertificateTimestamps: [][]byte{fixtureSCT(0xcd)},
				}
				srv := httptest.NewUnstartedServer(http.NotFoundHandler())
				srv.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{cert}, MinVersion: version, MaxVersion: version}
				srv.StartTLS()
				defer srv.Close()
				report := Probe(context.Background(), makeTargetForServer(t, srv))
				if !reflect.DeepEqual(report.CertificateSCTs, &tc.want) {
					t.Fatalf("certificate SCTs: got %+v, want %+v", report.CertificateSCTs, tc.want)
				}
				wantHandshake := &scan.SCTSummary{Count: 1, LogIDs: []string{strings.Repeat("cd", 32)}}
				if !reflect.DeepEqual(report.HandshakeSCTs, wantHandshake) {
					t.Fatalf("handshake SCTs changed: %+v", report.HandshakeSCTs)
				}
				assertSCTJSON(t, report, "certificate_scts", &tc.want)
				assertSCTJSON(t, report, "handshake_scts", wantHandshake)
			})
		}
	}
}

func TestCertificateSCTsJSON(t *testing.T) {
	for _, tc := range []struct {
		observation scan.CertificateSCTs
		want        string
	}{
		{
			scan.CertificateSCTs{SCTSummary: scan.SCTSummary{LogIDs: []string{}}},
			`{"count":0,"log_ids":[],"unparsed_count":0,"present":false,"parse_error":false}`,
		},
		{
			scan.CertificateSCTs{Present: true, ParseError: true, SCTSummary: scan.SCTSummary{LogIDs: []string{}}},
			`{"count":0,"log_ids":[],"unparsed_count":0,"present":true,"parse_error":true}`,
		},
		{
			scan.CertificateSCTs{Present: true, SCTSummary: scan.SCTSummary{Count: 1, LogIDs: []string{}, UnparsedCount: 1}},
			`{"count":1,"log_ids":[],"unparsed_count":1,"present":true,"parse_error":false}`,
		},
	} {
		raw, err := json.Marshal(tc.observation)
		if err != nil || string(raw) != tc.want {
			t.Errorf("got %s (err %v), want %s", raw, err, tc.want)
		}
	}
}

func FuzzCertificateSCTs(f *testing.F) {
	f.Add(fixtureSCTExtension(f, fixtureSCT(0xab), fixtureSCT(0xcd), []byte{1}))
	f.Add([]byte{})
	f.Add([]byte{0x04, 2, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		got := extractCertificateSCTs([]*x509.Certificate{{Extensions: []pkix.Extension{{Id: oidCertificateSCTs, Value: raw}}}})
		if !got.Present || got.LogIDs == nil {
			t.Fatal("present extension must yield an observation")
		}
		if got.ParseError {
			if got.Count != 0 || got.UnparsedCount != 0 || len(got.LogIDs) != 0 {
				t.Fatal("malformed framing must not yield partial counts or IDs")
			}
		} else if got.Count < 1 || got.UnparsedCount > got.Count || len(got.LogIDs) > got.Count-got.UnparsedCount {
			t.Fatalf("inconsistent summary: %+v", got)
		}
	})
}
