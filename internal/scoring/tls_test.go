package scoring

import (
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func cert(daysLeft int, keyAlg string) scan.Certificate {
	return scan.Certificate{
		DaysLeft: daysLeft,
		KeyAlg:   keyAlg,
		NotAfter: time.Now().AddDate(0, 0, daysLeft),
	}
}

func strongTLS13() *scan.TLSReport {
	return &scan.TLSReport{
		ChainTrust: scan.ChainTrustTrusted,
		Protocols: []scan.ProtocolSupport{
			{Name: "TLS 1.3", Offered: true},
			{Name: "TLS 1.2", Offered: true},
		},
		Ciphers: []scan.Cipher{
			{Protocol: "TLS 1.3", Name: "TLS_AES_256_GCM_SHA384", Strength: 256, PFS: true, AEAD: true},
		},
		CertificateChain: []scan.Certificate{cert(365, "ECDSA")},
	}
}

func preloadHeaders() *scan.HeadersReport {
	return &scan.HeadersReport{
		Core: map[string]scan.HeaderResult{
			"strict-transport-security": {
				Present: true,
				Value:   "max-age=63072000; includeSubDomains; preload",
			},
		},
	}
}

func TestCertificateScore(t *testing.T) {
	cases := []struct {
		name  string
		chain []scan.Certificate
		want  int
	}{
		{"empty", nil, 0},
		{"ECDSA fresh", []scan.Certificate{cert(365, "ECDSA")}, 100},
		{"RSA fresh", []scan.Certificate{cert(365, "RSA")}, 80},
		{"ECDSA expiring soon", []scan.Certificate{cert(15, "ECDSA")}, 80},
		{"Expired", []scan.Certificate{cert(-5, "ECDSA")}, 0},
		{"Ed25519", []scan.Certificate{cert(365, "Ed25519")}, 100},
	}
	for _, c := range cases {
		r := &scan.TLSReport{CertificateChain: c.chain}
		if got := CertificateScore(r); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestProtocolSupportScore(t *testing.T) {
	cases := []struct {
		name      string
		protocols []scan.ProtocolSupport
		want      int
	}{
		{"none", nil, 0},
		{"TLS 1.3 only", []scan.ProtocolSupport{{Name: "TLS 1.3", Offered: true}}, 100},
		{"TLS 1.2+1.3", []scan.ProtocolSupport{
			{Name: "TLS 1.3", Offered: true},
			{Name: "TLS 1.2", Offered: true},
		}, 97},
		{"TLS 1.0+1.2+1.3 (worst pulls down)", []scan.ProtocolSupport{
			{Name: "TLS 1.3", Offered: true},
			{Name: "TLS 1.2", Offered: true},
			{Name: "TLS 1.0", Offered: true},
		}, 85},
		{"all offered are disabled", []scan.ProtocolSupport{
			{Name: "TLS 1.2", Offered: false},
		}, 0},
	}
	for _, c := range cases {
		r := &scan.TLSReport{Protocols: c.protocols}
		if got := ProtocolSupportScore(r); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestKeyExchangeScore(t *testing.T) {
	if KeyExchangeScore(&scan.TLSReport{}) != 0 {
		t.Error("no ciphers: want 0")
	}
	r := &scan.TLSReport{Ciphers: []scan.Cipher{{PFS: true}}}
	if KeyExchangeScore(r) != 90 {
		t.Errorf("PFS cipher: want 90")
	}
	r = &scan.TLSReport{Ciphers: []scan.Cipher{{PFS: false}}}
	if KeyExchangeScore(r) != 40 {
		t.Errorf("non-PFS cipher: want 40")
	}
}

func TestCipherStrengthScore(t *testing.T) {
	cases := []struct {
		name    string
		ciphers []scan.Cipher
		want    int
	}{
		{"none", nil, 0},
		{"256 only", []scan.Cipher{{Strength: 256}}, 100},
		{"128 only", []scan.Cipher{{Strength: 128}}, 80},
		{"256+128 (worst pulls down)", []scan.Cipher{{Strength: 256}, {Strength: 128}}, 90},
		{"0-bit anon", []scan.Cipher{{Strength: 0}}, 0},
	}
	for _, c := range cases {
		r := &scan.TLSReport{Ciphers: c.ciphers}
		if got := CipherStrengthScore(r); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestTLSFinal_HappyPath_APlusRequiresPreload(t *testing.T) {
	r := strongTLS13()
	scores, gradeNoPreload := TLSFinal(r, nil)
	if gradeNoPreload != scan.GradeA {
		t.Errorf("without HSTS preload: got %s, want A", gradeNoPreload)
	}
	if scores.Final < 95 {
		t.Errorf("Final: got %d, want ≥95 (would map to A+ if preload-eligible)", scores.Final)
	}

	_, gradeWithPreload := TLSFinal(r, preloadHeaders())
	if gradeWithPreload != scan.GradeAPlus {
		t.Errorf("with HSTS preload: got %s, want A+", gradeWithPreload)
	}
}

func TestTLSFinal_FloorSSLv3(t *testing.T) {
	r := strongTLS13()
	r.Protocols = append(r.Protocols, scan.ProtocolSupport{Name: "SSL 3.0", Offered: true})
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeF {
		t.Errorf("SSLv3 offered: got %s, want F", grade)
	}
}

func TestTLSFinal_FloorSSLv2(t *testing.T) {
	r := strongTLS13()
	r.Protocols = append(r.Protocols, scan.ProtocolSupport{Name: "SSL 2.0", Offered: true})
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeF {
		t.Errorf("SSLv2 offered: got %s, want F", grade)
	}
}

func TestTLSFinal_FloorTLS10(t *testing.T) {
	r := strongTLS13()
	r.Protocols = append(r.Protocols, scan.ProtocolSupport{Name: "TLS 1.0", Offered: true})
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeC {
		t.Errorf("TLS 1.0 offered: got %s, want C", grade)
	}
}

func TestTLSFinal_FloorChainUntrusted(t *testing.T) {
	r := strongTLS13()
	r.ChainTrust = scan.ChainTrustUntrusted
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeT {
		t.Errorf("untrusted chain: got %s, want T", grade)
	}
}

func TestTLSFinal_FloorChainExpired(t *testing.T) {
	r := strongTLS13()
	r.ChainTrust = scan.ChainTrustExpired
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeT {
		t.Errorf("expired chain: got %s, want T", grade)
	}
}

func TestTLSFinal_FloorChainSelfSigned(t *testing.T) {
	r := strongTLS13()
	r.ChainTrust = scan.ChainTrustSelfSigned
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeT {
		t.Errorf("self-signed: got %s, want T", grade)
	}
}

func TestTLSFinal_FloorRC4(t *testing.T) {
	r := strongTLS13()
	r.Ciphers = []scan.Cipher{
		{Name: "TLS_RSA_WITH_RC4_128_SHA", Strength: 128, PFS: false},
	}
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeF {
		t.Errorf("RC4: got %s, want F", grade)
	}
}

func TestTLSFinal_Floor3DES(t *testing.T) {
	r := strongTLS13()
	r.Ciphers = []scan.Cipher{
		{Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Strength: 168, PFS: false},
	}
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeC {
		t.Errorf("3DES (also no PFS): got %s, want C (worst of 3DES floor and no-PFS floor)", grade)
	}
}

func TestTLSFinal_FloorNoPFS(t *testing.T) {
	r := strongTLS13()
	r.Ciphers = []scan.Cipher{
		{Name: "TLS_RSA_WITH_AES_256_CBC_SHA", Strength: 256, PFS: false},
	}
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeC {
		t.Errorf("no PFS: got %s, want C", grade)
	}
}

func TestTLSFinal_FloorAnonCipher(t *testing.T) {
	r := strongTLS13()
	r.Ciphers = append(r.Ciphers, scan.Cipher{
		Name: "TLS_DH_anon_WITH_AES_128_CBC_SHA", Strength: 128, PFS: true,
	})
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeF {
		t.Errorf("anonymous cipher: got %s, want F", grade)
	}
}

func TestTLSFinal_FloorExportCipher(t *testing.T) {
	r := strongTLS13()
	r.Ciphers = append(r.Ciphers, scan.Cipher{
		Name: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", Strength: 40,
	})
	_, grade := TLSFinal(r, preloadHeaders())
	if grade != scan.GradeF {
		t.Errorf("export cipher: got %s, want F", grade)
	}
}

func TestHSTSPreloadEligible(t *testing.T) {
	cases := []struct {
		name string
		hdr  *scan.HeadersReport
		want bool
	}{
		{"nil", nil, false},
		{"empty", &scan.HeadersReport{}, false},
		{"absent", &scan.HeadersReport{Core: map[string]scan.HeaderResult{
			"strict-transport-security": {Present: false},
		}}, false},
		{"short max-age", &scan.HeadersReport{Core: map[string]scan.HeaderResult{
			"strict-transport-security": {Present: true, Value: "max-age=3600; includeSubDomains; preload"},
		}}, false},
		{"no preload directive", &scan.HeadersReport{Core: map[string]scan.HeaderResult{
			"strict-transport-security": {Present: true, Value: "max-age=63072000; includeSubDomains"},
		}}, false},
		{"no includeSubDomains", &scan.HeadersReport{Core: map[string]scan.HeaderResult{
			"strict-transport-security": {Present: true, Value: "max-age=63072000; preload"},
		}}, false},
		{"valid", &scan.HeadersReport{Core: map[string]scan.HeaderResult{
			"strict-transport-security": {Present: true, Value: "max-age=63072000; includeSubDomains; preload"},
		}}, true},
	}
	for _, c := range cases {
		if got := hstsPreloadEligible(c.hdr); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
