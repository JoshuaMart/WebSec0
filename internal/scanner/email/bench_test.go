package email

import "testing"

// Benchmarks for the SPF parser. ParseSPF is on the hot path of every
// email-family scan and recursively chases include/redirect mechanisms
// (in the live runner the recursion is bounded by the RFC 7208 lookup
// limit; the parser itself stays single-record).
//
// Run:
//
//	go test -run NONE -bench BenchmarkParseSPF -benchmem ./internal/scanner/email/

// BenchmarkParseSPF_Minimal — the cheapest valid record.
func BenchmarkParseSPF_Minimal(b *testing.B) {
	const record = "v=spf1 -all"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSPF(record)
	}
}

// BenchmarkParseSPF_Typical models a record from a SaaS sender:
// vendor includes (SendGrid, Mailgun) plus the company's own MX/A
// mechanisms and a strict -all.
func BenchmarkParseSPF_Typical(b *testing.B) {
	const record = "v=spf1 mx a:mail.example.com " +
		"include:_spf.google.com " +
		"include:sendgrid.net " +
		"include:mailgun.org " +
		"include:_spf.intuit.com " +
		"ip4:192.0.2.0/24 ip4:198.51.100.0/24 " +
		"ip6:2001:db8::/32 " +
		"-all"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSPF(record)
	}
}

// BenchmarkParseSPF_Heavy stress-tests with many ip4 entries — common
// pattern when a sender publishes their full IP allocation directly
// rather than via includes.
func BenchmarkParseSPF_Heavy(b *testing.B) {
	record := buildHeavySPF(50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSPF(record)
	}
}

func buildHeavySPF(blocks int) string {
	out := make([]byte, 0, 16+blocks*22)
	out = append(out, "v=spf1"...)
	for i := 0; i < blocks; i++ {
		// 192.0.2.0/24, 192.0.3.0/24, … keep IPs in TEST-NET-1 (RFC 5737)
		out = append(out, ' ')
		out = append(out, "ip4:192.0."...)
		out = append(out, byte('0'+(i/100)%10), byte('0'+(i/10)%10), byte('0'+i%10))
		out = append(out, ".0/24"...)
	}
	out = append(out, " -all"...)
	return string(out)
}
