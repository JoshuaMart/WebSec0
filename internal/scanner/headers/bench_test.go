package headers

import "testing"

// Benchmarks for the CSP parser. ParseCSP is on the hot path for every
// scan that finds a Content-Security-Policy header — a long, real
// policy can have 30+ source expressions across 10+ directives.
//
// Run:
//
//	go test -run NONE -bench BenchmarkParseCSP -benchmem ./internal/scanner/headers/

// BenchmarkParseCSP_Tiny — the realistic floor (single directive).
func BenchmarkParseCSP_Tiny(b *testing.B) {
	const policy = "default-src 'self'"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseCSP(policy)
	}
}

// BenchmarkParseCSP_Typical mirrors a CSP from a moderately strict
// production site (modern SaaS with Stripe + Sentry + Google Fonts +
// CDN). 10 directives, ~25 source expressions.
func BenchmarkParseCSP_Typical(b *testing.B) {
	const policy = "default-src 'self'; " +
		"script-src 'self' 'nonce-abc123' https://js.stripe.com https://browser.sentry-cdn.com 'strict-dynamic'; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"img-src 'self' data: https://cdn.example.com https://images.unsplash.com; " +
		"font-src 'self' https://fonts.gstatic.com; " +
		"connect-src 'self' https://api.example.com wss://realtime.example.com https://o12345.ingest.sentry.io; " +
		"frame-src https://js.stripe.com https://hooks.stripe.com; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"frame-ancestors 'self'"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseCSP(policy)
	}
}

// BenchmarkParseCSP_Heavy stress-tests the parser with 200 source
// expressions on script-src — pathological but bounded by what some
// CDN-fronted sites ship.
func BenchmarkParseCSP_Heavy(b *testing.B) {
	policy := buildHeavyCSP(200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseCSP(policy)
	}
}

func buildHeavyCSP(sources int) string {
	const prefix = "default-src 'self'; script-src 'self'"
	out := make([]byte, 0, len(prefix)+sources*40)
	out = append(out, prefix...)
	for i := 0; i < sources; i++ {
		out = append(out, ' ')
		out = append(out, "https://cdn"...)
		out = append(out, byte('0'+(i/100)%10), byte('0'+(i/10)%10), byte('0'+i%10))
		out = append(out, ".example.com"...)
	}
	return string(out)
}
