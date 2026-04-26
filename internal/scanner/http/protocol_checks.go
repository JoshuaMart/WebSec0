package http

import (
	"context"
	"strings"

	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/scanner/headers"
)

// --- HTTP-HTTP2-MISSING ----------------------------------------------

type http2MissingCheck struct{}

func (http2MissingCheck) ID() string                       { return IDHTTP2Missing }
func (http2MissingCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (http2MissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (http2MissingCheck) Title() string                    { return "HTTP/2 is negotiated" }
func (http2MissingCheck) Description() string {
	return "HTTP/2 (RFC 7540) is the modern baseline. Negotiation is via ALPN `h2`."
}
func (http2MissingCheck) RFCRefs() []string { return []string{"RFC 7540"} }

func (http2MissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := headers.Fetch(ctx, t)
	if err != nil {
		return errFinding(IDHTTP2Missing, checks.FamilyHTTP, checks.SeverityLow, err), nil
	}
	if !res.Reachable {
		return skipped(IDHTTP2Missing, checks.FamilyHTTP, checks.SeverityLow, "homepage unreachable"), nil
	}
	if res.ProtoMajor >= 2 {
		return pass(IDHTTP2Missing, checks.FamilyHTTP, checks.SeverityLow,
			"HTTP/2 (or higher) negotiated",
			map[string]any{"proto": res.ProtoMajor}), nil
	}
	// Fallback: an Alt-Svc with h2 still indicates HTTP/2 capability even
	// if our client happened to fall back to HTTP/1.1.
	if strings.Contains(res.Header("Alt-Svc"), "h2") {
		return pass(IDHTTP2Missing, checks.FamilyHTTP, checks.SeverityLow,
			"HTTP/2 advertised via Alt-Svc", nil), nil
	}
	return fail(IDHTTP2Missing, checks.FamilyHTTP, checks.SeverityLow,
		"HTTP/2 not negotiated and not advertised",
		"Enable HTTP/2 at your reverse proxy or CDN.",
		map[string]any{"proto": res.ProtoMajor}), nil
}

// --- HTTP-HTTP3-MISSING ----------------------------------------------

type http3MissingCheck struct{}

func (http3MissingCheck) ID() string                       { return IDHTTP3Missing }
func (http3MissingCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (http3MissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (http3MissingCheck) Title() string                    { return "HTTP/3 advertised via Alt-Svc" }
func (http3MissingCheck) Description() string {
	return "HTTP/3 (RFC 9114) over QUIC reduces latency on lossy mobile networks; servers advertise via `Alt-Svc: h3=…`."
}
func (http3MissingCheck) RFCRefs() []string { return []string{"RFC 9114"} }

func (http3MissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := headers.Fetch(ctx, t)
	if err != nil {
		return errFinding(IDHTTP3Missing, checks.FamilyHTTP, checks.SeverityInfo, err), nil
	}
	if !res.Reachable {
		return skipped(IDHTTP3Missing, checks.FamilyHTTP, checks.SeverityInfo, "homepage unreachable"), nil
	}
	alt := res.Header("Alt-Svc")
	if strings.Contains(alt, "h3") {
		return pass(IDHTTP3Missing, checks.FamilyHTTP, checks.SeverityInfo,
			"HTTP/3 advertised via Alt-Svc",
			map[string]any{"alt_svc": alt}), nil
	}
	return fail(IDHTTP3Missing, checks.FamilyHTTP, checks.SeverityInfo,
		"HTTP/3 not advertised",
		"Add `Alt-Svc: h3=\":443\"; ma=86400` and enable QUIC on the edge.", nil), nil
}

// --- HTTP-COMPRESSION-NONE -------------------------------------------

type compressionCheck struct{}

func (compressionCheck) ID() string                       { return IDCompressionNone }
func (compressionCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (compressionCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (compressionCheck) Title() string                    { return "Responses are compressed" }
func (compressionCheck) Description() string {
	return "Compression (gzip/br/zstd) reduces bandwidth and improves perceived performance."
}
func (compressionCheck) RFCRefs() []string { return []string{"RFC 9110 §8.4"} }

func (compressionCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := headers.Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCompressionNone, checks.FamilyHTTP, checks.SeverityInfo, err), nil
	}
	if !res.Reachable {
		return skipped(IDCompressionNone, checks.FamilyHTTP, checks.SeverityInfo, "homepage unreachable"), nil
	}
	enc := strings.ToLower(res.Header("Content-Encoding"))
	for _, ok := range []string{"gzip", "br", "zstd", "deflate"} {
		if strings.Contains(enc, ok) {
			return pass(IDCompressionNone, checks.FamilyHTTP, checks.SeverityInfo,
				"response compressed",
				map[string]any{"encoding": enc}), nil
		}
	}
	return fail(IDCompressionNone, checks.FamilyHTTP, checks.SeverityInfo,
		"no Content-Encoding compression",
		"Enable gzip / brotli at the edge.", nil), nil
}
