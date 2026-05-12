// Package scanner is the scan orchestrator. It wires the safehttp gate,
// the probes (tls, sslv2, sslv3, headers, custom) and the scoring engine
// together, fans them out under the configured scan budget, assembles a
// scan.Result and stores it in the cache.
//
// The orchestrator deliberately lives outside internal/scan to avoid an
// import cycle: probes return scan.* types, scan must not import probes.
package scanner

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/JoshuaMart/websec0/internal/cache"
	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/custom"
	"github.com/JoshuaMart/websec0/internal/headers"
	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
	"github.com/JoshuaMart/websec0/internal/scoring"
	"github.com/JoshuaMart/websec0/internal/sslv2"
	"github.com/JoshuaMart/websec0/internal/sslv3"
	tlsprobe "github.com/JoshuaMart/websec0/internal/tls"
)

// rawProbeTimeout is the per-attempt budget for the SSLv2/SSLv3 raw probes.
const rawProbeTimeout = 5 * time.Second

// Scanner is the top-level scan engine.
type Scanner struct {
	cfg      *config.Config
	cache    *cache.Cache[*scan.Result]
	resolver *safehttp.Resolver
}

// New returns a Scanner wired with the given config. The cache is sized
// from cfg.Cache, the resolver uses cfg.Security.
func New(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:   cfg,
		cache: cache.New[*scan.Result](cfg.Cache.MaxEntries, cfg.Cache.TTL.Std()),
		resolver: &safehttp.Resolver{
			Policy: safehttp.Policy{
				AllowPrivate: cfg.Security.AllowPrivateTargets,
				Extra:        cfg.Security.ExtraBlockedCIDRs,
			},
		},
	}
}

// Request is the input shape accepted by Run, mirroring SPEC §6.1.
type Request struct {
	Host          string
	Port          int // 0 → default 443
	ListInHistory bool
	Fresh         bool
}

// ErrEmptyHost is returned when Request.Host is empty.
var ErrEmptyHost = errors.New("scanner: host is required")

// Run executes a full scan: input validation → DNS lookup + IP pinning →
// parallel probes under the scan budget → scoring → cache. The returned
// Result has its ID set even on partial probe failures.
func (s *Scanner) Run(ctx context.Context, req Request) (*scan.Result, error) {
	if req.Host == "" {
		return nil, ErrEmptyHost
	}

	policy := safehttp.InputPolicy{
		AllowedSchemes:   s.cfg.Security.AllowedSchemes,
		AllowCustomPorts: s.cfg.Security.AllowCustomPorts,
		DefaultPort:      443,
	}
	if req.Port > 0 {
		policy.DefaultPort = req.Port
	}

	v, err := safehttp.ValidateInput(req.Host, policy)
	if err != nil {
		return nil, err
	}

	target, err := s.resolver.Resolve(ctx, v)
	if err != nil {
		return nil, err
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.cfg.Scan.Timeout.Std())
	defer cancel()

	start := time.Now()
	result := s.runProbes(scanCtx, target)
	result.ID = cache.NewID(target.Host, time.Now())
	result.Host = target.Host
	result.Port = target.Port
	result.ResolvedIP = target.IP.String()
	result.ScannedAt = start
	result.DurationMs = time.Since(start).Milliseconds()

	s.cache.Put(result.ID, result)
	return result, nil
}

// Get retrieves a previously-completed scan by its ID. Returns (nil, false)
// if the ID is unknown or has expired.
func (s *Scanner) Get(id string) (*scan.Result, bool) {
	return s.cache.Get(id)
}

// runProbes fans out the probes against a resolved Target. Each probe runs
// in its own goroutine and writes to a dedicated local — there is no
// concurrent write to a shared struct. The scoring step happens after the
// wait, when all observations are merged.
func (s *Scanner) runProbes(ctx context.Context, target *safehttp.Target) *scan.Result {
	var (
		tlsReport     *scan.TLSReport
		ssl2Offered   bool
		ssl3Offered   bool
		headersReport *scan.HeadersReport
		customFinds   []scan.CustomFinding
	)

	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		tlsReport = tlsprobe.Probe(ctx, target)
	}()
	go func() {
		defer wg.Done()
		ssl2Offered = sslv2.Probe(ctx, target, rawProbeTimeout)
	}()
	go func() {
		defer wg.Done()
		ssl3Offered = sslv3.Probe(ctx, target, rawProbeTimeout)
	}()
	go func() {
		defer wg.Done()
		r, err := headers.Probe(ctx, target)
		if err == nil {
			headersReport = r
		}
	}()
	go func() {
		defer wg.Done()
		customFinds = custom.RunAll(ctx, target)
	}()
	wg.Wait()

	// Merge SSLv2/v3 results into the TLS protocols list so consumers see
	// one consolidated protocol matrix.
	if tlsReport != nil {
		tlsReport.Protocols = append(tlsReport.Protocols,
			scan.ProtocolSupport{Name: "SSL 3.0", Offered: ssl3Offered, Probe: scan.ProbeRawClientHello},
			scan.ProtocolSupport{Name: "SSL 2.0", Offered: ssl2Offered, Probe: scan.ProbeRawClientHello},
		)
	}

	// Score after observations are complete. Headers first because TLS A+
	// reads the parsed HSTS to gate the bonus.
	if headersReport != nil {
		headersReport.Score, headersReport.Grade = scoring.HeadersFinal(headersReport)
	}
	if tlsReport != nil {
		tlsReport.Scores, tlsReport.Grade = scoring.TLSFinal(tlsReport, headersReport)
	}

	return &scan.Result{
		TLS:     tlsReport,
		Headers: headersReport,
		Custom:  customFinds,
	}
}

// hostWithPort is a small helper kept here in case future callers need to
// stringify a target — left exported via Result.Host + Result.Port today.
// Marked _ so the compiler keeps it documented even if unused.
var _ = func(host string, port int) string {
	if port == 0 || port == 443 {
		return host
	}
	return host + ":" + strconv.Itoa(port)
}
