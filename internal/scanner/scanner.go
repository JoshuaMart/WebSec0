// Package scanner is the scan orchestrator. It wires the safehttp gate,
// the probes (tls, sslv2, sslv3, headers, custom) and the scoring engine
// together, fans them out under the configured scan budget, assembles a
// scan.Result and stores it in the cache.
// The orchestrator deliberately lives outside internal/scan to avoid an
// import cycle: probes return scan.* types, scan must not import probes.
package scanner

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JoshuaMart/websec0/internal/cache"
	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/custom"
	"github.com/JoshuaMart/websec0/internal/headers"
	"github.com/JoshuaMart/websec0/internal/history"
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
	history  *history.History
	resolver *safehttp.Resolver
}

// New returns a Scanner wired with the given config. The cache is sized
// from cfg.Cache, the resolver uses cfg.Security, and a history is created
// when cfg.History.Enabled.
func New(cfg *config.Config) *Scanner {
	var hist *history.History
	if cfg.History.Enabled {
		hist = history.New(cfg.History.Retention.Std())
	}
	return &Scanner{
		cfg:     cfg,
		cache:   cache.New[*scan.Result](cfg.Cache.MaxEntries, cfg.Cache.TTL.Std()),
		history: hist,
		resolver: &safehttp.Resolver{
			Policy: safehttp.Policy{
				AllowPrivate: cfg.Security.AllowPrivateTargets,
				Extra:        cfg.Security.ExtraBlockedCIDRs,
			},
		},
	}
}

// Request is the input shape accepted by Run, mirroring the JSON body
// of POST /api/v1/scan.
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
	if req.ListInHistory && s.history != nil {
		s.history.Add(summarise(result))
	}
	return result, nil
}

// Get retrieves a previously-completed scan by its ID. Returns (nil, false)
// if the ID is unknown or has expired.
func (s *Scanner) Get(id string) (*scan.Result, bool) {
	return s.cache.Get(id)
}

// History returns up to limit recent opt-in scan summaries. When the
// history feature is disabled (cfg.History.Enabled = false), the returned
// slice is empty.
func (s *Scanner) History(limit int) []history.Entry {
	if s.history == nil {
		return nil
	}
	return s.history.List(limit)
}

func summarise(r *scan.Result) history.Entry {
	e := history.Entry{
		ID:        r.ID,
		Host:      r.Host,
		ScannedAt: r.ScannedAt,
	}
	if r.TLS != nil {
		e.TLSGrade = r.TLS.Grade
		e.HighestTLS = highestOfferedProtocol(r.TLS.Protocols)
	}
	if r.Headers != nil {
		e.HeaderGrade = r.Headers.Grade
	}
	return e
}

// protocolPriority orders protocols from most to least desirable so the
// best offered one can be picked for the landing-strip subtitle.
var protocolPriority = []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"}

func highestOfferedProtocol(protocols []scan.ProtocolSupport) string {
	offered := map[string]bool{}
	for _, p := range protocols {
		if p.Offered {
			offered[p.Name] = true
		}
	}
	for _, name := range protocolPriority {
		if offered[name] {
			return name
		}
	}
	return ""
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
		r, redirect, err := headers.Probe(ctx, target)
		if err != nil {
			return
		}
		headersReport = r
		// If the target redirected to a www-sibling (apex/www toggle), the
		// real headers live there. Re-resolve through the same SSRF policy
		// and re-probe; replace the partial report on success. Strictly
		// off-host redirects (different registrable host) still surface
		// whatever the 3xx already exposed (HSTS, Server, …) — no retry.
		if redirect == "" {
			return
		}
		u, perr := url.Parse(redirect)
		if perr != nil || !wwwSibling(target.Host, u.Hostname()) {
			return
		}
		sibling, rerr := s.resolver.Resolve(ctx, &safehttp.Validated{
			Scheme: target.Scheme, Host: strings.ToLower(u.Hostname()), Port: target.Port,
		})
		if rerr != nil {
			return
		}
		r2, _, perr := headers.Probe(ctx, sibling)
		if perr != nil || r2 == nil {
			return
		}
		r2.ProbedHost = sibling.Host
		headersReport = r2
	}()
	go func() {
		defer wg.Done()
		customFinds = custom.RunAll(ctx, target)
	}()
	wg.Wait()

	// Merge SSLv2/v3 results into the TLS protocols list so consumers see
	// one consolidated protocol matrix.
	if tlsReport != nil {
		tlsReport.Protocols = append(
			tlsReport.Protocols,
			scan.ProtocolSupport{Name: "SSL 3.0", Offered: ssl3Offered, Probe: scan.ProbeRawClientHello},
			scan.ProtocolSupport{Name: "SSL 2.0", Offered: ssl2Offered, Probe: scan.ProbeRawClientHello},
		)
		// Weakness derivation is owned by the tls package but called here
		// because it joins observations from two probes: protocols+ciphers
		// from tls.Probe and the HTTP Server header from headers.Probe
		// (needed to fingerprint Heartbleed and Ticketbleed). The orchestrator
		// is the only layer that has both reports in scope.
		var serverHeader string
		if headersReport != nil && headersReport.Additional.Server != nil {
			serverHeader = headersReport.Additional.Server.Value
		}
		tlsReport.Vulnerabilities = tlsprobe.DeriveWeaknesses(tlsprobe.WeaknessInput{
			Protocols:    tlsReport.Protocols,
			Ciphers:      tlsReport.Ciphers,
			ServerHeader: serverHeader,
		})
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

// wwwSibling returns true when a and b differ only by the leading "www."
// label — cloudflare.com ↔ www.cloudflare.com. This is intentionally narrow
// (no public-suffix awareness) so the orchestrator only retries the dominant
// apex/www toggle case, not arbitrary same-eTLD+1 hosts.
func wwwSibling(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" || a == b {
		return false
	}
	return b == "www."+a || a == "www."+b
}
