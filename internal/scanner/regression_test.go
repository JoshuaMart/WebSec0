package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/cache"
	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/history"
	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

type localResolver struct {
	target *safehttp.Target
	calls  int
}

func (r *localResolver) Resolve(context.Context, *safehttp.Validated) (*safehttp.Target, error) {
	r.calls++
	return r.target, nil
}

func TestRun_ReusesCacheAndFreshReplacesIt(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	s := New(config.Defaults())
	resolver := &localResolver{target: targetFor(t, srv)}
	s.resolver = resolver
	first, err := s.Run(context.Background(), Request{Host: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.History(0)) != 0 {
		t.Fatal("unlisted scan became public")
	}
	second, err := s.Run(context.Background(), Request{Host: "EXAMPLE.TEST", ListInHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	if first != second || resolver.calls != 1 {
		t.Fatal("cache miss for equivalent host")
	}
	_, err = s.Run(context.Background(), Request{Host: "example.test", ListInHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.History(0)) != 1 {
		t.Fatal("cached report should appear once")
	}
	fresh, err := s.Run(context.Background(), Request{Host: "example.test", Fresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ID == first.ID || resolver.calls != 2 {
		t.Fatal("fresh did not rerun probes")
	}
	latest, err := s.Run(context.Background(), Request{Host: "example.test"})
	if err != nil || latest != fresh || resolver.calls != 2 {
		t.Fatal("new scan did not replace target cache")
	}
	if old, ok := s.Get(first.ID); !ok || old != first {
		t.Fatal("fresh scan removed old report")
	}
	s.cache.Purge()
	_, err = s.Run(context.Background(), Request{Host: "example.test"})
	if err != nil || resolver.calls != 3 {
		t.Fatal("evicted report incorrectly reused")
	}
}

func TestRun_CacheExpiryAndPortIsolation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Security.AllowCustomPorts = true
	s := New(cfg)
	var calls int
	s.resolver = &safehttp.Resolver{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return nil, nil
	}}
	s.cache = cache.New[*scan.Result](1, time.Millisecond)
	s.latest.Put("https://example.test:443", "cached")
	s.cache.Put("cached", &scan.Result{ID: "cached"})
	_, err := s.Run(context.Background(), Request{Host: "example.test", Port: 8443})
	if err == nil || calls != 1 {
		t.Fatal("cache crossed port boundary")
	}
	time.Sleep(10 * time.Millisecond)
	_, err = s.Run(context.Background(), Request{Host: "example.test"})
	if err == nil || calls != 2 {
		t.Fatal("expired report reused")
	}
}

func TestHistory_FiltersMissingReportsBeforeLimitWithoutTouchingLRU(t *testing.T) {
	s := New(config.Defaults())
	s.cache = cache.New[*scan.Result](2, time.Hour)
	s.cache.Put("older", &scan.Result{ID: "older"})
	s.cache.Put("newer", &scan.Result{ID: "newer"})
	for _, id := range []string{"newer", "older", "missing"} {
		s.history.Add(history.Entry{ID: id, ScannedAt: time.Now()})
	}
	got := s.History(1)
	if len(got) != 1 || got[0].ID != "older" {
		t.Fatalf("limit before filtering: %+v", got)
	}
	s.cache.Put("third", &scan.Result{ID: "third"})
	if _, ok := s.Get("older"); ok {
		t.Fatal("listing history changed LRU order")
	}
	s.cache.Purge()
	if len(s.History(0)) != 0 {
		t.Fatal("history links to missing reports")
	}
}

func TestHistory_FiltersExpiredReports(t *testing.T) {
	s := New(config.Defaults())
	s.cache = cache.New[*scan.Result](1, time.Millisecond)
	s.cache.Put("expires", &scan.Result{ID: "expires"})
	s.history.Add(history.Entry{ID: "expires", ScannedAt: time.Now()})
	time.Sleep(10 * time.Millisecond)
	if len(s.History(0)) != 0 {
		t.Fatal("expired report remains visible")
	}
}

func TestRunProbes_SequentialDisablesCustomConcurrency(t *testing.T) {
	var active, peak atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := config.Defaults()
	cfg.Scan.ParallelProbes = false
	s := New(cfg)
	result := s.runProbes(context.Background(), targetFor(t, srv))
	if peak.Load() != 1 {
		t.Fatalf("concurrent HTTP probes: %d", peak.Load())
	}
	if result.Headers == nil || len(result.Custom) != 2 || result.TLS == nil {
		t.Fatal("missing reports")
	}
}

func TestRunProbes_HonorsRedirectConfiguration(t *testing.T) {
	for _, follow := range []bool{false, true} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/final", http.StatusFound)
				return
			}
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}))
		cfg := config.Defaults()
		cfg.Scan.FollowRedirects = follow
		cfg.Scan.MaxRedirects = 1
		s := New(cfg)
		result := s.runProbes(context.Background(), targetFor(t, srv))
		srv.Close()
		if result.Headers == nil || result.Headers.Core["x-content-type-options"].Present != follow {
			t.Fatalf("follow=%v report=%+v", follow, result.Headers)
		}
	}
}

type waitingResolver struct{}

func (waitingResolver) Resolve(ctx context.Context, _ *safehttp.Validated) (*safehttp.Target, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRun_ScanBudgetIncludesResolution(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scan.Timeout = config.Duration(10 * time.Millisecond)
	s := New(cfg)
	s.resolver = waitingResolver{}
	outer, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := s.Run(outer, Request{Host: "example.test"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if outer.Err() != nil {
		t.Fatal("resolution ignored the scan budget")
	}
}
