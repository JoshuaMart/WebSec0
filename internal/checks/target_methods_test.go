package checks

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTarget_UA_DefaultsAndCustom(t *testing.T) {
	tgt, _ := NewTarget("example.com", nil)
	if got := tgt.UA(); got != DefaultUserAgent {
		t.Errorf("UA() default = %q, want %q", got, DefaultUserAgent)
	}
	tgt.UserAgent = "custom/1.0"
	if got := tgt.UA(); got != "custom/1.0" {
		t.Errorf("UA() custom = %q", got)
	}
}

func TestTarget_Client_DefaultsAndCustom(t *testing.T) {
	tgt, _ := NewTarget("example.com", nil)
	if got := tgt.Client(); got != http.DefaultClient {
		t.Errorf("Client() default = %p, want http.DefaultClient", got)
	}
	custom := &http.Client{}
	tgt.HTTPClient = custom
	if got := tgt.Client(); got != custom {
		t.Errorf("Client() custom = %p, want %p", got, custom)
	}
}

func TestTarget_FirstPinnedIP(t *testing.T) {
	tgt, _ := NewTarget("example.com", nil)
	if ip := tgt.FirstPinnedIP(); ip != nil {
		t.Errorf("FirstPinnedIP empty = %v, want nil", ip)
	}
	tgt.PinnedIPs = []net.IP{net.ParseIP("198.51.100.1"), net.ParseIP("198.51.100.2")}
	if ip := tgt.FirstPinnedIP(); !ip.Equal(net.ParseIP("198.51.100.1")) {
		t.Errorf("FirstPinnedIP = %v, want 198.51.100.1", ip)
	}
}

func TestTarget_DialAddress(t *testing.T) {
	cases := map[string]struct {
		input  string
		pinned []net.IP
		port   string
		want   string
	}{
		"bare host, no pin":          {"example.com", nil, "443", "example.com:443"},
		"host:port, no pin":          {"example.com:8443", nil, "443", "example.com:8443"},
		"pinned IPv4 overrides port": {"example.com", []net.IP{net.ParseIP("192.0.2.1")}, "443", "192.0.2.1:443"},
		"pinned IPv6 wraps in []":    {"example.com", []net.IP{net.ParseIP("2001:db8::1")}, "443", "[2001:db8::1]:443"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tgt, _ := NewTarget(tc.input, nil)
			tgt.PinnedIPs = tc.pinned
			if got := tgt.DialAddress(tc.port); got != tc.want {
				t.Errorf("DialAddress(%q) = %q, want %q", tc.port, got, tc.want)
			}
		})
	}
}

func TestTarget_CacheValue_FactoryRunsOncePerKey(t *testing.T) {
	tgt, _ := NewTarget("example.com", nil)

	var calls int32
	factory := func() (any, error) {
		atomic.AddInt32(&calls, 1)
		return "v", nil
	}

	// First call → factory runs.
	v, err := tgt.CacheValue("k1", factory)
	if err != nil || v != "v" {
		t.Fatalf("first call: v=%v err=%v", v, err)
	}
	// Second call (same key) → cached, factory does NOT run again.
	if v, err := tgt.CacheValue("k1", factory); err != nil || v != "v" {
		t.Fatalf("second call: v=%v err=%v", v, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("factory called %d times, want 1", got)
	}

	// Different key → factory runs again.
	if _, err := tgt.CacheValue("k2", factory); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("factory after new key called %d times, want 2", got)
	}
}

func TestTarget_CacheValue_PropagatesError(t *testing.T) {
	tgt, _ := NewTarget("example.com", nil)
	want := errors.New("boom")
	factory := func() (any, error) { return nil, want }

	if _, err := tgt.CacheValue("err", factory); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
	// Errored entries are also cached so we don't retry hot paths.
	called := 0
	_, _ = tgt.CacheValue("err", func() (any, error) {
		called++
		return nil, nil
	})
	if called != 0 {
		t.Errorf("factory re-ran on cached error: called=%d", called)
	}
}

func TestTarget_CacheValue_ConcurrentSingleflight(t *testing.T) {
	tgt, _ := NewTarget("example.com", nil)
	var calls int32
	start := make(chan struct{})
	factory := func() (any, error) {
		atomic.AddInt32(&calls, 1)
		<-start // block to keep concurrent callers in flight
		return "v", nil
	}

	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _ = tgt.CacheValue("once", factory)
		}()
	}
	// Give goroutines a moment to enter CacheValue and join the singleflight.
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("factory called %d times under concurrency, want 1 (singleflight broken)", got)
	}
}
