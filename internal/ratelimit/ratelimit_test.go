package ratelimit

import (
	"testing"
	"time"
)

func TestIPLimiterEnforcesBudget(t *testing.T) {
	t.Parallel()
	l := NewIPLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("203.0.113.5") {
			t.Errorf("request %d denied, want allowed", i+1)
		}
	}
	if l.Allow("203.0.113.5") {
		t.Error("4th request allowed, want denied (burst exhausted)")
	}
}

func TestIPLimiterIsolatesPerIP(t *testing.T) {
	t.Parallel()
	l := NewIPLimiter(1, time.Minute)
	if !l.Allow("1.1.1.1") {
		t.Error("first IP denied")
	}
	if !l.Allow("2.2.2.2") {
		t.Error("second IP denied (cross-IP leak?)")
	}
}

func TestTargetTrackerCooldown(t *testing.T) {
	t.Parallel()
	tr := NewTargetTracker(time.Minute, time.Hour, 10, time.Minute)
	first := tr.PreScan("1.1.1.1", "example.com", false)
	if first.CooldownLeft != 0 || first.CachedScanID != "" {
		t.Errorf("first PreScan = %+v", first)
	}
	tr.Record("example.com", "scan-1")
	second := tr.PreScan("2.2.2.2", "example.com", false)
	if second.CachedScanID != "scan-1" {
		t.Errorf("second PreScan should hit cache, got %+v", second)
	}
}

func TestTargetTrackerRefreshBypassesCache(t *testing.T) {
	t.Parallel()
	tr := NewTargetTracker(time.Minute, time.Hour, 10, time.Minute)
	_ = tr.PreScan("1.1.1.1", "example.com", false)
	tr.Record("example.com", "scan-1")
	d := tr.PreScan("1.1.1.1", "example.com", true)
	if d.CachedScanID != "" {
		t.Errorf("refresh=true should bypass cache, got %+v", d)
	}
	if d.CooldownLeft <= 0 {
		t.Errorf("expected cooldown to apply on refresh, got %+v", d)
	}
}

func TestTargetTrackerAbusePattern(t *testing.T) {
	t.Parallel()
	tr := NewTargetTracker(time.Hour, time.Hour, 3, time.Minute)
	for i, host := range []string{"a.example", "b.example", "c.example"} {
		d := tr.PreScan("9.9.9.9", host, false)
		if d.AbuseFlagged {
			t.Errorf("host %d (%s) flagged early", i, host)
		}
	}
	d := tr.PreScan("9.9.9.9", "d.example", false)
	if !d.AbuseFlagged {
		t.Error("4th distinct host should trigger abuse flag")
	}
}
