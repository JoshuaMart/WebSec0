package safehttp

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func mustReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{URL: u}
}

func TestAllowRedirect_SameHostAccepted(t *testing.T) {
	tgt := &Target{Host: "example.com"}
	check := AllowRedirect(tgt, 3)
	req := mustReq(t, "https://example.com/two")
	if err := check(req, []*http.Request{mustReq(t, "https://example.com/one")}); err != nil {
		t.Errorf("same-host redirect should be accepted, got %v", err)
	}
}

func TestAllowRedirect_OffHostRefused(t *testing.T) {
	tgt := &Target{Host: "example.com"}
	check := AllowRedirect(tgt, 3)
	req := mustReq(t, "https://attacker.test/x")
	if err := check(req, nil); !errors.Is(err, ErrOffHostRedirect) {
		t.Errorf("expected ErrOffHostRedirect, got %v", err)
	}
}

func TestAllowRedirect_HopLimitEnforced(t *testing.T) {
	tgt := &Target{Host: "example.com"}
	check := AllowRedirect(tgt, 2)
	via := []*http.Request{
		mustReq(t, "https://example.com/1"),
		mustReq(t, "https://example.com/2"),
	}
	req := mustReq(t, "https://example.com/3")
	if err := check(req, via); !errors.Is(err, ErrTooManyRedirects) {
		t.Errorf("expected ErrTooManyRedirects at maxHops=%d via=%d, got %v", 2, len(via), err)
	}
}

func TestAllowRedirect_HopZeroNeverFollows(t *testing.T) {
	tgt := &Target{Host: "example.com"}
	check := AllowRedirect(tgt, 0)
	req := mustReq(t, "https://example.com/x")
	if err := check(req, nil); err != http.ErrUseLastResponse {
		t.Errorf("expected http.ErrUseLastResponse when maxHops=0, got %v", err)
	}
}

func TestAllowRedirect_HostCaseInsensitive(t *testing.T) {
	tgt := &Target{Host: "example.com"}
	check := AllowRedirect(tgt, 1)
	req := mustReq(t, "https://EXAMPLE.com/x")
	if err := check(req, nil); err != nil {
		t.Errorf("case-only difference should match, got %v", err)
	}
}
