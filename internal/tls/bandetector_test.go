package tls

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// fakeTimeoutErr satisfies net.Error with Timeout()==true so classifyErr
// returns "timeout" without requiring a real syscall.
type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

func TestBanDetector_NoSuccessNoTrip(t *testing.T) {
	bd := newBanDetector()
	// 10 connection-level failures with no prior success → never trip,
	// because we cannot tell a banned target from a target that was never
	// reachable in the first place.
	for range 10 {
		bd.Record(fakeTimeoutErr{})
		bd.Record(context.DeadlineExceeded)
	}
	if bd.Triggered() {
		t.Fatal("banDetector tripped without any prior success")
	}
}

func TestBanDetector_TripsOnTimeout(t *testing.T) {
	bd := newBanDetector()
	bd.Record(nil) // arm
	bd.Record(fakeTimeoutErr{})
	if !bd.Triggered() {
		t.Fatal("banDetector should trip on a single timeout after a prior success")
	}
}

func TestBanDetector_TripsOnContextCancel(t *testing.T) {
	bd := newBanDetector()
	bd.Record(nil)
	bd.Record(context.DeadlineExceeded)
	if !bd.Triggered() {
		t.Fatal("banDetector should trip on ctx_cancel after a prior success")
	}
}

func TestBanDetector_ResetIsNotBan(t *testing.T) {
	// In a healthy run, the server RSTs handshakes for unsupported ciphers
	// — that is NOT a ban (the server is responding, just refusing this
	// suite). 5 resets must not trip the detector.
	bd := newBanDetector()
	bd.Record(nil)
	rstErr := &net.OpError{Op: "read", Err: syscall.ECONNRESET}
	for range 5 {
		bd.Record(rstErr)
	}
	if bd.Triggered() {
		t.Fatal("banDetector tripped on RST errors; only timeouts/ctx_cancel should trip it")
	}
}

func TestBanDetector_TLSAlertIsNotBan(t *testing.T) {
	bd := newBanDetector()
	bd.Record(nil)
	bd.Record(errors.New("tls: handshake failure"))
	if bd.Triggered() {
		t.Fatal("banDetector tripped on a TLS alert; the server replied, not blackholed")
	}
}

func TestBanDetector_StaysTripped(t *testing.T) {
	bd := newBanDetector()
	bd.Record(nil)
	bd.Record(fakeTimeoutErr{})
	// Subsequent successes (improbable in practice) must not un-trip the
	// detector — once we've decided to abort, every remaining decision is
	// already short-circuited.
	bd.Record(nil)
	if !bd.Triggered() {
		t.Fatal("banDetector un-tripped after a late success")
	}
}

func TestClassifyErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "ok"},
		{"deadline", context.DeadlineExceeded, "ctx_cancel"},
		{"canceled", context.Canceled, "ctx_cancel"},
		{"eof", io.EOF, "eof"},
		{"reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, "reset"},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "refused"},
		{"timeout-net", fakeTimeoutErr{}, "timeout"},
		{"alert", errors.New("tls: handshake failure"), "tls_alert"},
		{"other", errors.New("something weird"), "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyErr(c.err); got != c.want {
				t.Errorf("classifyErr(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
	// sanity check that the time package is still importable from this
	// test file even though we don't currently use it — useful guard for
	// the rare run where stdlib churn breaks the timeout helper above.
	_ = time.Now
}
