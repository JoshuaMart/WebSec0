package tls

// banDetector tracks whether the scanner appears to have been blackholed by
// the target mid-probe. The trigger is conservative: exactly one
// connection-level silent drop (timeout / dial cancellation) observed AFTER
// at least one prior successful handshake.
//
// Why one is enough: some WAFs react to a single legacy ClientHello
// (TLS 1.0/1.1) by IP-banning the caller — every subsequent dial then
// times out at 3s, and burning 3s × N versions × ~150 ciphers on a
// known-dead path adds nothing to the report.
//
// Why TLS alerts and RSTs do not trip the detector: both prove the server
// is still on the wire (it replied, just refusing this particular
// version/cipher). In the same baseline run we saw ~10 "reset" results
// interleaved with "ok" — RST is the legitimate response to an unsupported
// cipher and must not be confused with a ban.
type banDetector struct {
	sawSuccess bool
	tripped    bool
}

func newBanDetector() *banDetector { return &banDetector{} }

// Record observes the outcome of one handshake attempt. A nil err arms the
// detector by setting sawSuccess; a connection-level silent drop after that
// trips it.
func (b *banDetector) Record(err error) {
	if b.tripped {
		return
	}
	if err == nil {
		b.sawSuccess = true
		return
	}
	if !b.sawSuccess {
		return
	}
	switch classifyErr(err) {
	case "timeout", "ctx_cancel":
		b.tripped = true
	}
}

// Triggered reports whether the detector has decided the scanner is banned.
func (b *banDetector) Triggered() bool { return b.tripped }
