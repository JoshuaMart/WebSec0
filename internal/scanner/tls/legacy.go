package tls

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/tls/probes"
)

const legacyCacheKey = "tls.legacy"

// LegacyResult holds the outcome of all legacy-protocol and weak-cipher probes.
// Boolean fields report "server accepts this" — true means a security issue exists.
type LegacyResult struct {
	// Protocol acceptance
	SSL2Supported  bool
	SSL3Supported  bool
	TLS10Supported bool
	TLS11Supported bool
	TLS10Cipher    uint16 // cipher negotiated during TLS 1.0 probe
	TLS11Cipher    uint16

	// Weak cipher acceptance (probed at TLS 1.2 max-version)
	NullAccepted      bool
	NullCipher        uint16
	ExportAccepted    bool
	ExportCipher      uint16
	RC4Accepted       bool
	RC4Cipher         uint16
	DESAccepted       bool
	DESCipher         uint16
	TripleDESAccepted bool
	TripleDESCipher   uint16

	// CBC cipher accepted with TLS 1.0 (BEAST, CVE-2011-3389)
	CBCInTLS10Accepted bool
	CBCTLS10Cipher     uint16

	// DHE key size in bits (0 = not used / probe failed; < 2048 = weak)
	DHKeyBits int
}

// LegacyFetch performs (or memoises) all legacy-protocol and cipher probes
// for the target. Every legacy TLS check calls this.
func LegacyFetch(ctx context.Context, t *checks.Target) (*LegacyResult, error) {
	v, err := t.CacheValue(legacyCacheKey, func() (any, error) {
		return doLegacyFetch(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	res, _ := v.(*LegacyResult)
	if res == nil {
		return nil, errors.New("tls: nil legacy result")
	}
	return res, nil
}

func doLegacyFetch(ctx context.Context, t *checks.Target) *LegacyResult {
	addr := t.DialAddress("443")

	// Each goroutine writes to its own local variable; the main goroutine
	// reads them only after g.Wait() (happens-before relationship).
	var (
		ssl2Status probes.ProtocolStatus
		ssl3Status probes.ProtocolStatus
		tls10      probes.TLSHelloResult
		tls11      probes.TLSHelloResult
		nullR      probes.TLSHelloResult
		exportR    probes.TLSHelloResult
		rc4R       probes.TLSHelloResult
		desR       probes.TLSHelloResult
		tdR        probes.TLSHelloResult // triple-DES
		cbcTLS10R  probes.TLSHelloResult
		dhBits     int
	)

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error { ssl2Status, _ = probes.ProbeSSLv2(gCtx, addr); return nil })
	g.Go(func() error { ssl3Status, _ = probes.ProbeSSLv3(gCtx, addr); return nil })
	g.Go(func() error {
		tls10, _ = probes.ProbeTLSHello(gCtx, addr, 0x0301, nil)
		return nil
	})
	g.Go(func() error {
		tls11, _ = probes.ProbeTLSHello(gCtx, addr, 0x0302, nil)
		return nil
	})
	g.Go(func() error {
		nullR, _ = probes.ProbeTLSHello(gCtx, addr, 0x0303, probes.NullCipherSuites)
		return nil
	})
	g.Go(func() error {
		exportR, _ = probes.ProbeTLSHello(gCtx, addr, 0x0303, probes.ExportCipherSuites)
		return nil
	})
	g.Go(func() error {
		rc4R, _ = probes.ProbeTLSHello(gCtx, addr, 0x0303, probes.RC4CipherSuites)
		return nil
	})
	g.Go(func() error {
		desR, _ = probes.ProbeTLSHello(gCtx, addr, 0x0303, probes.DESCipherSuites)
		return nil
	})
	g.Go(func() error {
		tdR, _ = probes.ProbeTLSHello(gCtx, addr, 0x0303, probes.TripleDESCipherSuites)
		return nil
	})
	g.Go(func() error {
		// CBC in TLS 1.0: probe with CBC ciphers and TLS 1.0 max-version
		cbcTLS10R, _ = probes.ProbeTLSHello(gCtx, addr, 0x0301, probes.CBCCipherSuites)
		return nil
	})
	g.Go(func() error {
		dhBits, _ = probes.ProbeDHKeySize(gCtx, addr)
		return nil
	})

	_ = g.Wait()

	res := &LegacyResult{}
	res.SSL2Supported = ssl2Status == probes.StatusAccepted
	res.SSL3Supported = ssl3Status == probes.StatusAccepted

	if tls10.Accepted && tls10.NegotiatedVersion == 0x0301 {
		res.TLS10Supported = true
		res.TLS10Cipher = tls10.NegotiatedCipher
	}
	if tls11.Accepted && tls11.NegotiatedVersion == 0x0302 {
		res.TLS11Supported = true
		res.TLS11Cipher = tls11.NegotiatedCipher
	}
	if nullR.Accepted {
		res.NullAccepted = true
		res.NullCipher = nullR.NegotiatedCipher
	}
	if exportR.Accepted {
		res.ExportAccepted = true
		res.ExportCipher = exportR.NegotiatedCipher
	}
	if rc4R.Accepted {
		res.RC4Accepted = true
		res.RC4Cipher = rc4R.NegotiatedCipher
	}
	if desR.Accepted {
		res.DESAccepted = true
		res.DESCipher = desR.NegotiatedCipher
	}
	if tdR.Accepted {
		res.TripleDESAccepted = true
		res.TripleDESCipher = tdR.NegotiatedCipher
	}
	if cbcTLS10R.Accepted && cbcTLS10R.NegotiatedVersion == 0x0301 {
		res.CBCInTLS10Accepted = true
		res.CBCTLS10Cipher = cbcTLS10R.NegotiatedCipher
	}
	res.DHKeyBits = dhBits

	return res
}
