package scoring

import "github.com/JoshuaMart/websec0/internal/scan"

// protocolWeight maps each supported protocol to its score. The scale is
// WebSec0's own: SSL Labs scores TLS 1.0, 1.1 and 1.2 at 90, 95 and 100,
// while WebSec0 keeps TLS 1.3 above TLS 1.2 and scores the deprecated
// versions lower. Only the (best + worst) / 2 rule follows SSL Labs.
var protocolWeight = map[string]int{
	"SSL 2.0": 0,
	"SSL 3.0": 20,
	"TLS 1.0": 70,
	"TLS 1.1": 80,
	"TLS 1.2": 95,
	"TLS 1.3": 100,
}

// ProtocolSupportScore is (best + worst) / 2 across the protocols the
// server actually offers, as in the SSL Labs rating guide.
func ProtocolSupportScore(t *scan.TLSReport) int {
	if len(t.Protocols) == 0 {
		return 0
	}
	offered := make([]int, 0, len(t.Protocols))
	for _, p := range t.Protocols {
		if !p.Offered {
			continue
		}
		if s, ok := protocolWeight[p.Name]; ok {
			offered = append(offered, s)
		}
	}
	if len(offered) == 0 {
		return 0
	}
	minV, maxV := offered[0], offered[0]
	for _, s := range offered {
		if s < minV {
			minV = s
		}
		if s > maxV {
			maxV = s
		}
	}
	return (minV + maxV) / 2
}
