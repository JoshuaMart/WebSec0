package tls

import (
	"testing"
	"time"
)

func TestParseHSTS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in         string
		ok         bool
		maxAge     time.Duration
		includeSub bool
		preload    bool
	}{
		{`max-age=31536000`, true, 365 * 24 * time.Hour, false, false},
		{`max-age=63072000; includeSubDomains; preload`, true, 730 * 24 * time.Hour, true, true},
		{` Max-Age = "300" ; IncludeSubDomains `, true, 5 * time.Minute, true, false},
		{`includeSubDomains`, false, 0, false, false}, // missing required max-age
		{``, false, 0, false, false},
		{`max-age=-10`, false, 0, false, false},
	}
	for _, c := range cases {
		got, ok := ParseHSTS(c.in)
		if ok != c.ok {
			t.Errorf("ParseHSTS(%q).ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.MaxAge != c.maxAge || got.IncludeSubDomains != c.includeSub || got.Preload != c.preload {
			t.Errorf("ParseHSTS(%q) = %+v, want max-age=%v include=%v preload=%v",
				c.in, got, c.maxAge, c.includeSub, c.preload)
		}
	}
}
