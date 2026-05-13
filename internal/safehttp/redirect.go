package safehttp

import (
	"net/http"
	"strings"
)

// AllowRedirect is the http.Client CheckRedirect predicate enforced by
// NewClient. It refuses any redirect that leaves target.Host (off-host)
// and caps the redirect chain at maxHops. If maxHops is zero or
// negative, no redirect is followed at all.
func AllowRedirect(target *Target, maxHops int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if maxHops <= 0 {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxHops {
			return ErrTooManyRedirects
		}
		if !strings.EqualFold(req.URL.Hostname(), target.Host) {
			return ErrOffHostRedirect
		}
		return nil
	}
}
