package safehttp

import (
	"context"
	"net"
	"strings"
)

// TXTLookupFunc returns complete TXT records (DNS character-strings joined).
// Tests inject this function to avoid contacting external DNS servers.
type TXTLookupFunc func(context.Context, string) ([]string, error)

// LookupTXT queries the configured system resolver, never a nameserver supplied
// by the scanned host. The absolute name prevents local search-suffix expansion.
func LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, strings.TrimSuffix(name, ".")+".")
}
