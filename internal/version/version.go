// Package version exposes build-time metadata. Values are injected via
// -ldflags '-X github.com/JoshuaMart/websec0/internal/version.<Var>=<value>'.
// See Makefile for the canonical invocation.
package version

// Build-time injectables. Defaults make `go run` ergonomic without ldflags.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// Info aggregates the build metadata for JSON serialization
// (e.g. GET /api/v1/version).
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

// Get returns a snapshot of the current build metadata.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
}
