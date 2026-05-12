// Package version exposes the build-time identifiers (release tag, git
// commit, build date) injected via -ldflags. Defaults reflect a local
// "go run" build with no metadata.
package version

// Build identifiers. Overridden at link time by the Makefile and goreleaser.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String formats the identifiers as a single line suitable for --version.
func String() string {
	return "websec0 " + Version + " (commit " + Commit + ", built " + Date + ")"
}
