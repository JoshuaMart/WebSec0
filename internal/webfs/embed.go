// Package webfs embeds the compiled Astro frontend (web/dist/).
// Run "make web" before building the Go binary to populate dist/.
package webfs

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var static embed.FS

// FS returns a sub-filesystem rooted at dist/, suitable for http.FileServerFS.
func FS() (fs.FS, error) {
	return fs.Sub(static, "dist")
}
