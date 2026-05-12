package api

import (
	"net/http"

	"github.com/JoshuaMart/websec0/catalog"
)

// checksHandler serves the embedded checks catalog (SPEC §6.3). The bytes
// are loaded once at handler construction; the JSON is byte-for-byte
// identical to catalog/checks.json. Cache-Control allows downstream
// caching since the catalog is immutable per build.
func checksHandler() http.HandlerFunc {
	body := catalog.Raw()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}
}
