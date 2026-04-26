// Package spec embeds api/openapi.yaml at build time and exposes both the
// raw YAML bytes and a parsed JSON tree for serving on
// GET /api/v1/openapi.json.
package spec

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/go-faster/jx"
	"gopkg.in/yaml.v3"
)

// YAML is the raw OpenAPI document, embedded from api/openapi.yaml.
//
//go:embed openapi.yaml
var YAML []byte

var (
	jsonOnce   sync.Once
	jsonBytes  []byte
	jsonLoaded map[string]jx.Raw
	jsonErr    error
)

// JSON returns the OpenAPI document re-encoded as JSON. The result is
// memoised; callers may share the byte slice freely.
func JSON() ([]byte, error) {
	jsonOnce.Do(loadJSON)
	return jsonBytes, jsonErr
}

// AsRawMap returns the OpenAPI document as a map[string]jx.Raw, ready to
// be returned from the ogen-generated GetOpenAPIOK handler.
func AsRawMap() (map[string]jx.Raw, error) {
	jsonOnce.Do(loadJSON)
	return jsonLoaded, jsonErr
}

func loadJSON() {
	var doc map[string]any
	if err := yaml.Unmarshal(YAML, &doc); err != nil {
		jsonErr = fmt.Errorf("spec: parse YAML: %w", err)
		return
	}
	doc = normalize(doc).(map[string]any)

	b, err := json.Marshal(doc)
	if err != nil {
		jsonErr = fmt.Errorf("spec: marshal JSON: %w", err)
		return
	}
	jsonBytes = b

	m := make(map[string]jx.Raw, len(doc))
	for k, v := range doc {
		raw, err := json.Marshal(v)
		if err != nil {
			jsonErr = fmt.Errorf("spec: marshal field %q: %w", k, err)
			return
		}
		m[k] = raw
	}
	jsonLoaded = m
}

// normalize converts map[interface{}]interface{} (gopkg.in/yaml.v3 default
// for nested maps) to map[string]interface{} so encoding/json accepts it.
func normalize(v any) any {
	switch x := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normalize(vv)
		}
		return out
	case map[string]any:
		for k, vv := range x {
			x[k] = normalize(vv)
		}
		return x
	case []any:
		for i, vv := range x {
			x[i] = normalize(vv)
		}
		return x
	default:
		return v
	}
}
