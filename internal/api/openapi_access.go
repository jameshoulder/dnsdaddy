package api

import (
	"bytes"
	_ "embed"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed openapi-access.yaml
var accessOpenAPISchema []byte

// Extend only the live endpoint, not Overview.live, whose wire type remains
// anonymous. Merge decoded schema maps rather than replacing prose or adding
// duplicate path keys. No remote reference or network request is involved.
func withAccessActivitySchema(base []byte) []byte {
	var doc, extra map[string]any
	if err := yaml.Unmarshal(base, &doc); err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(accessOpenAPISchema, &extra); err != nil {
		panic(err)
	}
	operation := openAPIAccessMap(doc, "paths", "/api/v1/activity/live", "get")
	media := openAPIAccessMap(operation, "responses", "200", "content", "application/json")
	original := openAPIAccessMap(media, "schema")
	if ref, ok := original["$ref"].(string); ok {
		const prefix = "#/components/schemas/"
		if !strings.HasPrefix(ref, prefix) {
			panic("api: live activity schema must use a local reference")
		}
		original = openAPIAccessMap(doc, "components", "schemas", strings.TrimPrefix(ref, prefix))
	}
	schema := copyAccessMap(original)
	properties := copyAccessMap(openAPIAccessMap(original, "properties"))
	for key, value := range openAPIAccessMap(extra, "properties") {
		properties[key] = value
	}
	schema["properties"] = properties
	required, _ := original["required"].([]any)
	schema["required"] = append(append([]any{}, required...), "clientAccess")
	media["schema"] = schema
	operation["summary"] = "Immediate DNS activity and bounded client-access diagnostics"
	operation["description"] = "Reads anonymous handler counters and privacy-gated, bounded refusal-source diagnostics. Normal session/token authentication still uses the store. No DNS probes, query persistence or client grants occur. Source addresses are observations, not authenticated device identities. Counters exclude wire parsing and DoH authentication failures before the DNS handler. Responses use Cache-Control: no-store; completion does not prove remote delivery."
	// Keep the version header first for existing consumers which recognise
	// the served document by its opening line. Map serialization sorts keys
	// and otherwise moves components ahead of openapi. Move the node pair,
	// rather than rewriting a string or dropping any part of the document.
	var node yaml.Node
	if err := node.Encode(doc); err != nil {
		panic(err)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "openapi" {
			key, value := node.Content[i], node.Content[i+1]
			copy(node.Content[2:i+2], node.Content[:i])
			node.Content[0], node.Content[1] = key, value
			break
		}
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&node); err != nil {
		panic(err)
	}
	if err := encoder.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

func openAPIAccessMap(root map[string]any, path ...string) map[string]any {
	for _, key := range path {
		next, ok := root[key].(map[string]any)
		if !ok {
			panic("api: missing OpenAPI mapping " + key)
		}
		root = next
	}
	return root
}

func copyAccessMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
