package api

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

// The spec is served to clients, so a field the code returns and the spec does
// not describe is a field generated clients will not have.
//
// This exists because a hand-edit put `clientAclStale` one level too shallow —
// a sibling of `content` under the 200 response rather than a property of the
// schema. The document still parsed as YAML, so checking that it parsed proved
// nothing: it was structurally wrong in exactly the way that makes a field
// vanish from generated clients and rendered documentation, and silently.
func TestHealthResponseMatchesTheSpec(t *testing.T) {
	var spec map[string]any
	if err := yaml.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}

	properties := specHealthProperties(t, spec)

	// Every key the Go type marshals must be described.
	raw, err := json.Marshal(HealthResponse{})
	if err != nil {
		t.Fatalf("marshal HealthResponse: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal HealthResponse: %v", err)
	}

	for name := range fields {
		if _, ok := properties[name]; !ok {
			t.Errorf("HealthResponse returns %q, which openapi.yaml does not describe under the "+
				"health 200 schema — generated clients would not have it", name)
		}
	}
	// And nothing described that the code does not return, which is the same
	// mistake pointing the other way.
	for name := range properties {
		if _, ok := fields[name]; !ok {
			t.Errorf("openapi.yaml describes %q on the health response, which the code does not "+
				"return", name)
		}
	}
}

// specHealthProperties walks to the health 200 schema, failing with the path it
// got stuck on rather than panicking on a type assertion.
func specHealthProperties(t *testing.T, spec map[string]any) map[string]any {
	t.Helper()

	node := any(spec)
	for _, step := range []string{
		"paths", "/api/v1/health", "get", "responses", "200",
		"content", "application/json", "schema", "properties",
	} {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("openapi.yaml: expected a mapping before %q", step)
		}
		node, ok = m[step]
		if !ok {
			t.Fatalf("openapi.yaml: no %q where the health response schema should be — the most "+
				"likely cause is an indentation slip putting a field outside the schema", step)
		}
	}

	props, ok := node.(map[string]any)
	if !ok {
		t.Fatal("openapi.yaml: the health schema's properties is not a mapping")
	}
	return props
}

// A response map may only contain status codes. A field indented to this level
// is the specific mistake above, and it is invisible to a YAML parse.
func TestResponseMapsContainOnlyStatusCodes(t *testing.T) {
	var spec map[string]any
	if err := yaml.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}

	paths, _ := spec["paths"].(map[string]any)
	for path, item := range paths {
		operations, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for method, op := range operations {
			operation, ok := op.(map[string]any)
			if !ok {
				continue
			}
			responses, ok := operation["responses"].(map[string]any)
			if !ok {
				continue
			}
			for code := range responses {
				if len(code) != 3 || code < "100" || code > "599" {
					t.Errorf("%s %s: response map contains %q, which is not a status code — a "+
						"field indented one level too shallow lands here and disappears from "+
						"generated clients", method, path, code)
				}
			}
		}
	}
}
