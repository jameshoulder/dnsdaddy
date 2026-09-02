package api

import (
	"encoding/json"
	"fmt"
	"strings"
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

	// And nothing described that the code cannot return, which is the same
	// mistake pointing the other way.
	//
	// The comparison is against the fully populated form rather than the zero
	// value: the entitled fields are pointers and omitempty, so marshalling an
	// empty struct yields only the tier every caller sees. Using that as the
	// reference would delete the documentation for the other tier the first
	// time someone ran this.
	rawFull, err := json.Marshal(fullHealthResponse())
	if err != nil {
		t.Fatalf("marshal populated HealthResponse: %v", err)
	}
	var allFields map[string]any
	if err := json.Unmarshal(rawFull, &allFields); err != nil {
		t.Fatalf("unmarshal populated HealthResponse: %v", err)
	}
	for name := range properties {
		if _, ok := allFields[name]; !ok {
			t.Errorf("openapi.yaml describes %q on the health response, which the code does not "+
				"return", name)
		}
	}

	// The public tier is the security-relevant half, so it is pinned by name.
	// A field added to HealthResponse without a pointer would silently join
	// the body every stranger receives, and this is what stops that.
	if len(fields) != 1 {
		t.Errorf("the unauthenticated health body carries %d fields (%v); it must carry only status",
			len(fields), fields)
	}
	if _, ok := fields["status"]; !ok {
		t.Error("the unauthenticated health body does not carry status")
	}
}

// fullHealthResponse is the entitled form: every field populated.
func fullHealthResponse() HealthResponse {
	var (
		ver    = "test"
		uptime = int64(1)
		size   = 1
		prot   = true
		stale  = false
	)
	return HealthResponse{
		Status:         "ok",
		Version:        &ver,
		UptimeSeconds:  &uptime,
		BlocklistSize:  &size,
		Protecting:     &prot,
		ClientACLStale: &stale,
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

// notInTheSpec are the patterns openapi.yaml deliberately does not describe as
// paths, each for a reason that is not "somebody forgot".
//
// The dashboard is not an API. The two mount points are prefixes that exist so
// requireAuth wraps a sub-tree, and have no operation of their own. The DoH
// endpoints are resolver endpoints rather than management ones and are
// described in the specification's prose, where their credential model can be
// explained; putting them in paths would offer them to generated management
// clients that have no business calling them.
var notInTheSpec = map[string]bool{
	"/":             true,
	"/api/v1/":      true,
	"/metrics":      true,
	"/dns-query":    true,
	"/dns-query/":   true,
	"/openapi.yaml": true,
}

// A route the specification does not describe is a route no generated client
// can call and no reader of the documentation knows exists.
//
// This reads the router rather than a list, so a route added tomorrow is
// covered without anybody remembering to add it here — which is the failure
// this replaces. Both halves matter: the path must be described, and so must
// the method, because an endpoint that gains a DELETE nobody documented is
// exactly as invisible as one that was never added.
func TestEveryRouteIsInTheSpecification(t *testing.T) {
	var spec map[string]any
	if err := yaml.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("openapi.yaml has no paths mapping")
	}

	public, managed := routeTable(t)
	all := append(append([]string{}, public...), managed...)
	if len(all) < 40 {
		t.Fatalf("only found %d routes in server.go; the parser is not reading the router", len(all))
	}

	for _, pattern := range all {
		method, path, hasMethod := strings.Cut(pattern, " ")
		if !hasMethod {
			path = pattern
		}
		if notInTheSpec[path] {
			continue
		}

		item, ok := paths[path].(map[string]any)
		if !ok {
			t.Errorf("openapi.yaml does not describe %s, which server.go serves", path)
			continue
		}
		if !hasMethod {
			continue
		}
		if _, ok := item[strings.ToLower(method)]; !ok {
			t.Errorf("openapi.yaml describes %s but not its %s operation", path, method)
		}
	}
}

// A credential must never be readable through this API, and the specification
// is where a client author finds out what to expect. A `secret` property that
// is not marked writeOnly tells every generated client that reading one back
// is a thing it can do — and would be a promise the code is not keeping.
func TestCredentialFieldsInTheSpecAreWriteOnly(t *testing.T) {
	var spec map[string]any
	if err := yaml.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}

	// Names that mean "a credential" in this API. Matched exactly, and
	// deliberately not by substring: secretSet and secretHint describe a stored
	// credential without being one, and must stay readable.
	//
	// APIToken's secret is the single exception in the whole surface and is
	// handled by modelling rather than by an exemption here: it lives in
	// APITokenCreated, which is referenced only by the 201 that returns it
	// once. If it ever reappears on a readable schema, this test fails, which
	// is the point.
	credentialNames := map[string]bool{
		"secret": true, "apikey": true, "api_key": true,
		"password": true, "currentpassword": true, "newpassword": true,
	}

	var checked int
	var walk func(node any, path string)
	walk = func(node any, path string) {
		switch n := node.(type) {
		case map[string]any:
			props, _ := n["properties"].(map[string]any)
			for name, raw := range props {
				if !credentialNames[strings.ToLower(name)] {
					continue
				}
				field, _ := raw.(map[string]any)
				checked++
				if strings.HasSuffix(path, "/APITokenCreated/allOf[1]") {
					// Returned exactly once, at creation, and nowhere else.
					// Named by its schema so the exception cannot silently
					// widen to another one.
					continue
				}
				if field["writeOnly"] != true {
					t.Errorf("%s.%s is a credential and is not marked writeOnly, so generated "+
						"clients will expect to read it back", path, name)
				}
			}
			for k, v := range n {
				walk(v, path+"/"+k)
			}
		case []any:
			for i, v := range n {
				walk(v, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(spec, "")

	if checked == 0 {
		t.Fatal("the walk found no credential fields at all, so it is checking nothing")
	}
}
