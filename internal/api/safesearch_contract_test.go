package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// `safeSearch` is the one field in the API that is accepted, stored and
// returned without anything acting on it. That is a genuine hazard: a client
// reading only the specification would reasonably conclude that setting it
// turns safe search on, and would then believe a control is in place that is
// not.
//
// The decision was to keep the field rather than delete it — the REST API
// promises fields are never removed within v1, and the database column is part
// of the "downgrade is a binary swap" guarantee — and to make the no-op status
// impossible to miss instead. These tests pin that: the prose is a contract,
// not a comment, and removing it should fail the build rather than quietly ship
// a field that lies about itself.
//
// If enforcement is ever implemented, this file is what tells you the
// documentation has to change with it.
func TestSafeSearchIsMarkedNotEnforcedInTheSpec(t *testing.T) {
	h := newHarness(t)

	resp, raw := h.do("GET", "/openapi.yaml", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /openapi.yaml = %d", resp.StatusCode)
	}
	spec := string(raw)

	// Both schemas carry the field: one is what a client reads back, the other
	// is what it writes. A disclaimer on only one of them still leaves the
	// other looking functional.
	for _, schema := range []string{"Policy:", "PolicyInput:"} {
		body, ok := schemaSection(spec, schema)
		if !ok {
			t.Fatalf("schema %s not found in the served specification", schema)
		}
		field, ok := fieldSection(body, "safeSearch")
		if !ok {
			t.Fatalf("%s does not declare safeSearch", schema)
		}
		if !strings.Contains(field, "deprecated: true") {
			t.Errorf("%s.safeSearch is not marked deprecated; a generated client "+
				"will present it as a working control", schema)
		}
		if !strings.Contains(strings.ToLower(field), "not enforced") {
			t.Errorf("%s.safeSearch does not say it is not enforced:\n%s", schema, field)
		}
	}
}

// The other half of the contract: the value really is stored and returned
// unchanged. An operator who set it before this decision must not find it
// silently reset, and a client that round-trips a policy must not lose it.
func TestSafeSearchRoundTripsEvenThoughItDoesNothing(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("POST", "/api/v1/policies", map[string]any{
		"name":       "safe-search-policy",
		"safeSearch": true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/policies = %d: %s", resp.StatusCode, raw)
	}

	var created struct {
		ID         string `json:"id"`
		SafeSearch bool   `json:"safeSearch"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode created policy: %v", err)
	}
	if !created.SafeSearch {
		t.Error("safeSearch was not stored; the field is a no-op, but it is not supposed to be silently dropped")
	}

	resp, raw = h.do("GET", "/api/v1/policies/"+created.ID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET policy = %d: %s", resp.StatusCode, raw)
	}
	var fetched struct {
		SafeSearch bool `json:"safeSearch"`
	}
	if err := json.Unmarshal(raw, &fetched); err != nil {
		t.Fatalf("decode fetched policy: %v", err)
	}
	if !fetched.SafeSearch {
		t.Error("safeSearch did not survive a round trip")
	}
}

// schemaSection returns the body of a named schema under components/schemas.
// The specification is indented consistently, so a section runs until the next
// line at the same indentation.
func schemaSection(spec, header string) (string, bool) {
	return indentedBlock(spec, "    "+header, "    ")
}

// fieldSection returns one property's block from inside a schema body.
func fieldSection(schema, name string) (string, bool) {
	// A field is either "name:" followed by an indented block, or a one-line
	// inline mapping. Both are captured by taking the block at its indent.
	return indentedBlock(schema, "        "+name+":", "        ")
}

func indentedBlock(in, start, indent string) (string, bool) {
	lines := strings.Split(in, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, start) {
			continue
		}
		out := []string{line}
		for _, next := range lines[i+1:] {
			if strings.TrimSpace(next) == "" {
				out = append(out, next)
				continue
			}
			// A line at the same indent or shallower ends the block.
			if !strings.HasPrefix(next, indent+" ") {
				break
			}
			out = append(out, next)
		}
		return strings.Join(out, "\n"), true
	}
	return "", false
}
