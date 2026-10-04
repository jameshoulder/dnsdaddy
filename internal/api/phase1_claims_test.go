package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
	"gopkg.in/yaml.v3"
)

const phase1DefaultFact = "Fresh installations without an explicit resolver-mode override start in Forward (off); upgrades preserve saved mode choices, and explicit configuration takes precedence."

// The prose must follow an actual fresh database, not another prose constant.
// Existing startup/control tests cover saved choices and explicit overrides.
func TestPhase1DefaultClaimsMatchTheSeededBinary(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "claims.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mode, err := st.GetSetting(context.Background(), store.SettingLocalDNSSECDefault)
	if err != nil || mode != "off" {
		t.Fatalf("fresh mode = %q, %v; reconcile the public claims with this change", mode, err)
	}
	for _, name := range []string{
		"README.md", "SECURITY.md", "TRUST.md", "docs/capabilities.md",
		"docs/assurance.md", "docs/roadmap.md", "dnsdaddy.example.yaml",
		"install.sh", "internal/web/static/setup.js",
	} {
		body, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), phase1DefaultFact) {
			t.Errorf("%s does not carry the shared default/override fact", name)
		}
	}
}

// Parse the document actually served by this build; indentation changes must
// not hide an active-looking input or output field from the contract check.
func TestPhase1SafeSearchBothServedSchemasRemainExplicitNoOps(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do("GET", "/openapi.yaml", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("spec status %d", resp.StatusCode)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	lookup := func(keys ...string) map[string]any {
		current := spec
		for _, key := range keys {
			next, ok := current[key].(map[string]any)
			if !ok {
				t.Fatalf("missing schema mapping %s in %v", key, keys)
			}
			current = next
		}
		return current
	}
	for _, name := range []string{"Policy", "PolicyInput"} {
		field := lookup("components", "schemas", name, "properties", "safeSearch")
		description, _ := field["description"].(string)
		if field["type"] != "boolean" || field["deprecated"] != true || !strings.Contains(strings.ToLower(description), "not enforced") {
			t.Errorf("%s.safeSearch must be a deprecated, explicitly not enforced compatibility boolean: %+v", name, field)
		}
	}
}

func TestPhase1SafeSearchCompatibilitySurvivesPatchAndUnrelatedEdits(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, raw := h.do("POST", "/api/v1/policies", map[string]any{"name": "Compatibility only", "safeSearch": true})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || created.ID == "" {
		t.Fatalf("created policy: %s %v", raw, err)
	}
	path := "/api/v1/policies/" + created.ID
	for _, want := range []bool{false, true} {
		resp, raw = h.do("PATCH", path, map[string]any{"safeSearch": want})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("patch: %d %s", resp.StatusCode, raw)
		}
		resp, raw = h.do("PATCH", path, map[string]any{"description": "No search-result enforcement is provided"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unrelated patch: %d %s", resp.StatusCode, raw)
		}
		resp, raw = h.do("GET", path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("read: %d %s", resp.StatusCode, raw)
		}
		var fetched struct {
			SafeSearch *bool `json:"safeSearch"`
		}
		if err := json.Unmarshal(raw, &fetched); err != nil {
			t.Fatal(err)
		}
		if fetched.SafeSearch == nil || *fetched.SafeSearch != want {
			t.Fatalf("compatibility value was dropped or reset: %s", raw)
		}
	}
}
