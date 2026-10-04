package api

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestServedAccessContractPreservesCountersAndAddsBoundedSources(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatal(err)
	}
	schema := openAPIAccessMap(doc, "paths", "/api/v1/activity/live", "get", "responses", "200", "content", "application/json", "schema")
	properties := openAPIAccessMap(schema, "properties")
	for _, name := range []string{"available", "recent", "sinceStart", "clientAccess"} {
		if _, ok := properties[name]; !ok {
			t.Fatalf("missing live field %s", name)
		}
	}
	entries := openAPIAccessMap(properties, "clientAccess", "properties", "entries")
	if entries["maxItems"] != 64 {
		t.Fatal("source bound missing from served contract")
	}
	if _, ok := doc["security"]; !ok {
		t.Fatal("management authentication disappeared")
	}
	if _, ok := openAPIAccessMap(doc, "paths")["/api/v1/setup"]; !ok {
		t.Fatal("setup contract disappeared")
	}
	if _, ok := openAPIAccessMap(doc, "components", "schemas", "LiveActivity", "properties")["clientAccess"]; ok {
		t.Fatal("the anonymous Overview.live contract was changed")
	}
}
