package api

import (
	"encoding/json"
	"testing"
)

// A fresh install is the state every deployment passes through, and it is the
// state in which every list this API returns is empty. Go marshals a nil slice
// to null, so "empty" and "broken" looked identical on the wire: the Reports
// page called .map on a null categories array and died with "Cannot read
// properties of null" — for a new user, on the page they opened to see whether
// the product was working.
//
// This walks the responses rather than naming the fields, so a list added
// later is covered without anyone remembering to come back here.
func TestNoEndpointReturnsANullArrayOnAFreshInstall(t *testing.T) {
	h := newHarness(t)
	h.login()

	for _, path := range []string{
		"/api/v1/reports/summary?days=7",
		"/api/v1/overview",
		"/api/v1/networks",
		"/api/v1/policies",
		"/api/v1/feeds",
		"/api/v1/resolvers",
		"/api/v1/diagnostics",
		"/api/v1/findings",
		"/api/v1/findings/summary",
		"/api/v1/queries",
		"/api/v1/categories",
		"/api/v1/threats/categories",
		"/api/v1/threats/top-domains",
		"/api/v1/activity/queries",
		"/api/v1/detectors",
	} {
		t.Run(path, func(t *testing.T) {
			resp, raw := h.do("GET", path, nil)
			if resp.StatusCode != 200 {
				// Not a skip. A skip here is how a renamed route quietly stops
				// being covered while the suite still reports green.
				t.Fatalf("status %d — route missing or renamed; fix the path\n%s",
					resp.StatusCode, raw)
			}
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, raw)
			}
			walkForNulls(t, "", doc)
		})
	}
}

// walkForNulls reports a null sitting where a list belongs. It cannot know the
// intended type of a bare null, so it only judges keys that look plural — which
// is every list field in this API and no scalar one. A null date or a null
// error string is legitimate and stays unflagged.
func walkForNulls(t *testing.T, path string, v any) {
	t.Helper()
	switch n := v.(type) {
	case map[string]any:
		for k, child := range n {
			at := path + "/" + k
			if child == nil && looksPlural(k) {
				t.Errorf("%s is null; the dashboard iterates it, and Go renders an "+
					"empty slice as null unless the handler says otherwise", at)
				continue
			}
			walkForNulls(t, at, child)
		}
	case []any:
		for i, child := range n {
			walkForNulls(t, path+"/[]", child)
			_ = i
		}
	}
}

func looksPlural(key string) bool {
	switch key {
	case "categories", "networks", "feeds", "upstreams", "policies", "queries",
		"findings", "checks", "topBlockedDomains", "publicCidrs", "dashboardCidrs",
		"cidrs", "endpoints", "resolvers", "sources", "rows", "items":
		return true
	}
	return false
}
