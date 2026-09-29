package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestFreshFeedCatalogueDoesNotExposeObservatory(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, body := h.do("GET", "/api/v1/feeds", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("feed list: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "observatoryFeedId") || strings.Contains(string(body), "dnsdaddy-observatory") || strings.Contains(string(body), "threats.dnsdaddy.dev") {
		t.Fatalf("retired built-in service still exposed: %s", body)
	}
}

func TestRetiredBuiltinCannotBeReenabledOrRefreshed(t *testing.T) {
	h := newHarness(t)
	h.login()
	_, err := h.store.DB().Exec(`INSERT INTO feeds (id,name,url,category,format,enabled,builtin,created_at,updated_at) VALUES ('dnsdaddy-observatory','Historical source','https://threats.dnsdaddy.dev/api/v1/feed.json','malware','observatory',1,1,0,0)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.RetireLegacyObservatory(context.Background()); err != nil {
		t.Fatal(err)
	}
	row, err := h.store.GetFeed(context.Background(), "dnsdaddy-observatory")
	if err != nil || row.Enabled {
		t.Fatalf("retirement must preserve a disabled historical row: %+v %v", row, err)
	}
	for _, req := range []struct {
		method, path string
		body         any
	}{
		{"PATCH", "/api/v1/feeds/dnsdaddy-observatory", map[string]any{"enabled": true}},
		{"POST", "/api/v1/feeds/dnsdaddy-observatory/refresh", nil},
	} {
		resp, body := h.do(req.method, req.path, req.body)
		if resp.StatusCode != http.StatusGone {
			t.Fatalf("retired connector operation returned %d: %s", resp.StatusCode, body)
		}
	}
	_, body := h.do("GET", "/api/v1/feeds", nil)
	if strings.Contains(string(body), "dnsdaddy-observatory") {
		t.Fatal("retired row still appears in provider choices")
	}
}

func TestRetirementPreservesOperatorDefinedCompatibleFeeds(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, body := h.do("POST", "/api/v1/feeds", map[string]any{"name": "My indicator service", "url": "https://feed.example/indicators.json", "category": "malware", "format": "observatory", "enabled": true})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create compatible feed: %d %s", resp.StatusCode, body)
	}
	var row struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatal(err)
	}
	if err := h.store.RetireLegacyObservatory(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err := h.store.GetFeed(context.Background(), row.ID)
	if err != nil || !saved.Enabled || saved.Builtin {
		t.Fatalf("operator-owned source was changed: %+v %v", saved, err)
	}
}
