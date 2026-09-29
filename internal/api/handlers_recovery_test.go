package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/backup"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func TestRecoveryRoutesRequireAuthenticationAndSameOrigin(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/api/v1/config/history", "/api/v1/recovery/status"} {
		resp, _ := h.do("GET", p, nil)
		if resp.StatusCode != 401 {
			t.Errorf("%s status %d", p, resp.StatusCode)
		}
	}
	resp, _ := h.do("POST", "/api/v1/recovery/backup", map[string]string{"passphrase": "isolated test phrase"})
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous backup status %d", resp.StatusCode)
	}
	h.login()
	req := httptest.NewRequest("POST", "http://management.example/api/v1/recovery/backup", strings.NewReader(`{"passphrase":"isolated test phrase"}`))
	token, err := h.store.CreateSession(context.Background(), time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("Origin", "https://unrelated.example")
	w := httptest.NewRecorder()
	h.api.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("cross-origin backup status %d", w.Code)
	}
}

func TestConfigHistoryShowsRealChangesAndNoTokenSecret(t *testing.T) {
	h := newHarness(t)
	h.login()
	resp, raw := h.do("POST", "/api/v1/tokens", map[string]string{"name": "automation"})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	var token store.APIToken
	if err := json.Unmarshal(raw, &token); err != nil {
		t.Fatal(err)
	}
	resp, raw = h.do("GET", "/api/v1/config/history", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("history: %d %s", resp.StatusCode, raw)
	}
	if token.Secret == "" {
		t.Fatal("fixture returned no API token")
	}
	if bytes.Contains(raw, []byte(token.Secret)) {
		t.Fatal("API token leaked to configuration history")
	}
	if !bytes.Contains(raw, []byte("automation")) || !bytes.Contains(raw, []byte("session:admin")) {
		t.Fatalf("missing actual change or actor: %s", raw)
	}
	for _, query := range []string{"?beforeId=-1", "?beforeId=nonsense", "?limit=201", "?limit=0"} {
		resp, _ := h.do("GET", "/api/v1/config/history"+query, nil)
		if resp.StatusCode != 400 {
			t.Fatalf("bad cursor %s status %d", query, resp.StatusCode)
		}
	}
}

func TestUnavailableAuditRefusesMutationBeforeItRuns(t *testing.T) {
	h := newHarness(t)
	h.login()
	if _, err := h.store.DB().Exec("DROP TABLE config_change_history"); err != nil {
		t.Fatal(err)
	}
	resp, raw := h.do("PUT", "/api/v1/clients", map[string]string{"ip": "10.10.1.2", "name": "must-not-save"})
	if resp.StatusCode != 503 {
		t.Fatalf("status %d %s", resp.StatusCode, raw)
	}
	clients, err := h.store.ListClients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		if c.Name == "must-not-save" {
			t.Fatal("mutation ran without durable intent")
		}
	}
}

func TestAuditCompletionFailureReportsPersistedChangeAndPendingIntent(t *testing.T) {
	h := newHarness(t)
	h.login()
	if _, err := h.store.DB().Exec(`CREATE TRIGGER deny_audit_completion BEFORE UPDATE ON config_change_history BEGIN SELECT RAISE(FAIL,'fixture update failure'); END`); err != nil {
		t.Fatal(err)
	}
	resp, raw := h.do("PUT", "/api/v1/clients", map[string]string{"ip": "10.10.1.3", "name": "actually-saved"})
	if resp.StatusCode != 500 || !bytes.Contains(raw, []byte(`"configurationMayHaveChanged":true`)) || resp.Header.Get("X-DNSDaddy-Audit-Incomplete") != "true" {
		t.Fatalf("silent audit loss: %d %s", resp.StatusCode, raw)
	}
	clients, err := h.store.ListClients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range clients {
		if c.Name == "actually-saved" {
			found = true
		}
	}
	if !found {
		t.Fatal("test did not exercise an already committed mutation")
	}
	events, _, err := h.store.ListConfigChanges(context.Background(), 0, 50)
	if err != nil || len(events) != 1 || events[0].Status != "pending" {
		t.Fatalf("lost durable pending record: %+v %v", events, err)
	}
}

func TestAuditedConcurrentChangesHaveDistinctOrderedBeforeAndAfter(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.SetClientName(ctx, "10.10.1.4", "initial"); err != nil {
		t.Fatal(err)
	}
	session, err := h.store.CreateSession(ctx, time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	makeRequest := func(name string) *http.Request {
		r := httptest.NewRequest("PUT", "http://management.example/api/v1/clients", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
		return r
	}
	first := h.api.withConfigAudit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		if err := h.store.SetClientName(ctx, "10.10.1.4", "first"); err != nil {
			t.Error(err)
		}
		w.WriteHeader(204)
	}))
	second := h.api.withConfigAudit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.store.SetClientName(ctx, "10.10.1.4", "second"); err != nil {
			t.Error(err)
		}
		w.WriteHeader(204)
	}))
	wg.Add(2)
	go func() { defer wg.Done(); first.ServeHTTP(httptest.NewRecorder(), makeRequest("first")) }()
	<-entered
	go func() { defer wg.Done(); second.ServeHTTP(httptest.NewRecorder(), makeRequest("second")) }()
	close(release)
	wg.Wait()
	events, _, err := h.store.ListConfigChanges(ctx, 0, 50)
	if err != nil || len(events) != 2 {
		t.Fatalf("history: %+v %v", events, err)
	}
	if len(events[0].Changes) != 1 || events[0].Changes[0].Before != "first" || events[0].Changes[0].After != "second" {
		t.Fatalf("overlapped changes: %+v", events[0])
	}
	if len(events[1].Changes) != 1 || events[1].Changes[0].Before != "initial" || events[1].Changes[0].After != "first" {
		t.Fatalf("incorrect first change: %+v", events[1])
	}
}

func TestRecoveryBackupReturnsVerifiedEncryptedAttachment(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.api.Recovery = backup.New(backup.Options{Config: h.api.Config, Database: h.store.DB(), Version: "api-fixture"})
	resp, raw := h.do("POST", "/api/v1/recovery/backup", map[string]string{"passphrase": "too short"})
	if resp.StatusCode != 400 {
		t.Fatalf("weak passphrase: %d %s", resp.StatusCode, raw)
	}
	passphrase := "isolated API recovery passphrase"
	resp, raw = h.do("POST", "/api/v1/recovery/backup", map[string]string{"passphrase": passphrase})
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("backup response: %d %s", resp.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte(passphrase)) {
		t.Fatal("passphrase in attachment")
	}
	if _, err := backup.Restore(context.Background(), bytes.NewReader(raw), []byte(passphrase), filepath.Join(t.TempDir(), "restore")); err != nil {
		t.Fatalf("HTTP backup is not restorable: %v", err)
	}
	events, _, err := h.store.ListConfigChanges(context.Background(), 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(events)
	if bytes.Contains(encoded, []byte(passphrase)) {
		t.Fatal("passphrase in history")
	}
}

func TestAuditCapturesPairedIntegrationModeAndEnrichmentSettings(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	session, err := h.store.CreateSession(ctx, time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("PUT", "http://management.example/api/v1/integrations/settings", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	wrapped := h.api.withConfigAudit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.store.SetIntegrationSettings(ctx, "cache_only", true); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("write status %d %s", w.Code, w.Body.String())
	}
	events, _, err := h.store.ListConfigChanges(ctx, 0, 50)
	if err != nil || len(events) != 1 {
		t.Fatalf("history: %+v %v", events, err)
	}
	foundMode, foundEnrichment := false, false
	for _, change := range events[0].Changes {
		if change.Resource == "setting:integrations.reputation_mode" && change.Field == "value" {
			foundMode = true
		}
		if change.Resource == "setting:integrations.enrichment" && change.Field == "value" {
			foundEnrichment = true
		}
		if change.Redacted {
			t.Fatal("non-secret integration mode was redacted")
		}
	}
	if !foundMode || !foundEnrichment {
		t.Fatalf("paired integration setting missing: %+v", events[0].Changes)
	}
}
