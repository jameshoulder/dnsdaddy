package blocklist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestF04ObservatoryMetadataNeverEntersLogs(t *testing.T) {
	sources := []struct {
		name  string
		value any
	}{
		{"userinfo", "https://synthetic-user:synthetic-password@publisher.example/list"},
		{"query", "https://publisher.example/list?api_key=synthetic-query-token&unknown=synthetic-other-token"},
		{"path", "https://publisher.example/synthetic-path-token/list"},
		{"bare-token", "Bearer synthetic-bearer-token"},
		{"malformed-url", "https://synthetic-user:synthetic-password@[bad%host/?token=synthetic-query-token"},
		{"controls", "synthetic-log-token\r\nforged event\x00"},
		{"legitimate", "legitimate-publisher-label"},
		{"nonstring", map[string]string{"token": "synthetic-object-token"}},
	}
	for _, tc := range sources {
		for _, single := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/single=%v", tc.name, single), func(t *testing.T) {
				h := newManagerHarness(t)
				var logs bytes.Buffer
				h.mgr.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				body, err := json.Marshal(map[string]any{"source": tc.value, "generated_at": "2026-08-26T09:15:00Z", "indicators": []map[string]any{
					{"value": "blocked.example", "type": "domain", "categories": []string{"malware", "c2"}},
					{"value": "127.0.0.1", "type": "ip"},
				}})
				if err != nil {
					t.Fatal(err)
				}
				f := h.addFeed(t, "metadata-fixture", "https://publisher.example/list", "malware", "observatory")
				h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) { return stage1Response(r, 200, string(body)), nil })
				if single {
					err = h.mgr.RefreshFeed(context.Background(), f.ID)
				} else {
					err = h.mgr.Refresh(context.Background())
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, category := range []string{"malware", "c2"} {
					if _, ok := h.holder.Load().LookupEnabled("blocked.example", map[string]bool{category: true}); !ok {
						t.Fatalf("lost %s indexing", category)
					}
				}
				cache, err := os.ReadFile(h.mgr.cachePath(f.ID))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(cache, body) {
					t.Fatal("logging protection mutated cached content")
				}
				parsed, err := ParseObservatory(bytes.NewReader(cache), nil)
				if err != nil {
					t.Fatal(err)
				}
				if source, ok := tc.value.(string); ok && parsed.Source != source {
					t.Fatal("logging protection changed parsed source metadata")
				}
				safe := logs.String()
				if strings.Contains(safe, "synthetic-") || strings.Contains(safe, "legitimate-publisher-label") {
					t.Fatal("untrusted source metadata entered logs")
				}
				for _, diagnostic := range []string{"observatory feed indexed", "observatory feed had unusable indicators", "\"indicators\":1", "\"domains\":1", "\"skipped\":1", "\"generated_at\":", "\"source_present\":"} {
					if !strings.Contains(safe, diagnostic) {
						t.Fatalf("missing safe diagnostic %s", diagnostic)
					}
				}
				// Restart/cache-only rebuild must use the same safe logging boundary.
				logs.Reset()
				if err := h.mgr.LoadFromCache(context.Background()); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(logs.String(), "synthetic-") || strings.Contains(logs.String(), "legitimate-publisher-label") {
					t.Fatal("metadata leaked during cache-only rebuild")
				}
			})
		}
	}
}

func TestF04MalformedCacheDiagnosticsNeverEchoContent(t *testing.T) {
	for _, body := range []string{
		`{"https://synthetic-user:synthetic-password@publisher.example/list?token=synthetic-query-token": [}`,
		`{"source":"synthetic-source-token","indicators":[`,
	} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			h := newManagerHarness(t)
			var logs bytes.Buffer
			h.mgr.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			f := h.addFeed(t, "malformed-fixture", "https://publisher.example/list", "malware", "observatory")
			if err := os.WriteFile(h.mgr.cachePath(f.ID), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := h.mgr.LoadFromCache(context.Background()); err != nil {
				t.Fatal(err)
			}
			load := h.mgr.FeedLoads()[f.ID]
			if load.Loaded || load.Error == "" {
				t.Fatal("invalid cache must report failure")
			}
			encoded, err := json.Marshal(load)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(logs.String()+string(encoded), "synthetic-") {
				t.Fatal("cache parser diagnostic leaked untrusted content")
			}
			if !strings.Contains(logs.String(), "skipping feed with no usable cached copy") {
				t.Fatal("lost cache failure diagnostic")
			}
			if h.holder.Load().Len() != 0 {
				t.Fatal("invalid Observatory document contributed indicators")
			}
		})
	}
}

func TestF04LoadErrorClassificationDoesNotSerializeErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("synthetic-path-token: %w", os.ErrNotExist), "its cached copy is missing"},
		{fmt.Errorf("synthetic-path-token: %w", os.ErrPermission), "its cached copy cannot be read (permission denied)"},
		{errors.New("https://synthetic-user:synthetic-password@publisher.example/?token=synthetic-query-token"), "its cached copy is unreadable or invalid"},
	} {
		if got := describeLoadError(tc.err); got != tc.want {
			t.Fatalf("unexpected safe diagnostic: %q", got)
		}
	}
}
