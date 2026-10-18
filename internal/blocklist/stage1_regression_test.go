package blocklist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/feedpolicy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

type stage1RoundTrip func(*http.Request) (*http.Response, error)

func (f stage1RoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func stage1Response(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func TestStage1SaveRejectsUnsafeFeeds(t *testing.T) {
	h := newManagerHarness(t)
	for _, raw := range []string{"http://public.example/list", "https://127.0.0.1/list", "https://[::1]/list", "https://169.254.169.254/list", "https://user:synthetic-password@public.example/list"} {
		t.Run(raw, func(t *testing.T) {
			name := "synthetic"
			_, err := h.store.CreateFeed(context.Background(), store.FeedInput{Name: &name, URL: &raw})
			if err == nil {
				t.Fatal("unsafe remote feed accepted")
			}
		})
	}
}
func TestStage1RedirectDowngradeRejected(t *testing.T) {
	h := newManagerHarness(t)
	calls := 0
	h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			resp := stage1Response(r, 302, "")
			resp.Header.Set("Location", "http://feed.example/downgrade")
			return resp, nil
		}
		return stage1Response(r, 200, "evil.example\n"), nil
	})
	result := h.mgr.download(context.Background(), store.Feed{URL: "https://feed.example/list", Format: "domains"})
	if result.Error == "" || calls != 1 {
		t.Fatalf("downgrade followed: calls=%d outcome=%+v", calls, result)
	}
}
func TestStage1CredentialsNeverEnterFeedDiagnostics(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint(full), func(t *testing.T) {
			h := newManagerHarness(t)
			var logs bytes.Buffer
			h.mgr.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			raw := "https://feed.example/synthetic-path-secret?api_key=synthetic-query-secret"
			f := h.addFeed(t, "synthetic", raw, "malware", "domains")
			h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("synthetic echoed upstream error: %s", raw)
			})
			if full {
				_ = h.mgr.Refresh(context.Background())
			} else {
				_ = h.mgr.RefreshFeed(context.Background(), f.ID)
			}
			got, err := h.store.GetFeed(context.Background(), f.ID)
			if err != nil {
				t.Fatal(err)
			}
			combined := logs.String() + got.LastError
			for _, secret := range []string{"synthetic-path-secret", "synthetic-query-secret", raw} {
				if strings.Contains(combined, secret) {
					t.Errorf("credential marker leaked: %s", secret)
				}
			}
			if got.LastError == "" {
				t.Fatal("missing safe error")
			}
		})
	}
}

func TestStage1AllowedRedirectAndConditionalRefresh(t *testing.T) {
	h := newManagerHarness(t)
	calls := 0
	h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/list" {
			response := stage1Response(r, 302, "")
			response.Header.Set("Location", "https://feed.example/final")
			return response, nil
		}
		if r.Header.Get("If-None-Match") == "synthetic-etag" {
			return stage1Response(r, 304, ""), nil
		}
		response := stage1Response(r, 200, "synthetic.example\n")
		response.Header.Set("ETag", "synthetic-etag")
		return response, nil
	})
	f := h.addFeed(t, "safe", "https://feed.example/list", "malware", "domains")
	for i := 0; i < 2; i++ {
		if err := h.mgr.RefreshFeed(context.Background(), f.ID); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 4 {
		t.Fatalf("redirect/304 flow: %d calls", calls)
	}
	if _, ok := h.holder.Load().Lookup("synthetic.example"); !ok {
		t.Fatal("lost list after 304")
	}
}
func TestStage1LegacyHTTPKeepsCacheAndReportsPolicy(t *testing.T) {
	h := newManagerHarness(t)
	f := h.addFeed(t, "legacy", "https://feed.example/list", "malware", "domains")
	if err := os.WriteFile(h.mgr.cachePath(f.ID), []byte("cached.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.DB().Exec("UPDATE feeds SET url=? WHERE id=?", "http://legacy.example/synthetic-path-secret?key=synthetic-query-secret", f.ID); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return stage1Response(r, 200, "replacement.example\n"), nil
	})
	if err := h.mgr.RefreshFeed(context.Background(), f.ID); err == nil {
		t.Fatal("legacy HTTP refreshed")
	}
	if calls != 0 {
		t.Fatal("policy rejected after network I/O")
	}
	if _, ok := h.holder.Load().Lookup("cached.example"); !ok {
		t.Fatal("lost cached protection")
	}
	stored, _ := h.store.GetFeed(context.Background(), f.ID)
	if !strings.Contains(stored.LastError, "HTTPS") || strings.Contains(stored.LastError, "secret") {
		t.Fatal("policy error unclear or unsafe")
	}
}
func TestStage1BadStatusAndBodyErrorsDoNotEchoCredentials(t *testing.T) {
	for _, mode := range []string{"status", "body"} {
		t.Run(mode, func(t *testing.T) {
			h := newManagerHarness(t)
			var logs bytes.Buffer
			h.mgr.log = slog.New(slog.NewJSONHandler(&logs, nil))
			raw := "https://feed.example/synthetic-path-secret?token=synthetic-query-secret"
			f := h.addFeed(t, "safe", raw, "malware", "domains")
			h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) {
				response := stage1Response(r, 503, "synthetic-query-secret")
				if mode == "body" {
					response.StatusCode = 200
					response.Body = io.NopCloser(stage1FailReader{})
				}
				return response, nil
			})
			_ = h.mgr.RefreshFeed(context.Background(), f.ID)
			stored, _ := h.store.GetFeed(context.Background(), f.ID)
			if stored.LastError == "" {
				t.Fatal("missing failure")
			}
			for _, secret := range []string{"synthetic-path-secret", "synthetic-query-secret"} {
				if strings.Contains(logs.String()+stored.LastError, secret) {
					t.Fatal("diagnostic leak")
				}
			}
		})
	}
}

type stage1FailReader struct{}

func (stage1FailReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic-path-secret synthetic-query-secret")
}

func TestStage1ConfiguredPrivateHTTPSFeedAndCrossOriginRedirect(t *testing.T) {
	h := newManagerHarness(t, func(c *config.Feeds) {
		c.NetworkRules = []feedpolicy.Rule{
			{Origin: "https://corp.example:8443", PrivateCIDRs: []string{"10.20.0.0/16"}, RedirectOrigins: []string{"https://cdn.example"}},
			{Origin: "https://10.20.1.1:8443", PrivateCIDRs: []string{"10.20.1.1/32"}},
		}
	})
	// Admission of an explicitly configured literal internal feed remains possible.
	_ = h.addFeed(t, "private", "https://10.20.1.1:8443/list", "malware", "domains")
	calls := 0
	h.mgr.client.Transport = stage1RoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			resp := stage1Response(r, 302, "")
			resp.Header.Set("Location", "https://cdn.example/list")
			return resp, nil
		}
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("Referer") != "" {
			t.Error("cross-origin request inherited endpoint data")
		}
		return stage1Response(r, 200, "synthetic.example\n"), nil
	})
	result := h.mgr.download(context.Background(), store.Feed{ID: "synthetic", URL: "https://corp.example:8443/list?key=synthetic-query-secret", ETag: "synthetic-etag", Format: "domains"})
	if result.Error != "" || calls != 2 {
		t.Fatalf("explicit integration failed: %+v, %d", result, calls)
	}
}
