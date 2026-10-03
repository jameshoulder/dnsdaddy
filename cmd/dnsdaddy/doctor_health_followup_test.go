package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/config"
	"github.com/jameshoulder/dnsdaddy/internal/diag"
)

func TestDoctorMissingHealthFieldsAreUnknown(t *testing.T) {
	for _, payload := range []string{`{"status":"ok"}`, `{"status":"ok","blocklistSize":0}`, `{"status":"ok","clientAclStale":false}`, `{"status":"unexpected"}`} {
		t.Run(payload, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, payload) }))
			defer server.Close()
			cfg := config.Default()
			cfg.HTTP.Listen = server.Listener.Addr().String()
			checks, stale := doctorWeb(context.Background(), nil, cfg, time.Second)
			if stale != nil || checks[0].Status == diag.StatusPass {
				t.Fatalf("missing evidence became healthy: %+v, stale=%v", checks, stale)
			}
		})
	}
}

func TestDoctorTokenIsSentOnlyToTheVerifiedLocalEndpoint(t *testing.T) {
	const token = "dnsd_fixture"
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected.Store(true) }))
	defer destination.Close()
	for _, redirect := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Error("missing token")
			}
			if redirect {
				http.Redirect(w, r, destination.URL, http.StatusFound)
				return
			}
			_, _ = io.WriteString(w, `{"status":"ok","blocklistSize":42,"clientAclStale":false}`)
		}))
		cfg := config.Default()
		cfg.HTTP.Listen = server.Listener.Addr().String()
		checks, stale := doctorWebWithToken(context.Background(), nil, cfg, time.Second, token)
		if redirect {
			if stale != nil || checks[0].Status != diag.StatusFail {
				t.Fatal("redirect was not refused")
			}
		} else if stale == nil || *stale || checks[0].Status != diag.StatusPass {
			t.Fatalf("authenticated detail lost: %+v", checks)
		}
		server.Close()
	}
	if redirected.Load() {
		t.Fatal("doctor followed a redirect with a credential")
	}
}

func TestDoctorTokenFileSecurity(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("dnsd_fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readDoctorToken(file); err != nil || got != "dnsd_fixture" {
		t.Fatalf("valid file: %q %v", got, err)
	}
	link := file + ".link"
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readDoctorToken(link); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDoctorToken(file); err == nil {
		t.Fatal("accepted world-readable token")
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "dnsd_", "dnsd_good\nInjected: value", strings.Repeat("x", 4097)} {
		if err := os.WriteFile(file, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readDoctorToken(file); err == nil {
			t.Fatal("accepted invalid token")
		}
	}
}
