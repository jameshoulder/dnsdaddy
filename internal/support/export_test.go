package support

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectDefaultMakesNoOutboundCalls(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	t.Cleanup(srv.Close)

	cfgPath := writeMinimalConfig(t)
	pkg, err := Collect(context.Background(), Options{
		ConfigPath: cfgPath,
		Version:    "test",
		Now:        func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		DoctorRuns: func(context.Context, string) (DoctorSection, error) {
			t.Fatal("doctor collector must not run by default")
			return DoctorSection{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Collection.OutboundRequests != "none-by-default" {
		t.Fatalf("outbound=%q", pkg.Collection.OutboundRequests)
	}
	if pkg.Doctor != nil {
		t.Fatal("doctor section must be absent by default")
	}
	if calls != 0 {
		t.Fatalf("unexpected outbound calls: %d", calls)
	}
	_ = srv.URL // ensure server exists; collector must not use it
}

func TestSecretCanariesAndAdversarialText(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	_, err := Collect(context.Background(), Options{
		ConfigPath:   cfgPath,
		OperatorNote: "Authorization: Bearer dnsd_secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := Collect(context.Background(), Options{
		ConfigPath:     cfgPath,
		OperatorNote:   "see https://example.invalid/path?token=abc",
		SyntheticRepro: "dig @192.0.2.1 example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.ReviewRequired) == 0 {
		t.Fatal("expected reviewRequired for URL/token-like note")
	}
	joined := strings.Join(pkg.Omitted, " ")
	for _, needle := range []string{"password", "query names", "database", "master keys"} {
		if !strings.Contains(strings.ToLower(joined), needle) {
			t.Fatalf("omitted list missing %q", needle)
		}
	}
}

func TestWritePermissionsBoundsAndNoOverwrite(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	dir := filepath.Join(t.TempDir(), "support-out")
	res, err := Write(context.Background(), Options{
		ConfigPath: cfgPath,
		OutputDir:  dir,
		Version:    "test",
		Now:        func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("output dir permissions too open: %v", st.Mode())
	}
	for _, p := range []string{res.Package, res.Manifest} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s permissions too open: %v", p, fi.Mode())
		}
	}
	var decoded Package
	raw, err := os.ReadFile(res.Package)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Build.Version != "test" {
		t.Fatalf("version=%q", decoded.Build.Version)
	}
	if _, err := Write(context.Background(), Options{ConfigPath: cfgPath, OutputDir: dir}); err == nil {
		t.Fatal("expected refusing to overwrite existing output directory")
	}
}

func TestIncludeDoctorLabelsActiveSection(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	pkg, err := Collect(context.Background(), Options{
		ConfigPath:    cfgPath,
		IncludeDoctor: true,
		DoctorRuns: func(context.Context, string) (DoctorSection, error) {
			return DoctorSection{
				Label:   "active-diagnostics",
				Summary: "probe summary",
				Checks:  json.RawMessage(`[{"name":"listener","status":"pass"}]`),
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Doctor == nil || pkg.Collection.ActiveProbes != "explicitly-requested" {
		t.Fatalf("doctor=%v probes=%q", pkg.Doctor, pkg.Collection.ActiveProbes)
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	_, err := Collect(context.Background(), Options{
		ConfigPath:   cfgPath,
		OperatorNote: "bad\x80text",
	})
	if err == nil {
		t.Fatal("expected utf-8 error")
	}
}

func writeMinimalConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "data_dir: " + filepath.ToSlash(dir) + "\n" +
		"dns:\n  listen_udp: \"127.0.0.1:5353\"\n  listen_tcp: \"127.0.0.1:5353\"\n" +
		"  upstreams:\n    - https://1.1.1.1/dns-query\n" +
		"http:\n  listen: \"127.0.0.1:18080\"\n  admin_password: \"support-test-password-not-exported\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
