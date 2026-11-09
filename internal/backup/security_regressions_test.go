package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityRestoreRejectsUnknownEmptyManifestMapping(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("data_dir: /elsewhere\nhttp:\n  admin_password: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for _, path := range []string{"unexpected.field", "data_dir", "http.admin_password"} {
		err := rewriteConfiguration(root, dir, Manifest{Paths: map[string]string{path: ""}})
		if err == nil {
			t.Fatalf("restore accepted unsupported mapping %q with empty value", path)
		}
	}
}

func TestSecurityRestoreForcesCredentialAndDataLocation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("data_dir: /old\nhttp:\n  admin_password: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := rewriteConfiguration(root, dir, Manifest{Paths: map[string]string{
		"dns.tls_cert_file": "refs/dns-tls-cert.pem",
	}}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), filepath.Join(dir, "data")) || strings.Contains(string(b), "admin_password: old") {
		t.Fatalf("restore did not enforce recovered database location and cleared bootstrap password: %s", b)
	}
}

func TestSecurityRestoreRefusesTriggerBypassingSessionRevocation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "restore.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		"CREATE TABLE sessions (id TEXT)",
		"INSERT INTO sessions VALUES ('old-session')",
		"CREATE TRIGGER keep_session BEFORE DELETE ON sessions BEGIN SELECT RAISE(IGNORE); END",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := finishDatabase(context.Background(), dbPath, t.TempDir(), Manifest{}); err == nil {
		t.Fatal("restore declared success although an archive trigger can retain sessions")
	}
}

func TestSecurityCredentialInspectionRejectsComputedView(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "provider.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE VIEW api_provider_secrets AS SELECT 'p' AS provider_id, zeroblob(10000000) AS ciphertext, 'k' AS key_id"); err != nil {
		t.Fatal(err)
	}
	if err := validateCredentials(context.Background(), dbPath, nil); err == nil {
		t.Fatal("restore queried an attacker-controlled computed credential view")
	}
}
