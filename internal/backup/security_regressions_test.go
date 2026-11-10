package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityRestoreRejectsUnknownEmptyManifestMapping checks that unknown empty-valued archive mappings cannot override protected settings.
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

// TestSecurityRestoreForcesCredentialAndDataLocation checks restored launch settings force the recovered database and clear bootstrap secrets.
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

// TestSecurityRestoreRefusesTriggerBypassingSessionRevocation verifies an archive trigger cannot silently preserve administrator sessions.
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

// TestSecurityCredentialInspectionRejectsComputedView prevents unbounded computed credential views during restore.
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

// TestSecurityRestoreRejectsUppercaseSessionTrigger ensures trigger detection is case-insensitive for restored SESSIONS tables.
func TestSecurityRestoreRejectsUppercaseSessionTrigger(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "uppercase-sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		"CREATE TABLE SESSIONS (id TEXT)",
		"INSERT INTO SESSIONS VALUES ('old-session')",
		"CREATE TRIGGER preserve_session BEFORE DELETE ON SESSIONS BEGIN SELECT RAISE(IGNORE); END",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := finishDatabase(context.Background(), dbPath, t.TempDir(), Manifest{}); err == nil {
		t.Fatal("restore accepted a session trigger declared on SESSIONS")
	}
}

// TestSecurityUppercaseSessionsWithoutTriggerCanBeRevoked allows a safe uppercase session table to be fully revoked.
func TestSecurityUppercaseSessionsWithoutTriggerCanBeRevoked(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "uppercase-no-trigger.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE SESSIONS (id TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO SESSIONS VALUES ('old-session')"); err != nil {
		t.Fatal(err)
	}
	revoked, err := finishDatabase(context.Background(), dbPath, t.TempDir(), Manifest{})
	if err != nil {
		t.Fatalf("recovered upper-case table without triggers should be revocable: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("revoked %d sessions, want 1", revoked)
	}
}
