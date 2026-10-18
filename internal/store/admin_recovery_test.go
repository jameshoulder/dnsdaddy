package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestStage5ARecoveryTransactionRollback(t *testing.T) {
	for _, fault := range []string{"state", "sessions", "audit", "commit"} {
		t.Run(fault, func(t *testing.T) {
			s, e := Open(filepath.Join(t.TempDir(), "db"))
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			ctx := context.Background()
			if _, e = s.InitializeAdminCredential(ctx, authHash(t, "synthetic-proof"), true); e != nil {
				t.Fatal(e)
			}
			before, e := s.ReadAdminCredential(ctx)
			if e != nil {
				t.Fatal(e)
			}
			execAuthFixture(t, s, "INSERT INTO sessions(token_hash,created_at,expires_at,last_seen) VALUES('synthetic',0,9999999999,0)")
			target := map[string]string{"state": "admin_auth_state", "sessions": "sessions", "audit": "admin_recovery_events", "commit": "admin_auth_state"}[fault]
			op := "UPDATE"
			if fault == "sessions" {
				op = "DELETE"
			}
			if fault == "audit" {
				op = "INSERT"
				execAuthFixture(t, s, `CREATE TABLE admin_recovery_events(id INTEGER PRIMARY KEY,at INTEGER,revision INTEGER,action TEXT)`)
			}
			body := "SELECT RAISE(ABORT,'synthetic failure');"
			if fault == "commit" {
				execAuthFixture(t, s, "CREATE TABLE recovery_parent(id INTEGER PRIMARY KEY)")
				execAuthFixture(t, s, "CREATE TABLE recovery_child(id INTEGER REFERENCES recovery_parent(id) DEFERRABLE INITIALLY DEFERRED)")
				body = "INSERT INTO recovery_child VALUES(99);"
			}
			execAuthFixture(t, s, "CREATE TRIGGER recovery_fault AFTER "+op+" ON "+target+" BEGIN "+body+" END")
			if e = s.RecoverGeneratedAdminCredential(ctx, before); e == nil {
				t.Fatal("fault accepted")
			}
			after, e := s.ReadAdminCredential(ctx)
			if e != nil || after != before {
				t.Fatal("failed transaction changed authority")
			}
			n, e := s.CountSessions(ctx)
			if e != nil || n != 1 {
				t.Fatal("failed transaction revoked session")
			}
			execAuthFixture(t, s, "DROP TRIGGER recovery_fault")
			if e = s.RecoverGeneratedAdminCredential(ctx, before); e != nil {
				t.Fatal(e)
			}
			after, e = s.ReadAdminCredential(ctx)
			if e != nil || after.Hash != before.Hash || after.State != AuthActive {
				t.Fatal("retry changed password")
			}
			n, e = s.CountSessions(ctx)
			if e != nil || n != 0 {
				t.Fatal("sessions not revoked")
			}
			if e = s.RecoverGeneratedAdminCredential(ctx, before); e != ErrAdminConflict {
				t.Fatal("stale activation accepted")
			}
			var events int
			if e = s.db.QueryRow("SELECT count(*) FROM admin_recovery_events").Scan(&events); e != nil || events != 1 {
				t.Fatal("audit not atomic")
			}
		})
	}
}

func TestStage5AConcurrentRecoveryAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	if _, e = s.InitializeAdminCredential(ctx, authHash(t, "synthetic-proof"), true); e != nil {
		t.Fatal(e)
	}
	before, e := s.ReadAdminCredential(ctx)
	if e != nil {
		t.Fatal(e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e = s.RecoverGeneratedAdminCredential(canceled, before); e == nil {
		t.Fatal("canceled recovery succeeded")
	}
	other, e := OpenAdminRecovery(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	ready := make(chan struct{})
	results := make(chan error, 2)
	for _, db := range []*Store{s, other} {
		go func(db *Store) { <-ready; results <- db.RecoverGeneratedAdminCredential(ctx, before) }(db)
	}
	close(ready)
	winners := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("expected one CAS winner")
	}
	after, e := s.ReadAdminCredential(ctx)
	if e != nil || after.Hash != before.Hash || after.State != AuthActive || after.Revision != 1 {
		t.Fatal("concurrent recovery changed authority")
	}
	var events int
	if e = s.db.QueryRow("SELECT count(*) FROM admin_recovery_events").Scan(&events); e != nil || events != 1 {
		t.Fatal("duplicate recovery event")
	}
}
func TestStage5ASnapshotClassification(t *testing.T) {
	for _, kind := range []string{"fresh", "pending", "active", "legacy", "legacy-missing", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			s, e := Open(filepath.Join(t.TempDir(), "db"))
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			ctx := context.Background()
			want := AuthBootstrapPending
			switch kind {
			case "pending":
				_, e = s.InitializeAdminCredential(ctx, authHash(t, "synthetic-proof"), true)
			case "active", "legacy", "legacy-missing", "malformed":
				_, e = s.InitializeAdminCredential(ctx, authHash(t, "synthetic-proof"), false)
				want = AuthActive
			}
			if e != nil {
				t.Fatal(e)
			}
			if kind == "legacy" || kind == "legacy-missing" {
				execAuthFixture(t, s, "DROP TABLE admin_auth_state")
			}
			if kind == "legacy-missing" {
				execAuthFixture(t, s, "DELETE FROM settings WHERE key=?", AdminPasswordHashKey)
				want = AuthRecoveryRequired
			}
			if kind == "malformed" {
				execAuthFixture(t, s, "UPDATE settings SET value='malformed' WHERE key=?", AdminPasswordHashKey)
				want = AuthRecoveryRequired
			}
			c, e := SnapshotCredential(ctx, s.db)
			if e != nil || c.State != want {
				t.Fatal("incorrect snapshot classification")
			}
		})
	}
}
