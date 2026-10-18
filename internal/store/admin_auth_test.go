package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func authHash(t *testing.T, text string) string {
	t.Helper()
	h, e := bcrypt.GenerateFromPassword([]byte(text), bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	return string(h)
}
func activeCredential(t *testing.T, s *Store) AdminCredential {
	t.Helper()
	_, e := s.InitializeAdminCredential(context.Background(), authHash(t, "synthetic-current-password"), false)
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.ReadAdminCredential(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func execAuthFixture(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, e := s.db.Exec(q, args...); e != nil {
		t.Fatal("fixture SQL failed")
	}
}

func TestF03LegacyMigrationPreservesHashAndSignsOutOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	hash := authHash(t, "short") // existing weak but structurally valid passwords are not reset
	execAuthFixture(t, s, "DROP TABLE admin_auth_state")
	execAuthFixture(t, s, "INSERT INTO settings(key,value) VALUES(?,?)", AdminPasswordHashKey, hash)
	execAuthFixture(t, s, "INSERT INTO sessions(token_hash,created_at,expires_at,last_seen) VALUES(?,0,9999999999,0)", hashSessionToken("legacy-token"))
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.ReadAdminCredential(ctx)
	if e != nil || c.Hash != hash || c.State != AuthActive || c.Source != "legacy" {
		t.Fatal("legacy hash not preserved")
	}
	if live, _ := s.LookupSession(ctx, "legacy-token"); live {
		t.Fatal("legacy session survived migration")
	}
	token, e := s.CreateSessionAtRevision(ctx, c.Revision, time.Hour, "synthetic")
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c2, e := s.ReadAdminCredential(ctx)
	if e != nil || c2 != c {
		t.Fatal("migration was not idempotent")
	}
	if live, e := s.LookupSession(ctx, token); e != nil || !live {
		t.Fatal("normal restart revoked session")
	}
}
func TestF03LegacyMissingAndInvalidHashesCannotBootstrap(t *testing.T) {
	for _, bad := range []string{"missing", "", "malformed"} {
		name := bad
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy.db")
			s, e := Open(path)
			if e != nil {
				t.Fatal(e)
			}
			execAuthFixture(t, s, "DROP TABLE admin_auth_state")
			if bad != "missing" {
				execAuthFixture(t, s, "INSERT INTO settings(key,value) VALUES(?,?)", AdminPasswordHashKey, bad)
			}
			s.Close()
			s, e = Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if _, e = s.ReadAdminCredential(context.Background()); !errors.Is(e, ErrAdminRecovery) {
				t.Fatal("invalid legacy state not closed")
			}
			if _, e = s.InitializeAdminCredential(context.Background(), authHash(t, "synthetic-bootstrap-password"), false); e == nil {
				t.Fatal("invalid legacy state reset")
			}
		})
	}
}
func TestF03MigrationRollbackPreservesLegacyAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	hash := activeCredential(t, s).Hash
	execAuthFixture(t, s, "DROP TABLE admin_auth_state")
	execAuthFixture(t, s, "INSERT INTO sessions(token_hash,created_at,expires_at,last_seen) VALUES('fixture',0,9999999999,0)")
	execAuthFixture(t, s, "CREATE TRIGGER fail_migration BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'synthetic-secret'); END")
	s.Close()
	if opened, e := Open(path); e == nil {
		opened.Close()
		t.Fatal("migration failure was accepted")
	} else if strings.Contains(e.Error(), "synthetic-secret") {
		t.Fatal("migration exposed error payload")
	}
	raw, e := sql.Open("sqlite", "file:"+path)
	if e != nil {
		t.Fatal(e)
	}
	var n int
	raw.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='admin_auth_state'").Scan(&n)
	if n != 0 {
		t.Fatal("failed migration committed auth table")
	}
	var got string
	raw.QueryRow("SELECT value FROM settings WHERE key=?", AdminPasswordHashKey).Scan(&got)
	if got != hash {
		t.Fatal("failed migration changed hash")
	}
	if _, e = raw.Exec("DROP TRIGGER fail_migration"); e != nil {
		t.Fatal(e)
	}
	raw.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := s.ReadAdminCredential(context.Background())
	if e != nil || c.Hash != hash {
		t.Fatal("migration retry did not preserve hash")
	}
}
func TestF03BootstrapInsertIsAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	hashes := []string{authHash(t, "synthetic-first-password"), authHash(t, "synthetic-other-password")}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, h := range hashes {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			<-start
			_, e := s.InitializeAdminCredential(ctx, h, false)
			errs <- e
		}(h)
	}
	close(start)
	wg.Wait()
	close(errs)
	wins := 0
	for e := range errs {
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrAdminConflict) {
			t.Fatal("unexpected bootstrap result")
		}
	}
	if wins != 1 {
		t.Fatal("bootstrap must have exactly one winner")
	}
	c, e := s.ReadAdminCredential(ctx)
	if e != nil || (c.Hash != hashes[0] && c.Hash != hashes[1]) {
		t.Fatal("invalid bootstrap winner")
	}
	if e = s.SetSetting(ctx, AdminPasswordHashKey, hashes[0]); !errors.Is(e, ErrAdminRecovery) {
		t.Fatal("generic setting writer bypassed authority")
	}
}
func TestF03RotationRollbackAtEveryWriteAndCommit(t *testing.T) {
	for _, phase := range []string{"hash", "revision", "sessions", "commit"} {
		t.Run(phase, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()
			c := activeCredential(t, s)
			token, e := s.CreateSessionAtRevision(ctx, c.Revision, time.Hour, "synthetic")
			if e != nil {
				t.Fatal(e)
			}
			switch phase {
			case "hash":
				execAuthFixture(t, s, "CREATE TRIGGER fault BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT,'synthetic-auth-token'); END")
			case "revision":
				execAuthFixture(t, s, "CREATE TRIGGER fault BEFORE UPDATE ON admin_auth_state BEGIN SELECT RAISE(ABORT,'synthetic-auth-token'); END")
			case "sessions":
				execAuthFixture(t, s, "CREATE TRIGGER fault BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'synthetic-auth-token'); END")
			case "commit":
				execAuthFixture(t, s, "CREATE TABLE guard_parent(id INTEGER PRIMARY KEY)")
				execAuthFixture(t, s, "CREATE TABLE guard_child(id INTEGER REFERENCES guard_parent(id) DEFERRABLE INITIALLY DEFERRED)")
				execAuthFixture(t, s, "CREATE TRIGGER fault AFTER DELETE ON sessions BEGIN INSERT INTO guard_child VALUES(1); END")
			}
			e = s.ReplaceAdminCredential(ctx, c, authHash(t, "synthetic-next-password"))
			if !errors.Is(e, ErrAdminStorage) || strings.Contains(e.Error(), "synthetic-auth-token") {
				t.Fatal("unsafe failure result")
			}
			after, e := s.ReadAdminCredential(ctx)
			if e != nil || after != c {
				t.Fatal("partial password or revision change")
			}
			if live, e := s.LookupSession(ctx, token); e != nil || !live {
				t.Fatal("failed change revoked session")
			}
		})
	}
}
func TestF03ConcurrentRotationAndStaleLogin(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	c := activeCredential(t, s)
	token, e := s.CreateSessionAtRevision(ctx, c.Revision, time.Hour, "before-change")
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, p := range []string{"synthetic-next-one", "synthetic-next-two"} {
		h := authHash(t, p)
		go func() { <-start; errs <- s.ReplaceAdminCredential(ctx, c, h) }()
	}
	close(start)
	wins := 0
	for range 2 {
		e := <-errs
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrAdminConflict) {
			t.Fatal("unexpected rotation error")
		}
	}
	if wins != 1 {
		t.Fatal("two changes from one credential snapshot must not win")
	}
	if live, _ := s.LookupSession(ctx, token); live {
		t.Fatal("old session survived rotation")
	}
	if _, e = s.CreateSessionAtRevision(ctx, c.Revision, time.Hour, "stale-login"); !errors.Is(e, ErrAdminConflict) {
		t.Fatal("stale verified login issued session")
	}
	// Defense in depth: even a stale row inserted by maintenance is not valid.
	execAuthFixture(t, s, "INSERT INTO sessions(token_hash,created_at,expires_at,last_seen,credential_revision) VALUES(?,0,9999999999,0,?)", hashSessionToken("stale-row"), c.Revision)
	if live, _ := s.LookupSession(ctx, "stale-row"); live {
		t.Fatal("stale revision row accepted")
	}
}
func TestF03CredentialErrorsFailClosed(t *testing.T) {
	s := newTestStore(t)
	c := activeCredential(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.ReplaceAdminCredential(ctx, c, authHash(t, "synthetic-next-password")); !errors.Is(e, ErrAdminStorage) {
		t.Fatal("cancelled transaction accepted")
	}
	if _, e := s.ReadAdminCredential(ctx); !errors.Is(e, ErrAdminStorage) {
		t.Fatal("cancelled read accepted")
	}
	s.Close()
	if _, e := s.ReadAdminCredential(context.Background()); !errors.Is(e, ErrAdminStorage) {
		t.Fatal("closed database accepted")
	}
}

func TestF03InitializationAndReadonlyFailuresAreAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	execAuthFixture(t, s, "CREATE TRIGGER fail_init BEFORE UPDATE ON admin_auth_state BEGIN SELECT RAISE(ABORT,'synthetic-secret'); END")
	if _, e := s.InitializeAdminCredential(ctx, authHash(t, "synthetic-initial-password"), false); !errors.Is(e, ErrAdminStorage) {
		t.Fatal("initialization failure accepted")
	}
	c, e := s.ReadAdminCredential(ctx)
	if e != nil || c.Hash != "" || c.State != AuthBootstrapPending {
		t.Fatal("partial initial credential persisted")
	}
	execAuthFixture(t, s, "DROP TRIGGER fail_init")
	c = activeCredential(t, s)
	var filename string
	// Query SQLite for this isolated fixture's path rather than assuming the helper layout.
	var seq int
	var name string
	if e = s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &filename); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenReadOnly(filename)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if e = ro.ReplaceAdminCredential(ctx, c, authHash(t, "synthetic-other-password")); !errors.Is(e, ErrAdminStorage) {
		t.Fatal("read-only replacement accepted")
	}
	after, e := s.ReadAdminCredential(ctx)
	if e != nil || after != c {
		t.Fatal("read-only operation changed credential")
	}
}

func TestF03FreshMigrationCancellationRemainsFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	db, e := sql.Open("sqlite", "file:"+path)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = applySchemaAndAdminAuth(ctx, db); !errors.Is(e, ErrAdminStorage) {
		t.Fatal("cancelled migration accepted")
	}
	db.Close()
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e := s.ReadAdminCredential(context.Background())
	if e != nil || c.State != AuthBootstrapPending || c.Hash != "" {
		t.Fatal("interrupted fresh migration lost bootstrap eligibility")
	}
}
