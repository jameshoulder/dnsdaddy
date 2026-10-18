package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const AdminPasswordHashKey = "admin_password_hash"
const (
	AuthBootstrapPending = "bootstrap_pending"
	AuthActive           = "active"
	AuthRecoveryRequired = "recovery_required"
)

var (
	ErrAdminStorage  = errors.New("administrator credential storage is unavailable")
	ErrAdminRecovery = errors.New("administrator credential recovery is required; bootstrap configuration cannot reset an existing account")
	ErrAdminConflict = errors.New("administrator credentials changed; authenticate again")
)

// The hash setting remains the only password authority, including in backups.
type AdminCredential struct {
	Hash          string
	Revision      int64
	State, Source string
}

var bcryptEncoding = regexp.MustCompile(`^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

func ValidAdminHash(hash string) bool {
	if !bcryptEncoding.MatchString(hash) {
		return false
	}
	_, err := bcrypt.Cost([]byte(hash))
	return err == nil
}

// Apply schema and auth migration together: a crash cannot lose the evidence
// that a genuinely empty database is permitted to bootstrap. No seed rows exist yet.
func applySchemaAndAdminAuth(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrAdminStorage
	}
	defer tx.Rollback()
	var tables int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&tables); err != nil {
		return ErrAdminStorage
	}
	fresh := tables == 0
	if _, err = tx.ExecContext(ctx, schemaSQL); err != nil {
		return errors.New("database schema could not be applied")
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS admin_auth_state (
 id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>=0),
 state TEXT NOT NULL CHECK(state IN ('bootstrap_pending','active','recovery_required')),
 source TEXT NOT NULL CHECK(source IN ('','legacy','configured','generated')))`); err != nil {
		return ErrAdminStorage
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(sessions)")
	if err != nil {
		return ErrAdminStorage
	}
	hasRevision := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			rows.Close()
			return ErrAdminStorage
		}
		hasRevision = hasRevision || name == "credential_revision"
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrAdminStorage
	}
	if !hasRevision {
		if _, err = tx.ExecContext(ctx, `ALTER TABLE sessions ADD COLUMN credential_revision INTEGER NOT NULL DEFAULT 0`); err != nil {
			return ErrAdminStorage
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM admin_auth_state WHERE id=1").Scan(&count); err != nil {
		return ErrAdminStorage
	}
	if count == 0 {
		var hash string
		err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", AdminPasswordHashKey).Scan(&hash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ErrAdminStorage
		}
		state, source := AuthRecoveryRequired, "legacy"
		if err == nil && ValidAdminHash(hash) {
			state = AuthActive
		} else if fresh && errors.Is(err, sql.ErrNoRows) {
			state, source = AuthBootstrapPending, ""
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO admin_auth_state(id,revision,state,source) VALUES(1,0,?,?)", state, source); err != nil {
			return ErrAdminStorage
		}
		// A one-time migration sign-out. Normal restarts do not revoke sessions.
		if _, err = tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
			return ErrAdminStorage
		}
	}
	if err = tx.Commit(); err != nil {
		return ErrAdminStorage
	}
	return nil
}

func (s *Store) ReadAdminCredential(ctx context.Context) (AdminCredential, error) {
	var c AdminCredential
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(p.value,''),a.revision,a.state,a.source
 FROM admin_auth_state a LEFT JOIN settings p ON p.key=? WHERE a.id=1`, AdminPasswordHashKey).Scan(&c.Hash, &c.Revision, &c.State, &c.Source)
	if err != nil {
		return AdminCredential{}, ErrAdminStorage
	}
	if c.Revision < 0 || c.State == AuthRecoveryRequired ||
		(c.State == AuthActive && !ValidAdminHash(c.Hash)) ||
		(c.State == AuthBootstrapPending && ((c.Hash != "" && (c.Source != "generated" || !ValidAdminHash(c.Hash))) || (c.Hash == "" && c.Source != ""))) ||
		(c.State != AuthActive && c.State != AuthBootstrapPending) {
		return AdminCredential{}, ErrAdminRecovery
	}
	return c, nil
}

// initialize uses a conditional insert, never an UPSERT of an existing hash.
func (s *Store) InitializeAdminCredential(ctx context.Context, hash string, generated bool) (bool, error) {
	if !ValidAdminHash(hash) {
		return false, ErrAdminRecovery
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, ErrAdminStorage
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value)
 SELECT ?,? FROM admin_auth_state WHERE id=1 AND state=? AND source='' AND revision=0
 ON CONFLICT(key) DO NOTHING`, AdminPasswordHashKey, hash, AuthBootstrapPending)
	if err != nil {
		return false, ErrAdminStorage
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, ErrAdminStorage
	}
	if n != 1 {
		return false, ErrAdminConflict
	}
	state, source, revision := AuthActive, "configured", 1
	if generated {
		state, source, revision = AuthBootstrapPending, "generated", 0
	}
	if _, err = tx.ExecContext(ctx, "UPDATE admin_auth_state SET state=?,source=?,revision=? WHERE id=1", state, source, revision); err != nil {
		return false, ErrAdminStorage
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return false, ErrAdminStorage
	}
	if err = tx.Commit(); err != nil {
		return false, ErrAdminStorage
	}
	return true, nil
}
func (s *Store) ActivateGeneratedAdminCredential(ctx context.Context, hash string) error {
	return s.activateGenerated(ctx, AdminCredential{Hash: hash, State: AuthBootstrapPending, Source: "generated", Revision: 0}, false)
}

// RecoverGeneratedAdminCredential follows password proof in Auth and performs
// state CAS, session revocation and a nonsecret event in one transaction.
func (s *Store) RecoverGeneratedAdminCredential(ctx context.Context, expected AdminCredential) error {
	return s.activateGenerated(ctx, expected, true)
}
func (s *Store) activateGenerated(ctx context.Context, c AdminCredential, audit bool) error {
	if c.State != AuthBootstrapPending || c.Source != "generated" || c.Revision != 0 || !ValidAdminHash(c.Hash) {
		return ErrAdminRecovery
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrAdminStorage
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE admin_auth_state SET state=?,revision=1 WHERE id=1 AND state=? AND source='generated' AND revision=0 AND EXISTS(SELECT 1 FROM settings WHERE key=? AND value=?)`, AuthActive, AuthBootstrapPending, AdminPasswordHashKey, c.Hash)
	if err != nil {
		return ErrAdminStorage
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ErrAdminStorage
	}
	if n != 1 {
		return ErrAdminConflict
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return ErrAdminStorage
	}
	if audit {
		if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS admin_recovery_events(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,revision INTEGER NOT NULL,action TEXT NOT NULL CHECK(action='activate_existing_generated'))`); err != nil {
			return ErrAdminStorage
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO admin_recovery_events(at,revision,action) VALUES(?,1,'activate_existing_generated')", time.Now().UTC().Unix()); err != nil {
			return ErrAdminStorage
		}
	}
	if err = tx.Commit(); err != nil {
		return ErrAdminStorage
	}
	return nil
}
func (s *Store) ReplaceAdminCredential(ctx context.Context, expected AdminCredential, nextHash string) error {
	if expected.State != AuthActive || expected.Revision == math.MaxInt64 || !ValidAdminHash(nextHash) {
		return ErrAdminRecovery
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrAdminStorage
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE settings SET value=? WHERE key=? AND value=?
 AND EXISTS(SELECT 1 FROM admin_auth_state WHERE id=1 AND state=? AND revision=?)`, nextHash, AdminPasswordHashKey, expected.Hash, AuthActive, expected.Revision)
	if err != nil {
		return ErrAdminStorage
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ErrAdminStorage
	}
	if n != 1 {
		return ErrAdminConflict
	}
	if _, err = tx.ExecContext(ctx, "UPDATE admin_auth_state SET revision=revision+1 WHERE id=1"); err != nil {
		return ErrAdminStorage
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return ErrAdminStorage
	}
	if err = tx.Commit(); err != nil {
		return ErrAdminStorage
	}
	return nil
}
