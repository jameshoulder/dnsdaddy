package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
)

// SnapshotCredential inspects a committed snapshot without schema migration or
// initialization. Missing legacy hashes are recovery-required, never fresh.
func SnapshotCredential(ctx context.Context, db *sql.DB) (AdminCredential, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AdminCredential{}, ErrAdminStorage
	}
	defer tx.Rollback()
	var tables int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='admin_auth_state'").Scan(&tables); err != nil {
		return AdminCredential{}, ErrAdminStorage
	}
	var c AdminCredential
	if tables == 0 {
		err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", AdminPasswordHashKey).Scan(&c.Hash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return c, ErrAdminStorage
		}
		c.Source = "legacy"
		c.State = AuthRecoveryRequired
		if ValidAdminHash(c.Hash) {
			c.State = AuthActive
		}
	} else {
		err = tx.QueryRowContext(ctx, `SELECT COALESCE(p.value,''),a.revision,a.state,a.source FROM admin_auth_state a LEFT JOIN settings p ON p.key=? WHERE a.id=1`, AdminPasswordHashKey).Scan(&c.Hash, &c.Revision, &c.State, &c.Source)
		if err != nil {
			return AdminCredential{}, ErrAdminStorage
		}
		if c.Revision < 0 || (c.Source != "" && c.Source != "legacy" && c.Source != "configured" && c.Source != "generated") {
			return AdminCredential{}, ErrAdminRecovery
		}
		switch c.State {
		case AuthActive:
			if !ValidAdminHash(c.Hash) {
				c.State = AuthRecoveryRequired
			}
		case AuthBootstrapPending:
			if c.Revision != 0 || !((c.Hash == "" && c.Source == "") || (ValidAdminHash(c.Hash) && c.Source == "generated")) {
				c.State = AuthRecoveryRequired
			}
		case AuthRecoveryRequired:
		default:
			return AdminCredential{}, ErrAdminRecovery
		}
	}
	if err = tx.Commit(); err != nil {
		return AdminCredential{}, ErrAdminStorage
	}
	return c, nil
}

// OpenAdminRecovery never creates a database or runs migrations/seed routines.
// The caller must validate ownership/type and keep the service stopped.
func OpenAdminRecovery(ctx context.Context, path string) (*Store, error) {
	db, err := openAdminRecoveryDB(path)
	if err != nil {
		return nil, ErrAdminStorage
	}
	db.SetMaxOpenConns(1)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, ErrAdminStorage
	}
	return &Store{db: db}, nil
}

func openAdminRecoveryDB(path string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	return sql.Open("sqlite", u.String())
}
