package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
)

const defaultAccessMigrationKey = "migration.default_ad_hoc_access_v1"

// seed installs first-run defaults: three policies, a catch-all network, and
// the built-in feed list. It is idempotent — existing rows are left alone,
// except that built-in feed metadata (name, URL, category) is refreshed so an
// upgrade can correct a moved or renamed source.
func (s *Store) seed(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := unixMilli(time.Now())

	var policyCount int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policies").Scan(&policyCount); err != nil {
		return err
	}

	if policyCount == 0 {
		defaults := []struct {
			id, name, desc string
			cats           []string
			isDefault      bool
			logQueries     bool
		}{
			{
				id:         "p_standard",
				name:       "Standard business",
				desc:       "Blocks malware, phishing, command-and-control, and cryptomining. Leaves everything else alone.",
				cats:       catalog.DefaultCategories(),
				isDefault:  true,
				logQueries: true,
			},
			{
				id:         "p_strict",
				name:       "Strict",
				desc:       "Standard business plus newly registered domains, adult content, and gambling.",
				cats:       append(catalog.DefaultCategories(), "newly-registered", "adult", "gambling"),
				logQueries: true,
			},
			{
				id:         "p_monitor",
				name:       "Monitor only",
				desc:       "Logs every query and blocks nothing. Useful for a pilot VLAN before you enforce.",
				cats:       nil,
				logQueries: true,
			},
		}

		for _, p := range defaults {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO policies (id, name, description, categories, block_mode, safe_search, log_queries, is_default, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
				p.id, p.name, p.desc, encodeJSON(nonNil(p.cats)), string(BlockNXDOMAIN),
				boolToInt(p.logQueries), boolToInt(p.isDefault), now, now)
			if err != nil {
				return err
			}
		}
	}

	var networkCount int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM networks").Scan(&networkCount); err != nil {
		return err
	}

	// Before Default became a real ad-hoc access switch, the bootstrap ACL was
	// always active. Existing installations therefore served unmatched clients
	// from dns.allowed_client_cidrs regardless of the n_default AllowResolver
	// bit (which, with no CIDRs, granted nothing).
	//
	// Preserve that effective behaviour once, by turning the new switch on for
	// a database that already contains networks. A genuinely fresh database is
	// different: it gets n_default with ad-hoc access explicitly OFF. The marker
	// is written in the same transaction so this cannot run twice after a crash.
	var accessMigrationDone int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM settings WHERE key = ?", defaultAccessMigrationKey,
	).Scan(&accessMigrationDone); err != nil {
		return err
	}

	if networkCount == 0 {
		// The catch-all network has no CIDRs: policy.Engine falls back to it for
		// any client that does not match a more specific network. Its access bit
		// is intentionally off on a fresh install; turning it on admits unmatched
		// clients only inside dns.allowed_client_cidrs.
		_, err := tx.ExecContext(ctx, `
			INSERT INTO networks (id, name, location, policy_id, token, enabled, allow_resolver, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)`,
			"n_default", "Default", "All unmatched clients", "p_standard", NewToken(10), now, now)
		if err != nil {
			return err
		}
	} else if accessMigrationDone == 0 {
		if _, err := tx.ExecContext(ctx,
			"UPDATE networks SET allow_resolver = 1, updated_at = ? WHERE id = ?",
			now, "n_default",
		); err != nil {
			return err
		}
	}

	if accessMigrationDone == 0 {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO settings (key, value) VALUES (?, ?)",
			defaultAccessMigrationKey, "1",
		); err != nil {
			return err
		}
	}

	for _, f := range catalog.DefaultFeeds {
		// Preserve the operator's enabled/disabled choice and refresh state,
		// but keep name/URL/category/format in sync with the shipped catalog.
		_, err := tx.ExecContext(ctx, `
			INSERT INTO feeds (id, name, url, category, format, enabled, builtin, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name       = excluded.name,
				url        = excluded.url,
				category   = excluded.category,
				format     = excluded.format,
				builtin    = 1,
				updated_at = excluded.updated_at`,
			f.ID, f.Name, f.URL, f.Category, f.Format, boolToInt(f.Enabled), now, now)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GetSetting reads a key from the settings table.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting writes a key to the settings table.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	return err
}
