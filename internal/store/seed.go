package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
)

// SettingLocalDNSSECDefault records what local DNSSEC validation should do on
// this installation when the operator has not configured it either way.
//
// It exists because the question cannot be answered from configuration alone.
// Load starts from Default() and unmarshals YAML over it, so an omitted
// local_dnssec_validation key is indistinguishable at runtime from one written
// out explicitly — there is no "unset" to detect once the struct is populated.
// The database can tell the difference the config file cannot: a database with
// no networks in it has never run DNS Daddy before.
//
// So the decision is made once, at the moment the difference is still visible,
// and recorded. Fresh installs get Learn; an upgrade of an installation that
// never asked for it keeps it off, because Learn sends real DNSSEC queries
// upstream and consumes CPU, and inheriting that from a release upgrade is a
// change to someone's traffic that they did not ask for.
const SettingLocalDNSSECDefault = "install.local_dnssec_default"

// installMarkerKey records that first-run decisions have been taken for this
// database. Both the ad-hoc access migration and the DNSSEC default are keyed
// off it, so the two can never disagree about whether an installation is new.
const installMarkerKey = "install.first_run_decisions_v1"

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

	// First-run decisions, taken once and recorded, because the evidence for
	// them disappears immediately afterwards.
	//
	// "Has this database run DNS Daddy before?" is answerable exactly once: a
	// database with no networks has not. Everything below that depends on the
	// distinction is decided here, in the transaction that also removes the
	// evidence, so a crash cannot leave it half-applied or let it run twice.
	var decided int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM settings WHERE key = ?", installMarkerKey,
	).Scan(&decided); err != nil {
		return err
	}
	freshInstall := networkCount == 0

	if freshInstall {
		// The catch-all network has no CIDRs: policy.Engine falls back to it
		// for any client that does not match a more specific network. Its
		// access bit is intentionally off here, so a fresh install refuses
		// unmatched clients until someone decides otherwise. Turning it on
		// admits them only inside dns.allowed_client_cidrs; it never widens
		// that list.
		_, err := tx.ExecContext(ctx, `
			INSERT INTO networks (id, name, location, policy_id, token, enabled, allow_resolver, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)`,
			clientacl.DefaultNetworkID, "Default", "All unmatched clients", "p_standard", NewToken(10), now, now)
		if err != nil {
			return err
		}
	} else if decided == 0 {
		// An upgrade. Before the Default row became an ad-hoc access switch,
		// its AllowResolver bit granted nothing — a catch-all has no ranges —
		// so every existing installation served its whole configured pool with
		// that bit clear. Leaving it clear now would cut DNS off from every
		// client of every existing deployment the moment they upgraded, so the
		// switch is turned on once to preserve exactly the behaviour they
		// already had. It remains theirs to turn off afterwards.
		if _, err := tx.ExecContext(ctx,
			"UPDATE networks SET allow_resolver = 1, updated_at = ? WHERE id = ?",
			now, clientacl.DefaultNetworkID,
		); err != nil {
			return err
		}
	}

	if decided == 0 {
		dnssecDefault := "off"
		if freshInstall {
			dnssecDefault = "observe"
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO settings (key, value) VALUES (?, ?)",
			SettingLocalDNSSECDefault, dnssecDefault,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO settings (key, value) VALUES (?, ?)",
			installMarkerKey, "1",
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
