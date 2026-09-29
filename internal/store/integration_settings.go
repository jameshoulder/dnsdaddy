package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var ErrProviderLimit = errors.New("external provider limit reached (64)")

const IntegrationPreferencesVersionKey = "integrations.ui_preferences_v1"

// CreateManagedAPIProvider performs its capacity check inside the INSERT, so
// simultaneous authenticated requests cannot grow the engine past its bound.
func (s *Store) CreateManagedAPIProvider(ctx context.Context, p APIProvider) (APIProvider, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.Kind = strings.TrimSpace(p.Kind)
	if p.Name == "" {
		return APIProvider{}, ErrProviderNameRequired
	}
	if p.Kind == "" {
		return APIProvider{}, ErrProviderKindRequired
	}
	p.ID = NewID("apr")
	applyProviderDefaults(&p)
	now := unixMilli(time.Now())
	res, err := s.db.ExecContext(ctx, `INSERT INTO api_providers
		(id,name,kind,enabled,capabilities,config,timeout_ms,rate_per_minute,cache_ttl_seconds,policy_scope,created_at,updated_at)
		SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM api_providers) < 64`,
		p.ID, p.Name, p.Kind, p.Enabled, encodeJSON(p.Capabilities), encodeStringMap(p.Config), p.TimeoutMS, p.RatePerMinute, p.CacheTTLSeconds, encodeJSON(p.PolicyScope), now, now)
	if err != nil {
		return APIProvider{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return APIProvider{}, err
	}
	if n == 0 {
		return APIProvider{}, ErrProviderLimit
	}
	p.CreatedAt, p.UpdatedAt = fromUnixMilli(now), fromUnixMilli(now)
	return p, nil
}

// SetIntegrationSettings persists a coherent mode/enrichment choice. A crash
// between two individual settings writes must not enable only half a request.
func (s *Store) SetIntegrationSettings(ctx context.Context, mode string, enrichment bool) error {
	if _, valid := integrationModeRank(mode); !valid {
		return errors.New("invalid integration reputation mode")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := saveIntegrationPreferences(ctx, tx, mode, enrichment); err != nil {
		return err
	}
	return tx.Commit()
}

func saveIntegrationPreferences(ctx context.Context, tx *sql.Tx, mode string, enrichment bool) error {
	enrich := "false"
	if enrichment {
		enrich = "true"
	}
	// The version marker is atomic with the two choices. It proves a new UI
	// write or the migration has already reconciled the legacy YAML gates.
	for _, pair := range [][2]string{{"integrations.reputation_mode", mode}, {"integrations.enrichment", enrich}, {IntegrationPreferencesVersionKey, "1"}} {
		if _, err := tx.ExecContext(ctx, "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", pair[0], pair[1]); err != nil {
			return err
		}
	}
	return nil
}

func integrationModeRank(mode string) (int, bool) {
	switch mode {
	case "off":
		return 0, true
	case "cache_only":
		return 1, true
	case "blocking":
		return 2, true
	default:
		return 0, false
	}
}

// InitializeIntegrationSettings captures the OLD effective state exactly once.
// Before this feature YAML disabled the engine or capped a saved reputation
// choice. Treating that old saved choice as a new UI override could silently
// start sharing on upgrade. Every failure returns an explicitly inert state.
func (s *Store) InitializeIntegrationSettings(ctx context.Context, legacyEnabled bool, legacyMode string, legacyEnrichment bool) (string, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "off", false, err
	}
	defer tx.Rollback() //nolint:errcheck
	rows, err := tx.QueryContext(ctx, "SELECT key,value FROM settings WHERE key IN ('integrations.reputation_mode','integrations.enrichment','integrations.ui_preferences_v1')")
	if err != nil {
		return "off", false, err
	}
	values := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			rows.Close()
			return "off", false, err
		}
		values[key] = value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "off", false, err
	}
	if version, marked := values[IntegrationPreferencesVersionKey]; marked {
		mode := values["integrations.reputation_mode"]
		enrich := values["integrations.enrichment"]
		_, valid := integrationModeRank(mode)
		if version != "1" || !valid || (enrich != "true" && enrich != "false") {
			return "off", false, errors.New("saved external API preferences are invalid; sharing remains off until an explicit settings save")
		}
		if err := tx.Commit(); err != nil {
			return "off", false, err
		}
		return mode, enrich == "true", nil
	}
	mode := "off"
	enrichment := false
	if legacyEnabled {
		ceilingRank, valid := integrationModeRank(legacyMode)
		if !valid {
			legacyMode = "off"
		}
		mode = legacyMode
		if savedRank, savedValid := integrationModeRank(values["integrations.reputation_mode"]); savedValid && savedRank <= ceilingRank {
			mode = values["integrations.reputation_mode"]
		}
		// The old engine also prevented enrichment while reputation was off.
		enrichment = legacyEnrichment && mode != "off"
	}
	if err := saveIntegrationPreferences(ctx, tx, mode, enrichment); err != nil {
		return "off", false, err
	}
	if err := tx.Commit(); err != nil {
		return "off", false, err
	}
	return mode, enrichment, nil
}

// RetireLegacyObservatory preserves the historical feed row and evidence but
// removes the old bundled service from all scheduled downloads and indexes.
// Only the original built-in identity is affected; ordinary custom feeds stay
// under the operator's control, including compatible JSON indicator feeds.
func (s *Store) RetireLegacyObservatory(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE feeds SET enabled = 0, updated_at = ?
		WHERE id = 'dnsdaddy-observatory' AND builtin = 1 AND enabled <> 0`, time.Now().UnixMilli())
	return err
}

func RetiredBuiltinFeed(f Feed) bool { return f.Builtin && f.ID == "dnsdaddy-observatory" }
