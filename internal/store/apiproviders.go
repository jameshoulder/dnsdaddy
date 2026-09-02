package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// APIProvider is an external intelligence service an operator has configured.
//
// It carries no credential, by construction: the secret lives in a separate
// table and is only ever reachable through OpenProviderSecret, which takes a
// keyring. That means no amount of carelessness with this struct — logging it,
// serialising it into a debug endpoint, dumping it in an error — can disclose
// one. See docs/external-apis.md.
type APIProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind names the adapter in the apiprovider registry.
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	// Capabilities is the subset the operator switched on. Enabling a provider
	// and letting it influence resolution are separate decisions.
	Capabilities []string `json:"capabilities"`
	// Config is adapter-specific and never secret.
	Config          map[string]string `json:"config"`
	TimeoutMS       int               `json:"timeoutMs"`
	RatePerMinute   int               `json:"ratePerMinute"`
	CacheTTLSeconds int               `json:"cacheTtlSeconds"`
	// PolicyScope limits the provider to named policies. Empty means all.
	PolicyScope []string `json:"policyScope"`

	// SecretSet and SecretHint describe the stored credential without being
	// it. The hint is the last four characters, which is what a vendor console
	// shows and far too little to narrow a search for the rest.
	SecretSet   bool       `json:"secretSet"`
	SecretHint  string     `json:"secretHint"`
	SecretKeyID string     `json:"-"` // which keyring key sealed it
	RotatedAt   *time.Time `json:"rotatedAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Defaults applied when a caller leaves a bound unset. Chosen for a resolver
// on a small VPS: a short timeout because nothing should wait on a third
// party, a modest rate because most free tiers are metered, and a six-hour TTL
// because reputation moves in hours, not seconds.
const (
	DefaultProviderTimeoutMS  = 2000
	DefaultProviderRate       = 60
	DefaultProviderCacheTTLS  = 6 * 3600
	maxProviderTimeoutMS      = 15000
	maxProviderRatePerMinute  = 6000
	maxProviderCacheTTLSecond = 30 * 24 * 3600
)

// ErrProviderKindRequired and friends are validation failures the API layer
// turns into 400s.
var (
	ErrProviderNameRequired = errors.New("provider name is required")
	ErrProviderKindRequired = errors.New("provider kind is required")
)

// ListAPIProviders returns every configured provider, newest last so the
// dashboard's card order is stable as providers are added.
func (s *Store) ListAPIProviders(ctx context.Context) ([]APIProvider, error) {
	const q = `
		SELECT p.id, p.name, p.kind, p.enabled, p.capabilities, p.config,
		       p.timeout_ms, p.rate_per_minute, p.cache_ttl_seconds, p.policy_scope,
		       p.created_at, p.updated_at,
		       s.hint, s.key_id, s.rotated_at
		  FROM api_providers p
		  LEFT JOIN api_provider_secrets s ON s.provider_id = p.id
		 ORDER BY p.created_at ASC`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []APIProvider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetAPIProvider returns one provider, or ErrNotFound.
func (s *Store) GetAPIProvider(ctx context.Context, id string) (APIProvider, error) {
	const q = `
		SELECT p.id, p.name, p.kind, p.enabled, p.capabilities, p.config,
		       p.timeout_ms, p.rate_per_minute, p.cache_ttl_seconds, p.policy_scope,
		       p.created_at, p.updated_at,
		       s.hint, s.key_id, s.rotated_at
		  FROM api_providers p
		  LEFT JOIN api_provider_secrets s ON s.provider_id = p.id
		 WHERE p.id = ?`
	p, err := scanProvider(s.db.QueryRowContext(ctx, q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return APIProvider{}, ErrNotFound
	}
	return p, err
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so the column list
// above is written once. Getting it wrong in one of two near-identical copies
// is a bug that compiles.
type rowScanner interface{ Scan(dest ...any) error }

func scanProvider(sc rowScanner) (APIProvider, error) {
	var (
		p                APIProvider
		caps, cfg, scope string
		created, updated int64
		hint, keyID      sql.NullString
		rotated          sql.NullInt64
		enabled          int
	)
	if err := sc.Scan(&p.ID, &p.Name, &p.Kind, &enabled, &caps, &cfg,
		&p.TimeoutMS, &p.RatePerMinute, &p.CacheTTLSeconds, &scope,
		&created, &updated, &hint, &keyID, &rotated); err != nil {
		return APIProvider{}, err
	}

	p.Enabled = enabled != 0
	p.Capabilities = decodeStrings(caps)
	p.PolicyScope = decodeStrings(scope)
	p.Config = decodeStringMap(cfg)
	p.CreatedAt = fromUnixMilli(created)
	p.UpdatedAt = fromUnixMilli(updated)

	// A secret row existing is what "SecretSet" means. The hint may be empty
	// for a credential too short to hint at, so it cannot stand in for it.
	p.SecretSet = hint.Valid || keyID.Valid
	p.SecretHint = hint.String
	p.SecretKeyID = keyID.String
	if rotated.Valid {
		t := fromUnixMilli(rotated.Int64)
		p.RotatedAt = &t
	}
	return p, nil
}

// CreateAPIProvider inserts a provider. The credential is stored separately by
// SetProviderSecret; this deliberately does not take one, so that the code
// path which writes configuration and the one which writes credentials cannot
// be confused for each other.
func (s *Store) CreateAPIProvider(ctx context.Context, p APIProvider) (APIProvider, error) {
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
	const q = `
		INSERT INTO api_providers
		  (id, name, kind, enabled, capabilities, config,
		   timeout_ms, rate_per_minute, cache_ttl_seconds, policy_scope,
		   created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, q,
		p.ID, p.Name, p.Kind, boolToInt(p.Enabled),
		encodeJSON(p.Capabilities), encodeStringMap(p.Config),
		p.TimeoutMS, p.RatePerMinute, p.CacheTTLSeconds, encodeJSON(p.PolicyScope),
		now, now); err != nil {
		return APIProvider{}, err
	}
	p.CreatedAt = fromUnixMilli(now)
	p.UpdatedAt = fromUnixMilli(now)
	return p, nil
}

// APIProviderUpdate carries the fields a PATCH may change. Pointers so that
// "not mentioned" and "set to the zero value" are different requests —
// disabling a provider and not mentioning enabled must not be the same thing.
type APIProviderUpdate struct {
	Name            *string
	Enabled         *bool
	Capabilities    *[]string
	Config          *map[string]string
	TimeoutMS       *int
	RatePerMinute   *int
	CacheTTLSeconds *int
	PolicyScope     *[]string
}

// UpdateAPIProvider applies a partial update.
//
// Kind is deliberately absent: changing the adapter under a stored credential
// would send a VirusTotal key to Safe Browsing on the next lookup. Switching
// service means creating a provider and deleting the old one, which also makes
// the operator re-enter the credential — the correct amount of friction.
func (s *Store) UpdateAPIProvider(ctx context.Context, id string, up APIProviderUpdate) (APIProvider, error) {
	cur, err := s.GetAPIProvider(ctx, id)
	if err != nil {
		return APIProvider{}, err
	}

	if up.Name != nil {
		name := strings.TrimSpace(*up.Name)
		if name == "" {
			return APIProvider{}, ErrProviderNameRequired
		}
		cur.Name = name
	}
	if up.Enabled != nil {
		cur.Enabled = *up.Enabled
	}
	if up.Capabilities != nil {
		cur.Capabilities = *up.Capabilities
	}
	if up.Config != nil {
		cur.Config = *up.Config
	}
	if up.TimeoutMS != nil {
		cur.TimeoutMS = *up.TimeoutMS
	}
	if up.RatePerMinute != nil {
		cur.RatePerMinute = *up.RatePerMinute
	}
	if up.CacheTTLSeconds != nil {
		cur.CacheTTLSeconds = *up.CacheTTLSeconds
	}
	if up.PolicyScope != nil {
		cur.PolicyScope = *up.PolicyScope
	}
	applyProviderDefaults(&cur)

	now := unixMilli(time.Now())
	const q = `
		UPDATE api_providers
		   SET name = ?, enabled = ?, capabilities = ?, config = ?,
		       timeout_ms = ?, rate_per_minute = ?, cache_ttl_seconds = ?,
		       policy_scope = ?, updated_at = ?
		 WHERE id = ?`
	if _, err := s.db.ExecContext(ctx, q,
		cur.Name, boolToInt(cur.Enabled), encodeJSON(cur.Capabilities),
		encodeStringMap(cur.Config), cur.TimeoutMS, cur.RatePerMinute,
		cur.CacheTTLSeconds, encodeJSON(cur.PolicyScope), now, id); err != nil {
		return APIProvider{}, err
	}
	cur.UpdatedAt = fromUnixMilli(now)
	return cur, nil
}

// DeleteAPIProvider removes a provider, its credential, and everything cached
// under it.
//
// The secret and cache rows carry ON DELETE CASCADE, but foreign keys are only
// enforced when the pragma is on — which it is for the daemon and might not be
// for a future tool. Deleting explicitly means a stale ciphertext cannot
// outlive the provider it belonged to whatever the pragma says.
func (s *Store) DeleteAPIProvider(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit

	for _, q := range []string{
		"DELETE FROM api_provider_secrets WHERE provider_id = ?",
		"DELETE FROM intel_verdicts WHERE provider_id = ?",
		"DELETE FROM intel_enrichment WHERE provider_id = ?",
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}

	res, err := tx.ExecContext(ctx, "DELETE FROM api_providers WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// applyProviderDefaults fills unset bounds and clamps hostile ones.
//
// Clamped rather than rejected: these arrive from a dashboard form, and an
// operator who typed 300000 into a timeout box wants a long timeout, not an
// error. What they must not get is a value that lets one provider hold a
// worker for five minutes.
func applyProviderDefaults(p *APIProvider) {
	if p.TimeoutMS <= 0 {
		p.TimeoutMS = DefaultProviderTimeoutMS
	}
	if p.TimeoutMS > maxProviderTimeoutMS {
		p.TimeoutMS = maxProviderTimeoutMS
	}
	if p.RatePerMinute <= 0 {
		p.RatePerMinute = DefaultProviderRate
	}
	if p.RatePerMinute > maxProviderRatePerMinute {
		p.RatePerMinute = maxProviderRatePerMinute
	}
	if p.CacheTTLSeconds <= 0 {
		p.CacheTTLSeconds = DefaultProviderCacheTTLS
	}
	if p.CacheTTLSeconds > maxProviderCacheTTLSecond {
		p.CacheTTLSeconds = maxProviderCacheTTLSecond
	}
	if p.Capabilities == nil {
		p.Capabilities = []string{}
	}
	if p.PolicyScope == nil {
		p.PolicyScope = []string{}
	}
	if p.Config == nil {
		p.Config = map[string]string{}
	}
}

// SetProviderSecret stores a sealed credential.
//
// It takes ciphertext, not a plaintext and a keyring: sealing belongs to the
// caller that knows the plaintext, and keeping it out of the store means there
// is no code path in this package that has ever held a decrypted credential.
// hint must already be derived — secrets.Hint does it — for the same reason.
func (s *Store) SetProviderSecret(ctx context.Context, providerID string, ciphertext []byte, keyID, hint string) error {
	if len(ciphertext) == 0 {
		return fmt.Errorf("refusing to store an empty credential for %s", providerID)
	}
	now := unixMilli(time.Now())

	// The rotation timestamp survives an upsert, so "when was this last
	// changed" keeps meaning something across a rotation.
	const q = `
		INSERT INTO api_provider_secrets (provider_id, ciphertext, key_id, hint, created_at, rotated_at)
		VALUES (?, ?, ?, ?, ?, NULL)
		ON CONFLICT (provider_id) DO UPDATE SET
		  ciphertext = excluded.ciphertext,
		  key_id     = excluded.key_id,
		  hint       = excluded.hint,
		  rotated_at = ?`
	_, err := s.db.ExecContext(ctx, q, providerID, ciphertext, keyID, hint, now, now)
	return err
}

// ProviderSecretCiphertext returns the sealed credential, or ErrNotFound.
//
// Named for what it returns. A method called GetProviderSecret would read at
// the call site as though it hands back something usable, and the whole point
// is that nothing in this package can.
func (s *Store) ProviderSecretCiphertext(ctx context.Context, providerID string) ([]byte, error) {
	var ct []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT ciphertext FROM api_provider_secrets WHERE provider_id = ?", providerID).Scan(&ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return ct, err
}

// DeleteProviderSecret removes a stored credential, leaving the provider.
func (s *Store) DeleteProviderSecret(ctx context.Context, providerID string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM api_provider_secrets WHERE provider_id = ?", providerID)
	return err
}

func encodeStringMap(m map[string]string) string {
	if m == nil {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func decodeStringMap(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]string{}
	}
	return out
}
