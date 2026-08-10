package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TokenPrefix is the identifiable prefix on every DNS Daddy API token. Secret
// scanners key off it, and it makes a leaked token obvious in a log.
const TokenPrefix = "dnsd_"

// ListAPITokens returns token metadata. Secrets are never stored in a
// recoverable form, so they are not returned here.
func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, prefix, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []APIToken
	for rows.Next() {
		var (
			t        APIToken
			created  int64
			lastUsed *int64
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &created, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt = fromUnixMilli(created)
		if lastUsed != nil {
			u := fromUnixMilli(*lastUsed)
			t.LastUsedAt = &u
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateAPIToken mints a token. The returned APIToken carries the plaintext
// secret; it is the only time the caller can see it.
func (s *Store) CreateAPIToken(ctx context.Context, name string) (APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return APIToken{}, fmt.Errorf("token name is required")
	}

	secret := TokenPrefix + NewToken(24)
	sum := sha256.Sum256([]byte(secret))
	id := NewID("tok")
	now := unixMilli(time.Now())
	// Enough of the secret to recognise it in a list, not enough to use it.
	prefix := secret[:len(TokenPrefix)+6]

	if _, err := s.db.ExecContext(ctx,
		"INSERT INTO api_tokens (id, name, hash, prefix, created_at) VALUES (?, ?, ?, ?, ?)",
		id, name, hex.EncodeToString(sum[:]), prefix, now); err != nil {
		return APIToken{}, err
	}

	return APIToken{
		ID:        id,
		Name:      name,
		Prefix:    prefix,
		CreatedAt: fromUnixMilli(now),
		Secret:    secret,
	}, nil
}

// DeleteAPIToken revokes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM api_tokens WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// VerifyAPIToken checks a presented secret and records its use. It compares
// hashes in constant time so that a timing side channel cannot be used to
// recover a valid token byte by byte.
func (s *Store) VerifyAPIToken(ctx context.Context, secret string) (APIToken, error) {
	if !strings.HasPrefix(secret, TokenPrefix) {
		return APIToken{}, ErrNotFound
	}
	sum := sha256.Sum256([]byte(secret))
	want := hex.EncodeToString(sum[:])

	rows, err := s.db.QueryContext(ctx, "SELECT id, name, prefix, hash, created_at FROM api_tokens")
	if err != nil {
		return APIToken{}, err
	}
	defer rows.Close()

	var match APIToken
	found := false
	for rows.Next() {
		var (
			t       APIToken
			hash    string
			created int64
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &hash, &created); err != nil {
			return APIToken{}, err
		}
		if subtle.ConstantTimeCompare([]byte(hash), []byte(want)) == 1 {
			t.CreatedAt = fromUnixMilli(created)
			match = t
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return APIToken{}, err
	}
	if !found {
		return APIToken{}, ErrNotFound
	}

	if _, err := s.db.ExecContext(ctx, "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
		unixMilli(time.Now()), match.ID); err != nil {
		return APIToken{}, err
	}
	return match, nil
}

// NetworkByToken resolves a per-network DoH/DoT token to its network ID.
func (s *Store) NetworkByToken(ctx context.Context, token string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		"SELECT id FROM networks WHERE token = ? AND enabled = 1", strings.ToLower(token)).Scan(&id)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return id, err
}
