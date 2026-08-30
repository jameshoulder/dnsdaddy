package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Dashboard session storage.
//
// A session is an opaque 256-bit random value held only by the browser. The
// server stores its SHA-256 and the two timestamps that bound it, which is
// what makes revocation possible at all: with a self-contained signed cookie
// there is no row to delete, so "log out" is a request to the client and
// nothing more.
//
// What this buys, concretely:
//
//	logout            deletes the row; the cookie is dead on the next request
//	password change   deletes every row; every other browser is signed out
//	key compromise    there is no key — a stolen database yields hashes, and
//	                  a hash is not a cookie
//
// What it does not buy: an attacker who steals a live cookie is still that
// session until it expires or is revoked. Nothing short of binding the session
// to something the attacker cannot copy fixes that, and this is a self-hosted
// dashboard, not a bank.

// SessionTokenBytes is the entropy in a session token.
const SessionTokenBytes = 32

// hashSessionToken is the one place the stored form is derived, so a lookup
// and an insert can never disagree about it.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateSession issues a new session and returns the secret to put in the
// cookie. The secret is not recoverable afterwards.
func (s *Store) CreateSession(ctx context.Context, ttl time.Duration, label string) (string, error) {
	raw := make([]byte, SessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, created_at, expires_at, last_seen, label)
		 VALUES (?, ?, ?, ?, ?)`,
		hashSessionToken(token), now.Unix(), now.Add(ttl).Unix(), now.Unix(), label)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// LookupSession reports whether a session token is currently valid.
//
// Expiry is enforced in the WHERE clause rather than by reading the row and
// comparing afterwards: there is then no branch in which an expired session is
// briefly treated as live, and no way for a later edit to drop the comparison
// while leaving the query looking correct.
func (s *Store) LookupSession(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	var label string
	err := s.db.QueryRowContext(ctx,
		`SELECT label FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		hashSessionToken(token), time.Now().Unix()).Scan(&label)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("look up session: %w", err)
	}
	return true, nil
}

// TouchSession records that a session was used.
//
// Best-effort and deliberately not part of the authentication decision: this
// is one write per authenticated request, and a failed write must not log
// anybody out. It exists so an operator can see which sessions are live.
func (s *Store) TouchSession(ctx context.Context, token string) {
	if token == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen = ? WHERE token_hash = ?`,
		time.Now().Unix(), hashSessionToken(token))
}

// DeleteSession revokes one session. Logging out is exactly this.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE token_hash = ?`, hashSessionToken(token))
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteAllSessions revokes every session and reports how many it removed.
//
// Called on a password change, which is the moment an operator most often
// means "and get whoever it was out". A password change that left the
// attacker's session working would be a change that did nothing.
func (s *Store) DeleteAllSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions`)
	if err != nil {
		return 0, fmt.Errorf("delete all sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil // the deletion happened; only the count is unavailable
	}
	return n, nil
}

// PurgeExpiredSessions removes rows past their expiry.
//
// Housekeeping only. An expired row is already refused by LookupSession, so
// this changes no security decision — it stops the table growing without
// bound on a dashboard that is opened daily for a year.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("purge expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CountSessions returns the number of live sessions.
func (s *Store) CountSessions(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE expires_at > ?`, time.Now().Unix()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	return n, nil
}
