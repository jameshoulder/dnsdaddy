package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// DomainFirstSeen is one retention-independent observation of a registered
// domain (eTLD+1). It is local observation, not threat intelligence and not
// WHOIS registration age.
type DomainFirstSeen struct {
	RegisteredDomain string    `json:"registeredDomain"`
	FirstSeen        time.Time `json:"firstSeen"`
	LastSeen         time.Time `json:"lastSeen"`
	QueryCount       int64     `json:"queryCount"`
}

// ObserveRegisteredDomain upserts the first-seen index for one eTLD+1.
//
// first_seen is preserved on conflict; last_seen and query_count advance.
func (s *Store) ObserveRegisteredDomain(ctx context.Context, registeredDomain string, at time.Time) error {
	registeredDomain = strings.ToLower(strings.TrimSpace(registeredDomain))
	if registeredDomain == "" {
		return nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ms := unixMilli(at)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO domain_first_seen (registered_domain, first_seen, last_seen, query_count)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(registered_domain) DO UPDATE SET
			last_seen = MAX(domain_first_seen.last_seen, excluded.last_seen),
			query_count = domain_first_seen.query_count + 1`,
		registeredDomain, ms, ms)
	return err
}

// LookupRegisteredDomain returns the durable first-seen row for an eTLD+1.
func (s *Store) LookupRegisteredDomain(ctx context.Context, registeredDomain string) (DomainFirstSeen, error) {
	registeredDomain = strings.ToLower(strings.TrimSpace(registeredDomain))
	const q = `
		SELECT registered_domain, first_seen, last_seen, query_count
		  FROM domain_first_seen WHERE registered_domain = ?`
	var (
		out         DomainFirstSeen
		first, last int64
	)
	err := s.db.QueryRowContext(ctx, q, registeredDomain).Scan(
		&out.RegisteredDomain, &first, &last, &out.QueryCount)
	if errors.Is(err, sql.ErrNoRows) {
		return DomainFirstSeen{}, ErrNotFound
	}
	if err != nil {
		return DomainFirstSeen{}, err
	}
	out.FirstSeen = fromUnixMilli(first)
	out.LastSeen = fromUnixMilli(last)
	return out, nil
}

// CountRegisteredDomains reports how many eTLD+1 rows the index holds.
func (s *Store) CountRegisteredDomains(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domain_first_seen`).Scan(&n)
	return n, err
}
