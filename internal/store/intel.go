package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Disposition is a provider's judgement, normalised.
//
// Four values rather than a bare score, because the score alone cannot express
// the difference that matters most: "this provider says nothing is known about
// this domain" and "this provider says this domain is fine" are both a low
// score and only one of them is evidence. DispositionUnknown is the answer for
// a lookup that has not happened, failed, or came back empty — and it never
// blocks anything.
type Disposition string

const (
	DispositionUnknown    Disposition = "unknown"
	DispositionBenign     Disposition = "benign"
	DispositionSuspicious Disposition = "suspicious"
	DispositionMalicious  Disposition = "malicious"
)

// Valid reports whether d is a disposition this system emits. Anything else
// arriving from a database row or an adapter is treated as unknown.
func (d Disposition) Valid() bool {
	switch d {
	case DispositionUnknown, DispositionBenign, DispositionSuspicious, DispositionMalicious:
		return true
	}
	return false
}

// IntelVerdict is one provider's answer about one subject, as cached.
type IntelVerdict struct {
	Subject     string      `json:"subject"`
	ProviderID  string      `json:"providerId"`
	Score       float64     `json:"score"`
	Disposition Disposition `json:"disposition"`
	Categories  []string    `json:"categories"`
	// Raw is a bounded excerpt of what the provider actually said, so an
	// operator can check our normalisation rather than trust it.
	Raw       string    `json:"raw,omitempty"`
	FetchedAt time.Time `json:"fetchedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Fresh reports whether the verdict is still within its TTL at t.
func (v IntelVerdict) Fresh(t time.Time) bool { return t.Before(v.ExpiresAt) }

// maxRawExcerpt bounds what is kept of a provider's response.
//
// A provider is untrusted input. Without a cap, a service returning a
// multi-megabyte document per domain would grow the database at the rate the
// network resolves names — which is a denial of service delivered through a
// feature the operator switched on for safety.
const maxRawExcerpt = 4096

// PutIntelVerdict caches a verdict, replacing any previous one for the pair.
func (s *Store) PutIntelVerdict(ctx context.Context, v IntelVerdict) error {
	if v.Subject == "" || v.ProviderID == "" {
		return errors.New("verdict needs a subject and a provider")
	}
	if !v.Disposition.Valid() {
		v.Disposition = DispositionUnknown
	}
	// Clamped here as well as in the adapter. The adapter is where a hostile
	// score is meant to be caught; this is the layer that has to hold if an
	// adapter forgets, because everything downstream compares against a
	// threshold and a score of 1e9 would clear any of them.
	if v.Score < 0 {
		v.Score = 0
	}
	if v.Score > 1 {
		v.Score = 1
	}
	if len(v.Raw) > maxRawExcerpt {
		v.Raw = v.Raw[:maxRawExcerpt]
	}

	const q = `
		INSERT INTO intel_verdicts
		  (subject, provider_id, score, disposition, categories, raw, fetched_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (subject, provider_id) DO UPDATE SET
		  score = excluded.score, disposition = excluded.disposition,
		  categories = excluded.categories, raw = excluded.raw,
		  fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`
	_, err := s.db.ExecContext(ctx, q,
		v.Subject, v.ProviderID, v.Score, string(v.Disposition),
		encodeJSON(nonNil(v.Categories)), v.Raw,
		unixMilli(v.FetchedAt), unixMilli(v.ExpiresAt))
	return err
}

// IntelVerdicts returns every cached verdict for a subject, expired ones
// included.
//
// Expiry is the caller's decision, not this layer's. A stale verdict is still
// worth showing an operator investigating a domain — labelled as stale — and
// hiding it here would mean the only way to see it is to ask a paid API again.
func (s *Store) IntelVerdicts(ctx context.Context, subject string) ([]IntelVerdict, error) {
	const q = `
		SELECT subject, provider_id, score, disposition, categories, raw, fetched_at, expires_at
		  FROM intel_verdicts WHERE subject = ?
		 ORDER BY fetched_at DESC`
	rows, err := s.db.QueryContext(ctx, q, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IntelVerdict
	for rows.Next() {
		var (
			v                IntelVerdict
			disp, cats       string
			fetched, expires int64
		)
		if err := rows.Scan(&v.Subject, &v.ProviderID, &v.Score, &disp, &cats,
			&v.Raw, &fetched, &expires); err != nil {
			return nil, err
		}
		v.Disposition = Disposition(disp)
		if !v.Disposition.Valid() {
			v.Disposition = DispositionUnknown
		}
		v.Categories = decodeStrings(cats)
		v.FetchedAt = fromUnixMilli(fetched)
		v.ExpiresAt = fromUnixMilli(expires)
		out = append(out, v)
	}
	return out, rows.Err()
}

// IntelVerdict returns one provider's cached answer, or ErrNotFound.
func (s *Store) IntelVerdict(ctx context.Context, subject, providerID string) (IntelVerdict, error) {
	const q = `
		SELECT subject, provider_id, score, disposition, categories, raw, fetched_at, expires_at
		  FROM intel_verdicts WHERE subject = ? AND provider_id = ?`
	var (
		v                IntelVerdict
		disp, cats       string
		fetched, expires int64
	)
	err := s.db.QueryRowContext(ctx, q, subject, providerID).
		Scan(&v.Subject, &v.ProviderID, &v.Score, &disp, &cats, &v.Raw, &fetched, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return IntelVerdict{}, ErrNotFound
	}
	if err != nil {
		return IntelVerdict{}, err
	}
	v.Disposition = Disposition(disp)
	if !v.Disposition.Valid() {
		v.Disposition = DispositionUnknown
	}
	v.Categories = decodeStrings(cats)
	v.FetchedAt = fromUnixMilli(fetched)
	v.ExpiresAt = fromUnixMilli(expires)
	return v, nil
}

// IntelEnrichment is context attached to a subject. Never a judgement.
type IntelEnrichment struct {
	Subject    string            `json:"subject"`
	ProviderID string            `json:"providerId"`
	Data       map[string]string `json:"data"`
	FetchedAt  time.Time         `json:"fetchedAt"`
	ExpiresAt  time.Time         `json:"expiresAt"`
}

// maxEnrichmentFields and maxEnrichmentValue bound what a provider can attach.
//
// Same reasoning as maxRawExcerpt: this is a document from a third party,
// written to disk once per resolved name. Both limits are generous for real
// enrichment and fatal to a provider trying to use the cache as storage.
const (
	maxEnrichmentFields = 32
	maxEnrichmentValue  = 512
)

// PutIntelEnrichment caches enrichment, trimming it to the documented bounds.
func (s *Store) PutIntelEnrichment(ctx context.Context, e IntelEnrichment) error {
	if e.Subject == "" || e.ProviderID == "" {
		return errors.New("enrichment needs a subject and a provider")
	}

	trimmed := make(map[string]string, len(e.Data))
	for k, v := range e.Data {
		if len(trimmed) >= maxEnrichmentFields {
			break
		}
		if len(v) > maxEnrichmentValue {
			v = v[:maxEnrichmentValue]
		}
		trimmed[k] = v
	}

	const q = `
		INSERT INTO intel_enrichment (subject, provider_id, data, fetched_at, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (subject, provider_id) DO UPDATE SET
		  data = excluded.data, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`
	_, err := s.db.ExecContext(ctx, q, e.Subject, e.ProviderID,
		encodeStringMap(trimmed), unixMilli(e.FetchedAt), unixMilli(e.ExpiresAt))
	return err
}

// IntelEnrichments returns every provider's enrichment for a subject.
func (s *Store) IntelEnrichments(ctx context.Context, subject string) ([]IntelEnrichment, error) {
	const q = `
		SELECT subject, provider_id, data, fetched_at, expires_at
		  FROM intel_enrichment WHERE subject = ? ORDER BY fetched_at DESC`
	rows, err := s.db.QueryContext(ctx, q, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IntelEnrichment
	for rows.Next() {
		var (
			e                IntelEnrichment
			data             string
			fetched, expires int64
		)
		if err := rows.Scan(&e.Subject, &e.ProviderID, &data, &fetched, &expires); err != nil {
			return nil, err
		}
		e.Data = decodeStringMap(data)
		e.FetchedAt = fromUnixMilli(fetched)
		e.ExpiresAt = fromUnixMilli(expires)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneIntel deletes cache rows that expired before cutoff, and reports how
// many went.
//
// Run on the same schedule as the query-log prune. Without it the two cache
// tables are the only unbounded growth in the database, because every new
// domain the network resolves adds a row that nothing else removes.
func (s *Store) PruneIntel(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for _, table := range []string{"intel_verdicts", "intel_enrichment"} {
		res, err := s.db.ExecContext(ctx,
			"DELETE FROM "+table+" WHERE expires_at < ?", unixMilli(cutoff))
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// CountIntelRows reports how many verdicts and enrichments are cached, for the
// dashboard and for `doctor`.
func (s *Store) CountIntelRows(ctx context.Context) (verdicts, enrichments int64, err error) {
	if err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM intel_verdicts").Scan(&verdicts); err != nil {
		return 0, 0, err
	}
	if err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM intel_enrichment").Scan(&enrichments); err != nil {
		return 0, 0, err
	}
	return verdicts, enrichments, nil
}
