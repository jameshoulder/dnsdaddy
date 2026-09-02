package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
)

// maxEvidenceDetail bounds the source-supplied blob.
//
// Detail carries a third party's response or a detector's signals, so it is
// attacker-influenced in the same sense the provider excerpt is. 8 KiB is
// generous for a set of signals and small enough that a hostile provider
// cannot fill the disk one evidence row at a time.
const maxEvidenceDetail = 8 << 10

// PutEvidence records or refreshes one claim.
//
// Upsert rather than insert, keyed on (subject, source, claim). A feed that
// lists the same domain at every refresh should move its observation forward,
// not accumulate a row an hour — that is the difference between a store of
// what is known and a log of when we looked.
//
// The first observation time is preserved on refresh. "First seen three weeks
// ago, confirmed twelve minutes ago" is a more useful thing to be able to say
// than either half alone.
func (s *Store) PutEvidence(ctx context.Context, e evidence.Evidence) (evidence.Evidence, error) {
	if err := e.Validate(); err != nil {
		return evidence.Evidence{}, err
	}
	if e.ID == "" {
		e.ID = NewID("ev")
	}

	detail := "{}"
	if len(e.Detail) > 0 {
		if b, err := json.Marshal(e.Detail); err == nil && len(b) <= maxEvidenceDetail {
			detail = string(b)
		}
		// A detail blob that will not marshal, or is over the cap, is dropped
		// rather than failing the write. The claim is the load-bearing part;
		// losing an oversized appendix must not lose the fact that a source
		// said something.
	}

	var expires any
	if e.ExpiresAt != nil {
		expires = unixMilli(*e.ExpiresAt)
	}

	const q = `
		INSERT INTO evidence
			(id, subject_type, subject, kind, source, source_name, claim,
			 category, confidence, observed_at, expires_at, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(subject_type, subject, source, claim) DO UPDATE SET
			source_name = excluded.source_name,
			category    = excluded.category,
			confidence  = excluded.confidence,
			expires_at  = excluded.expires_at,
			detail      = excluded.detail,
			-- observed_at is deliberately NOT updated: it is when this claim
			-- was first made, and a refresh confirms it rather than restarting
			-- its history.
			kind        = excluded.kind`
	if _, err := s.db.ExecContext(ctx, q,
		e.ID, string(e.Subject.Type), e.Subject.Value, string(e.Kind),
		e.Source, e.SourceName, e.Claim, e.Category, string(e.Confidence),
		unixMilli(e.ObservedAt), expires, detail); err != nil {
		return evidence.Evidence{}, err
	}

	// Read back, so the caller gets the stored row rather than its own input —
	// on a refresh the ID and observed time are the existing row's, not the
	// ones just offered.
	return s.evidenceFor(ctx, e.Subject, e.Source, e.Claim)
}

// evidenceFor reads the single row identified by a subject, source and claim.
func (s *Store) evidenceFor(ctx context.Context, subj evidence.Subject, source, claim string) (evidence.Evidence, error) {
	const q = `
		SELECT id, subject_type, subject, kind, source, source_name, claim,
		       category, confidence, observed_at, expires_at, detail
		  FROM evidence
		 WHERE subject_type = ? AND subject = ? AND source = ? AND claim = ?`
	row := s.db.QueryRowContext(ctx, q, string(subj.Type), subj.Value, source, claim)
	e, err := scanEvidence(row)
	if errors.Is(err, sql.ErrNoRows) {
		return evidence.Evidence{}, ErrNotFound
	}
	return e, err
}

// EvidenceFor returns everything on file about a subject, newest first.
//
// Expired rows are returned rather than filtered. Deciding what to do with an
// expired claim is the assessment's job — evidence.Assess excludes it — and an
// investigation view legitimately wants to show "this was listed until
// Tuesday", which a store-level filter would make impossible.
func (s *Store) EvidenceFor(ctx context.Context, subj evidence.Subject) ([]evidence.Evidence, error) {
	const q = `
		SELECT id, subject_type, subject, kind, source, source_name, claim,
		       category, confidence, observed_at, expires_at, detail
		  FROM evidence
		 WHERE subject_type = ? AND subject = ?
		 ORDER BY observed_at DESC`
	rows, err := s.db.QueryContext(ctx, q, string(subj.Type), subj.Value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]evidence.Evidence, 0, 8)
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EvidenceByID returns specific rows, in the order requested.
//
// Used by the decision path to rehydrate exactly the evidence a decision cited,
// which is why it is by ID rather than by subject: the subject's evidence may
// have changed since, and an explanation must show what was there at the time.
func (s *Store) EvidenceByID(ctx context.Context, ids []string) ([]evidence.Evidence, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	found := make(map[string]evidence.Evidence, len(ids))
	const q = `
		SELECT id, subject_type, subject, kind, source, source_name, claim,
		       category, confidence, observed_at, expires_at, detail
		  FROM evidence WHERE id = ?`
	for _, id := range ids {
		row := s.db.QueryRowContext(ctx, q, id)
		e, err := scanEvidence(row)
		if errors.Is(err, sql.ErrNoRows) {
			// A cited row that has since been pruned. Skipped rather than
			// erroring: a partial explanation beats no explanation, and the
			// caller can see the count differs.
			continue
		}
		if err != nil {
			return nil, err
		}
		found[id] = e
	}
	out := make([]evidence.Evidence, 0, len(found))
	for _, id := range ids {
		if e, ok := found[id]; ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// DeleteEvidenceFrom removes every claim made by one source.
//
// Called when a feed or provider is deleted. Without it, deleting a feed would
// leave its assertions influencing assessments with no row anywhere explaining
// where they came from.
func (s *Store) DeleteEvidenceFrom(ctx context.Context, source string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM evidence WHERE source = ?`, source)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneEvidence deletes claims past their own expiry.
//
// Evidence with no expiry is never pruned by this: an operator's decision and
// a local first-seen observation are facts about the past, and they are small.
func (s *Store) PruneEvidence(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM evidence WHERE expires_at IS NOT NULL AND expires_at < ?`,
		unixMilli(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountEvidence reports how many rows are held, for metrics and for the
// privacy documentation's storage figures.
func (s *Store) CountEvidence(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence`).Scan(&n)
	return n, err
}

// scanEvidence reads one row from either a *sql.Row or a *sql.Rows.
func scanEvidence(sc rowScanner) (evidence.Evidence, error) {
	var (
		e                    evidence.Evidence
		subjType, kind, conf string
		observed             int64
		expires              sql.NullInt64
		detail               string
	)
	if err := sc.Scan(&e.ID, &subjType, &e.Subject.Value, &kind, &e.Source,
		&e.SourceName, &e.Claim, &e.Category, &conf, &observed, &expires,
		&detail); err != nil {
		return evidence.Evidence{}, err
	}

	e.Subject.Type = evidence.SubjectType(subjType)
	e.Kind = evidence.Kind(kind)
	e.Confidence = evidence.Confidence(conf)
	// A value written by a newer binary and read by an older one degrades to
	// the least alarming reading rather than to an empty string that would
	// render as a blank chip.
	if !e.Confidence.Valid() {
		e.Confidence = evidence.ConfidenceLow
	}
	e.ObservedAt = fromUnixMilli(observed)
	if expires.Valid {
		t := fromUnixMilli(expires.Int64)
		e.ExpiresAt = &t
	}
	if detail != "" && detail != "{}" {
		var m map[string]any
		if err := json.Unmarshal([]byte(detail), &m); err == nil {
			e.Detail = m
		}
	}
	return e, nil
}
