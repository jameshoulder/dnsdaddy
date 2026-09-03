package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
)

// ExplanationVersion moves when the wording of a stored explanation changes
// meaning. Old rows keep the version they were written under, so a reader can
// tell whether two explanations were produced by the same rules.
const ExplanationVersion = "1.0"

// Decision is one recorded enforcement or alert.
type Decision struct {
	ID         string           `json:"id"`
	Time       time.Time        `json:"time"`
	QueryLogID *int64           `json:"queryLogId,omitempty"`
	Subject    evidence.Subject `json:"subject"`
	Action     string           `json:"action"`
	Category   string           `json:"category,omitempty"`
	Rule       string           `json:"rule"`
	PolicyPath string           `json:"policyPath"`
	PolicyID   string           `json:"policyId,omitempty"`
	NetworkID  string           `json:"networkId,omitempty"`
	ClientIP   string           `json:"clientIp,omitempty"`
	ClientName string           `json:"clientName,omitempty"`
	QType      string           `json:"qtype,omitempty"`
	// Explanation is the sentence an operator reads. Stored, not regenerated:
	// an explanation that changes after the fact is not an audit trail.
	Explanation        string `json:"explanation"`
	ExplanationVersion string `json:"explanationVersion"`

	// Cited is populated by DecisionWithEvidence, not by the list queries.
	Cited []CitedEvidence `json:"evidence,omitempty"`
}

// CitedEvidence is one piece of evidence a decision referred to.
type CitedEvidence struct {
	Evidence evidence.Evidence `json:"evidence"`
	// Contributed reports whether this evidence changed the outcome, as
	// opposed to merely being on file at the time. An explanation that
	// conflates the two overstates its own case.
	Contributed bool `json:"contributed"`
}

// RecordDecision writes a decision and the evidence it cited, in one
// transaction.
//
// Atomic because a decision with no evidence rows is worse than no decision at
// all: it asserts that something was decided and then cannot say why, which is
// the exact failure this whole feature exists to prevent.
func (s *Store) RecordDecision(ctx context.Context, d Decision, cited []CitedEvidence) (Decision, error) {
	if d.ID == "" {
		d.ID = NewID("dec")
	}
	if d.ExplanationVersion == "" {
		d.ExplanationVersion = ExplanationVersion
	}
	if d.Subject.Type == "" {
		d.Subject.Type = evidence.SubjectDomain
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Decision{}, err
	}
	defer tx.Rollback() //nolint:errcheck // committed below on the happy path

	var qlID any
	if d.QueryLogID != nil {
		qlID = *d.QueryLogID
	}
	const insert = `
		INSERT INTO decisions
			(id, ts, query_log_id, subject_type, subject, action, category,
			 rule, policy_path, policy_id, network_id, client_ip, client_name,
			 qtype, explanation, explanation_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := tx.ExecContext(ctx, insert,
		d.ID, unixMilli(d.Time), qlID, string(d.Subject.Type), d.Subject.Value,
		d.Action, d.Category, d.Rule, d.PolicyPath, d.PolicyID, d.NetworkID,
		d.ClientIP, d.ClientName, d.QType, d.Explanation, d.ExplanationVersion,
	); err != nil {
		return Decision{}, err
	}

	for _, c := range cited {
		if c.Evidence.ID == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO decision_evidence (decision_id, evidence_id, contributed)
			 VALUES (?, ?, ?)`,
			d.ID, c.Evidence.ID, boolToInt(c.Contributed)); err != nil {
			return Decision{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Decision{}, err
	}
	d.Cited = cited
	return d, nil
}

// DecisionFilter bounds a decision listing.
type DecisionFilter struct {
	Subject  string
	ClientIP string
	Action   string
	Limit    int
}

// ListDecisions returns recent decisions, newest first, without their
// evidence. The detail endpoint fetches that; a list of fifty decisions each
// carrying six evidence rows is a payload nobody reads.
func (s *Store) ListDecisions(ctx context.Context, f DecisionFilter) ([]Decision, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `
		SELECT id, ts, query_log_id, subject_type, subject, action, category,
		       rule, policy_path, policy_id, network_id, client_ip, client_name,
		       qtype, explanation, explanation_version
		  FROM decisions WHERE 1=1`
	args := []any{}
	if f.Subject != "" {
		q += ` AND subject = ?`
		args = append(args, evidence.Domain(f.Subject).Value)
	}
	if f.ClientIP != "" {
		q += ` AND client_ip = ?`
		args = append(args, f.ClientIP)
	}
	if f.Action != "" {
		q += ` AND action = ?`
		args = append(args, f.Action)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Decision, 0, 16)
	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DecisionWithEvidence returns one decision and everything it cited.
//
// The evidence is fetched by the IDs the decision recorded, not by re-reading
// the subject's current evidence. That is the whole point: the explanation is
// what was true at the time, and a feed that has since dropped the domain must
// not silently rewrite it.
func (s *Store) DecisionWithEvidence(ctx context.Context, id string) (Decision, error) {
	const q = `
		SELECT id, ts, query_log_id, subject_type, subject, action, category,
		       rule, policy_path, policy_id, network_id, client_ip, client_name,
		       qtype, explanation, explanation_version
		  FROM decisions WHERE id = ?`
	d, err := scanDecision(s.db.QueryRowContext(ctx, q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Decision{}, ErrNotFound
	}
	if err != nil {
		return Decision{}, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT evidence_id, contributed FROM decision_evidence WHERE decision_id = ?`, id)
	if err != nil {
		return Decision{}, err
	}
	defer rows.Close()

	var (
		ids         []string
		contributed = map[string]bool{}
	)
	for rows.Next() {
		var evID string
		var contrib int
		if err := rows.Scan(&evID, &contrib); err != nil {
			return Decision{}, err
		}
		ids = append(ids, evID)
		contributed[evID] = contrib != 0
	}
	if err := rows.Err(); err != nil {
		return Decision{}, err
	}

	found, err := s.EvidenceByID(ctx, ids)
	if err != nil {
		return Decision{}, err
	}
	d.Cited = make([]CitedEvidence, 0, len(found))
	for _, e := range found {
		d.Cited = append(d.Cited, CitedEvidence{Evidence: e, Contributed: contributed[e.ID]})
	}
	return d, nil
}

// PruneDecisions deletes records older than cutoff. decision_evidence follows
// by cascade.
func (s *Store) PruneDecisions(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM decisions WHERE ts < ?`, unixMilli(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountDecisions reports how many records are held.
func (s *Store) CountDecisions(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM decisions`).Scan(&n)
	return n, err
}

func scanDecision(sc rowScanner) (Decision, error) {
	var (
		d        Decision
		ts       int64
		qlID     sql.NullInt64
		subjType string
	)
	if err := sc.Scan(&d.ID, &ts, &qlID, &subjType, &d.Subject.Value, &d.Action,
		&d.Category, &d.Rule, &d.PolicyPath, &d.PolicyID, &d.NetworkID,
		&d.ClientIP, &d.ClientName, &d.QType, &d.Explanation,
		&d.ExplanationVersion); err != nil {
		return Decision{}, err
	}
	d.Time = fromUnixMilli(ts)
	d.Subject.Type = evidence.SubjectType(subjType)
	if qlID.Valid {
		v := qlID.Int64
		d.QueryLogID = &v
	}
	return d, nil
}
