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

	// Completeness is CompleteRecord or TruncatedRecord: whether Cited is the
	// whole evidence list or was capped. A truncated record says so rather
	// than presenting a partial list as the full story.
	Completeness string `json:"completeness"`

	// Cited is populated by DecisionWithEvidence, not by the list queries.
	Cited []CitedEvidence `json:"evidence,omitempty"`
}

// Role says how a piece of evidence related to the outcome.
type Role string

const (
	// RoleCaused is the evidence the decision turned on. There is normally
	// exactly one.
	RoleCaused Role = "caused"
	// RoleContributed is evidence that was part of the reasoning without being
	// the deciding fact — a listing an allow-list overrode, for instance.
	RoleContributed Role = "contributed"
	// RoleObserved is evidence from an engine that cannot change an outcome.
	//
	// The value exists so that "did a detector cause this block?" is
	// answerable from the row rather than from knowing which engines happen to
	// enforce in this release. Only observe-mode engines are written with it,
	// and nothing else may be.
	RoleObserved Role = "observed"
)

// Contributing reports whether a role changed the outcome.
func (r Role) Contributing() bool { return r == RoleCaused || r == RoleContributed }

// CitedEvidence is one piece of evidence a decision referred to.
type CitedEvidence struct {
	Evidence evidence.Evidence `json:"evidence"`
	// Contributed reports whether this evidence changed the outcome, as
	// opposed to merely being on file at the time. An explanation that
	// conflates the two overstates its own case.
	//
	// Kept for the API's v1 promise and for a downgraded binary; Role is the
	// finer answer and the one to read.
	Contributed bool `json:"contributed"`
	// Role is how this evidence related to the outcome.
	Role Role `json:"role"`
}

// Completeness states for a decision record.
const (
	// CompleteRecord means the evidence list is the whole list.
	CompleteRecord = "complete"
	// TruncatedRecord means there was more evidence than the cap allows.
	TruncatedRecord = "truncated"
)

// roleOrLegacy reads a role, falling back to the contributed flag for rows
// written before the column existed.
//
// Legacy rows only ever carried the evidence that decided, so contributed
// maps to caused rather than to the weaker "contributed" — calling an old
// record's only evidence merely contributory would understate what it said.
func roleOrLegacy(role string, contributed bool) Role {
	switch Role(role) {
	case RoleCaused, RoleContributed, RoleObserved:
		return Role(role)
	}
	if contributed {
		return RoleCaused
	}
	return RoleContributed
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
	if d.Completeness == "" {
		d.Completeness = CompleteRecord
	}
	const insert = `
		INSERT INTO decisions
			(id, ts, query_log_id, subject_type, subject, action, category,
			 rule, policy_path, policy_id, network_id, client_ip, client_name,
			 qtype, explanation, explanation_version, completeness)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := tx.ExecContext(ctx, insert,
		d.ID, unixMilli(d.Time), qlID, string(d.Subject.Type), d.Subject.Value,
		d.Action, d.Category, d.Rule, d.PolicyPath, d.PolicyID, d.NetworkID,
		d.ClientIP, d.ClientName, d.QType, d.Explanation, d.ExplanationVersion,
		d.Completeness,
	); err != nil {
		return Decision{}, err
	}

	for i := range cited {
		c := &cited[i]
		if c.Evidence.ID == "" {
			continue
		}
		if c.Role == "" {
			c.Role = roleOrLegacy("", c.Contributed)
		}
		// Both columns are written. contributed is what a downgraded binary
		// reads, and it must not disagree with role: observed evidence did not
		// contribute, and the other two did.
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO decision_evidence (decision_id, evidence_id, contributed, role)
			 VALUES (?, ?, ?, ?)`,
			d.ID, c.Evidence.ID, boolToInt(c.Role.Contributing()), string(c.Role)); err != nil {
			return Decision{}, err
		}
		c.Contributed = c.Role.Contributing()
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
		       qtype, explanation, explanation_version, completeness
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
		       qtype, explanation, explanation_version, completeness
		  FROM decisions WHERE id = ?`
	d, err := scanDecision(s.db.QueryRowContext(ctx, q, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Decision{}, ErrNotFound
	}
	if err != nil {
		return Decision{}, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT evidence_id, contributed, role FROM decision_evidence WHERE decision_id = ?`, id)
	if err != nil {
		return Decision{}, err
	}
	defer rows.Close()

	var (
		ids   []string
		roles = map[string]Role{}
	)
	for rows.Next() {
		var evID, role string
		var contrib int
		if err := rows.Scan(&evID, &contrib, &role); err != nil {
			return Decision{}, err
		}
		ids = append(ids, evID)
		roles[evID] = roleOrLegacy(role, contrib != 0)
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
		role := roles[e.ID]
		d.Cited = append(d.Cited, CitedEvidence{
			Evidence: e, Role: role, Contributed: role.Contributing(),
		})
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
		&d.ExplanationVersion, &d.Completeness); err != nil {
		return Decision{}, err
	}
	if d.Completeness == "" {
		d.Completeness = CompleteRecord
	}
	d.Time = fromUnixMilli(ts)
	d.Subject.Type = evidence.SubjectType(subjType)
	if qlID.Valid {
		v := qlID.Int64
		d.QueryLogID = &v
	}
	return d, nil
}
