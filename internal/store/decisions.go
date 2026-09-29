package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	// EvidenceSource is set by the detail/export path. Legacy decisions only
	// have mutable references, which must never be described as a snapshot.
	EvidenceSource string `json:"evidenceSource,omitempty"`
	EvidenceNote   string `json:"evidenceNote,omitempty"`
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

	seen := make(map[string]bool, len(cited))
	for _, c := range cited {
		if c.Evidence.ID == "" || seen[c.Evidence.ID] {
			continue
		}
		seen[c.Evidence.ID] = true
		snapshot, err := json.Marshal(c.Evidence)
		if err != nil {
			return Decision{}, fmt.Errorf("capture decision evidence: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO decision_evidence_snapshots
			(decision_id, evidence_id, contributed, snapshot) VALUES (?, ?, ?, ?)`,
			d.ID, c.Evidence.ID, boolToInt(c.Contributed), string(snapshot)); err != nil {
			return Decision{}, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO decision_evidence (decision_id, evidence_id, contributed)
			 VALUES (?, ?, ?)`,
			d.ID, c.Evidence.ID, boolToInt(c.Contributed)); err != nil {
			return Decision{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO decision_evidence_captures (decision_id, evidence_count) VALUES (?, ?)`, d.ID, len(seen)); err != nil {
		return Decision{}, err
	}
	if err := tx.Commit(); err != nil {
		return Decision{}, err
	}
	d.EvidenceSource = "recorded_snapshot"
	d.Cited = cited
	return d, nil
}

// DecisionFilter bounds a decision listing.
type DecisionFilter struct {
	Subject   string
	ClientIP  string
	Action    string
	Since     time.Time
	Until     time.Time
	Limit     int
	Cursor    string
	Ascending bool
	// MaxInsertionID freezes an export's insertion boundary; nil is an ordinary list.
	MaxInsertionID *int64
}

// ListDecisions returns recent decisions, newest first, without their
// evidence. The detail endpoint fetches that; a list of fifty decisions each
// carrying six evidence rows is a payload nobody reads.
func (s *Store) ListDecisions(ctx context.Context, f DecisionFilter) ([]Decision, error) {
	rows, _, err := s.ListDecisionsPage(ctx, f)
	return rows, err
}

// ListDecisionsPage uses (time, id) as a total order, including decisions
// recorded within the same millisecond. A full final page has no cursor.
func (s *Store) ListDecisionsPage(ctx context.Context, f DecisionFilter) ([]Decision, string, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	where := []string{"1 = 1"}
	args := []any{}
	if f.Cursor != "" {
		c, err := parseCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		if f.Ascending {
			where = append(where, "(ts > ? OR (ts = ? AND id > ?))")
		} else {
			where = append(where, "(ts < ? OR (ts = ? AND id < ?))")
		}
		args = append(args, c.ts, c.ts, c.id)
	}
	if f.Subject != "" {
		where = append(where, "subject = ?")
		args = append(args, evidence.Domain(f.Subject).Value)
	}
	if f.ClientIP != "" {
		where = append(where, "client_ip = ?")
		args = append(args, f.ClientIP)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, unixMilli(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, unixMilli(f.Until))
	}
	if f.MaxInsertionID != nil {
		where = append(where, "insertion_seq <= ?")
		args = append(args, *f.MaxInsertionID)
	}
	order := "ts DESC, id DESC"
	if f.Ascending {
		order = "ts ASC, id ASC"
	}
	args = append(args, limit+1)
	// #nosec G202 -- predicates and order are literal fragments; every value is bound.
	q := `SELECT id, ts, query_log_id, subject_type, subject, action, category,
	       rule, policy_path, policy_id, network_id, client_ip, client_name,
	       qtype, explanation, explanation_version
	       FROM decisions WHERE ` + strings.Join(where, " AND ") + ` ORDER BY ` + order + ` LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := make([]Decision, 0, limit)
	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, "", err
		}
		if len(out) == limit {
			last := out[len(out)-1]
			return out, encodeCursor(findingCursor{ts: unixMilli(last.Time), id: last.ID}), rows.Err()
		}
		out = append(out, d)
	}
	return out, "", rows.Err()
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

	var expected int
	err = s.db.QueryRowContext(ctx, `SELECT evidence_count FROM decision_evidence_captures WHERE decision_id = ?`, id).Scan(&expected)
	if err == nil {
		rows, err := s.db.QueryContext(ctx, `SELECT contributed, snapshot FROM decision_evidence_snapshots WHERE decision_id = ? ORDER BY evidence_id`, id)
		if err != nil {
			return Decision{}, err
		}
		defer rows.Close()
		d.Cited = make([]CitedEvidence, 0, expected)
		for rows.Next() {
			var c CitedEvidence
			var contributed int
			var raw string
			if err := rows.Scan(&contributed, &raw); err != nil {
				return Decision{}, err
			}
			if err := json.Unmarshal([]byte(raw), &c.Evidence); err != nil {
				return Decision{}, fmt.Errorf("read captured decision evidence: %w", err)
			}
			c.Contributed = contributed != 0
			d.Cited = append(d.Cited, c)
		}
		if err := rows.Err(); err != nil {
			return Decision{}, err
		}
		if len(d.Cited) != expected {
			return Decision{}, fmt.Errorf("decision evidence snapshot is incomplete")
		}
		d.EvidenceSource = "recorded_snapshot"
		return d, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Decision{}, err
	}
	// No attempt to backfill. A reference may have been refreshed or pruned
	// before this upgrade; even an intact reference is not historical proof.
	d.EvidenceSource = "legacy_current_reference"
	d.EvidenceNote = "This decision predates evidence snapshots. The explanation is original; surviving evidence references reflect current stored rows and may have changed or been removed."
	rows, err := s.db.QueryContext(ctx,
		`SELECT evidence_id, contributed FROM decision_evidence WHERE decision_id = ? ORDER BY evidence_id`, id)
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
