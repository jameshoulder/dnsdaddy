package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Review states. "new" is the implicit state of a finding nobody has
// reviewed; it is also a state a review can return to.
const (
	ReviewNew           = "new"
	ReviewAcknowledged  = "acknowledged"
	ReviewResolved      = "resolved"
	ReviewFalsePositive = "false_positive"
)

// ReviewStates is every state, in workflow order.
func ReviewStates() []string {
	return []string{ReviewNew, ReviewAcknowledged, ReviewResolved, ReviewFalsePositive}
}

// ValidReviewState reports whether s is a state this build understands.
func ValidReviewState(s string) bool {
	switch s {
	case ReviewNew, ReviewAcknowledged, ReviewResolved, ReviewFalsePositive:
		return true
	}
	return false
}

// reviewTransitions is the workflow, stated once.
//
// The same state is always allowed: it is how a note is changed without
// changing the disposition, and it still bumps the version and writes
// history. Reopening is the move back to acknowledged from either closed
// state, and "new" is reachable only from acknowledged, which undoes an
// acknowledgement made by mistake without pretending a resolved finding was
// never looked at.
var reviewTransitions = map[string][]string{
	ReviewNew:           {ReviewAcknowledged, ReviewResolved, ReviewFalsePositive},
	ReviewAcknowledged:  {ReviewNew, ReviewResolved, ReviewFalsePositive},
	ReviewResolved:      {ReviewAcknowledged, ReviewFalsePositive},
	ReviewFalsePositive: {ReviewAcknowledged, ReviewResolved},
}

// ReviewTransitionAllowed reports whether a review may move from one state to
// another.
func ReviewTransitionAllowed(from, to string) bool {
	if from == to {
		return true
	}
	for _, allowed := range reviewTransitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// MaxReviewNote bounds the note. Long enough for a paragraph of context and
// a ticket reference, short enough that a note cannot be a place to store a
// document.
const MaxReviewNote = 2000

// FindingReview is an operator's current disposition of a finding.
//
// Version starts at 0 for a finding nobody has reviewed and increases by one
// per accepted write. A writer passes the version it read, and a write that
// names any other version is refused: see ErrStaleReview.
type FindingReview struct {
	FindingID string    `json:"findingId"`
	State     string    `json:"state"`
	Note      string    `json:"note"`
	Version   int64     `json:"version"`
	Actor     string    `json:"actor,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// ReviewEvent is one entry of a finding's review history.
type ReviewEvent struct {
	ID        int64     `json:"id"`
	FindingID string    `json:"findingId"`
	Version   int64     `json:"version"`
	FromState string    `json:"fromState"`
	ToState   string    `json:"toState"`
	Note      string    `json:"note"`
	Actor     string    `json:"actor,omitempty"`
	At        time.Time `json:"at"`
}

// ReviewInput is one write.
type ReviewInput struct {
	State string
	Note  string
	// Version is the version the writer read. Zero means "no review yet",
	// which is the version an unreviewed finding has.
	Version int64
	Actor   string
}

// ErrStaleReview reports that the finding's review moved on since the
// caller read it. Current is what it is now, so the caller can show the
// conflict rather than a bare failure.
type ErrStaleReview struct {
	Current FindingReview
}

func (e *ErrStaleReview) Error() string {
	return fmt.Sprintf("the review is at version %d, not the version you read; reload it and try again",
		e.Current.Version)
}

// ErrReviewTransition reports a move the workflow does not allow.
type ErrReviewTransition struct{ From, To string }

func (e *ErrReviewTransition) Error() string {
	return fmt.Sprintf("a finding cannot move from %s to %s", e.From, e.To)
}

// ErrReviewInvalid reports a malformed write.
var ErrReviewInvalid = errors.New("invalid review")

// GetFindingReview returns the review for a finding, or the implicit "new"
// review at version 0 when nobody has reviewed it. ErrNotFound when the
// finding itself does not exist.
func (s *Store) GetFindingReview(ctx context.Context, findingID string) (FindingReview, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE id = ?`, findingID).Scan(&exists); err != nil {
		return FindingReview{}, err
	}
	if exists == 0 {
		return FindingReview{}, ErrNotFound
	}
	r, err := s.findingReview(ctx, s.db, findingID)
	if err != nil {
		return FindingReview{}, err
	}
	return r, nil
}

// findingReview reads the row, or the implicit new state.
func (s *Store) findingReview(ctx context.Context, q rowQueryer, findingID string) (FindingReview, error) {
	r := FindingReview{FindingID: findingID, State: ReviewNew}
	var created, updated int64
	err := q.QueryRowContext(ctx, `
		SELECT state, note, version, actor, created_at, updated_at
		  FROM finding_reviews WHERE finding_id = ?`, findingID).
		Scan(&r.State, &r.Note, &r.Version, &r.Actor, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return r, nil
	}
	if err != nil {
		return FindingReview{}, err
	}
	r.CreatedAt, r.UpdatedAt = fromUnixMilli(created), fromUnixMilli(updated)
	return r, nil
}

type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// SetFindingReview records an operator's disposition of a finding.
//
// One transaction: read the current version, refuse if it is not the one
// the caller read, check the transition, write the row and the history
// entry. The findings row is not touched — there is no statement here that
// names it except to check it exists — so the measurement a review is about
// cannot be changed by reviewing it.
func (s *Store) SetFindingReview(ctx context.Context, findingID string, in ReviewInput) (FindingReview, error) {
	if !ValidReviewState(in.State) {
		return FindingReview{}, fmt.Errorf("%w: state must be one of %s", ErrReviewInvalid, strings.Join(ReviewStates(), ", "))
	}
	note, err := cleanReviewNote(in.Note)
	if err != nil {
		return FindingReview{}, err
	}
	if in.Version < 0 {
		return FindingReview{}, fmt.Errorf("%w: version must not be negative", ErrReviewInvalid)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FindingReview{}, err
	}
	defer tx.Rollback() //nolint:errcheck // committed below on the happy path

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE id = ?`, findingID).Scan(&exists); err != nil {
		return FindingReview{}, err
	}
	if exists == 0 {
		return FindingReview{}, ErrNotFound
	}

	current, err := s.findingReview(ctx, tx, findingID)
	if err != nil {
		return FindingReview{}, err
	}
	if current.Version != in.Version {
		return FindingReview{}, &ErrStaleReview{Current: current}
	}
	if !ReviewTransitionAllowed(current.State, in.State) {
		return FindingReview{}, &ErrReviewTransition{From: current.State, To: in.State}
	}

	now := time.Now().UTC()
	next := FindingReview{
		FindingID: findingID, State: in.State, Note: note, Version: current.Version + 1,
		Actor: in.Actor, CreatedAt: current.CreatedAt, UpdatedAt: now,
	}
	if next.CreatedAt.IsZero() {
		next.CreatedAt = now
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_reviews (finding_id, state, note, version, actor, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(finding_id) DO UPDATE SET
			state = excluded.state, note = excluded.note, version = excluded.version,
			actor = excluded.actor, updated_at = excluded.updated_at`,
		findingID, next.State, next.Note, next.Version, next.Actor,
		unixMilli(next.CreatedAt), unixMilli(next.UpdatedAt)); err != nil {
		return FindingReview{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_review_history (finding_id, version, from_state, to_state, note, actor, at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		findingID, next.Version, current.State, next.State, next.Note, next.Actor, unixMilli(now)); err != nil {
		return FindingReview{}, err
	}
	if err := tx.Commit(); err != nil {
		return FindingReview{}, err
	}
	return next, nil
}

// FindingReviewHistory returns a finding's review changes, oldest first.
// ErrNotFound when the finding does not exist.
func (s *Store) FindingReviewHistory(ctx context.Context, findingID string) ([]ReviewEvent, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE id = ?`, findingID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, finding_id, version, from_state, to_state, note, actor, at
		  FROM finding_review_history WHERE finding_id = ? ORDER BY id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ReviewEvent{}
	for rows.Next() {
		var (
			e  ReviewEvent
			at int64
		)
		if err := rows.Scan(&e.ID, &e.FindingID, &e.Version, &e.FromState, &e.ToState, &e.Note, &e.Actor, &at); err != nil {
			return nil, err
		}
		e.At = fromUnixMilli(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// FindingReviews returns the reviews for a set of findings, keyed by id.
// Findings with no review are absent, which callers read as "new".
func (s *Store) FindingReviews(ctx context.Context, ids []string) (map[string]FindingReview, error) {
	out := map[string]FindingReview{}
	if len(ids) == 0 {
		return out, nil
	}
	const chunk = 200
	for start := 0; start < len(ids); start += chunk {
		end := min(start+chunk, len(ids))
		batch := ids[start:end]
		args := make([]any, len(batch))
		for i, id := range batch {
			args[i] = id
		}
		// #nosec G202 -- placeholders() emits only "?" separated by commas;
		// every id is bound in args.
		rows, err := s.db.QueryContext(ctx, `
			SELECT finding_id, state, note, version, actor, created_at, updated_at
			  FROM finding_reviews WHERE finding_id IN (`+placeholders(len(batch))+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var (
				r                FindingReview
				created, updated int64
			)
			if err := rows.Scan(&r.FindingID, &r.State, &r.Note, &r.Version, &r.Actor, &created, &updated); err != nil {
				rows.Close()
				return nil, err
			}
			r.CreatedAt, r.UpdatedAt = fromUnixMilli(created), fromUnixMilli(updated)
			out[r.FindingID] = r
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ReviewStateCounts counts findings since t by review state, "new" included
// for findings with no review row. Scoped to the same window as the
// severity summary so the two can sit side by side.
func (s *Store) ReviewStateCounts(ctx context.Context, since time.Time) (map[string]int64, error) {
	out := map[string]int64{}
	for _, st := range ReviewStates() {
		out[st] = 0
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(r.state, ?), COUNT(*)
		  FROM findings f LEFT JOIN finding_reviews r ON r.finding_id = f.id
		 WHERE f.ts >= ?
		 GROUP BY COALESCE(r.state, ?)`, ReviewNew, unixMilli(since), ReviewNew)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var n int64
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		out[state] = n
	}
	return out, rows.Err()
}

// cleanReviewNote bounds and sanitises a note.
//
// Plain text. Control characters other than newline and tab are stripped so a
// note cannot carry a terminal escape or a log-line forgery into whatever
// renders it; markup is left as the literal characters it is, and every
// renderer escapes it. Bounded in runes rather than bytes so a limit reads the
// same to a person whatever script they write in.
func cleanReviewNote(note string) (string, error) {
	note = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, note)
	note = strings.TrimSpace(note)
	if !utf8.ValidString(note) {
		return "", fmt.Errorf("%w: note is not valid UTF-8", ErrReviewInvalid)
	}
	if utf8.RuneCountInString(note) > MaxReviewNote {
		return "", fmt.Errorf("%w: note is longer than %d characters", ErrReviewInvalid, MaxReviewNote)
	}
	return note, nil
}
