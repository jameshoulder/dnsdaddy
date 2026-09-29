package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func seedOneFinding(t *testing.T, st *Store, id string, at time.Time) {
	t.Helper()
	if err := st.InsertFindings(context.Background(), []Finding{{
		ID: id, Time: at, EventType: "dns_tunnel_suspected", Severity: "high", Confidence: 0.8,
		Score: 0.7, ClientIP: "10.0.0.5", Domain: "tunnel.example", Detector: "dns_tunnel",
		Title: "t", Summary: "s", Detail: `{"id":"` + id + `","signals":[{"name":"x","value":1}]}`,
	}}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
}

func TestAnUnreviewedFindingIsNewAtVersionZero(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedOneFinding(t, st, "f1", time.Now())

	r, err := st.GetFindingReview(ctx, "f1")
	if err != nil {
		t.Fatalf("GetFindingReview: %v", err)
	}
	if r.State != ReviewNew || r.Version != 0 || r.Note != "" {
		t.Errorf("review = %+v, want new at version 0", r)
	}
	if _, err := st.GetFindingReview(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown finding: err = %v, want ErrNotFound", err)
	}
	if _, err := st.SetFindingReview(ctx, "nope", ReviewInput{State: ReviewAcknowledged}); !errors.Is(err, ErrNotFound) {
		t.Errorf("review of an unknown finding: err = %v, want ErrNotFound", err)
	}
}

func TestReviewWorkflowTransitions(t *testing.T) {
	allowed := map[string][]string{
		ReviewNew:           {ReviewAcknowledged, ReviewResolved, ReviewFalsePositive},
		ReviewAcknowledged:  {ReviewNew, ReviewResolved, ReviewFalsePositive},
		ReviewResolved:      {ReviewAcknowledged, ReviewFalsePositive},
		ReviewFalsePositive: {ReviewAcknowledged, ReviewResolved},
	}
	for _, from := range ReviewStates() {
		for _, to := range ReviewStates() {
			want := from == to
			for _, a := range allowed[from] {
				if a == to {
					want = true
				}
			}
			if got := ReviewTransitionAllowed(from, to); got != want {
				t.Errorf("%s → %s allowed = %v, want %v", from, to, got, want)
			}
		}
	}
	// The one move that is refused in both directions between closed
	// states and new: a resolved finding cannot be un-looked-at.
	if ReviewTransitionAllowed(ReviewResolved, ReviewNew) || ReviewTransitionAllowed(ReviewFalsePositive, ReviewNew) {
		t.Error("a closed finding moved straight back to new")
	}
}

func TestReviewWritesBumpTheVersionAndRefuseStaleWriters(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedOneFinding(t, st, "f1", time.Now())

	first, err := st.SetFindingReview(ctx, "f1", ReviewInput{State: ReviewAcknowledged, Note: "looking", Version: 0, Actor: "session:admin"})
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if first.Version != 1 || first.State != ReviewAcknowledged || first.Actor != "session:admin" {
		t.Errorf("first review = %+v", first)
	}

	// A second writer who read version 0 must not overwrite the first.
	_, err = st.SetFindingReview(ctx, "f1", ReviewInput{State: ReviewResolved, Version: 0})
	var stale *ErrStaleReview
	if !errors.As(err, &stale) {
		t.Fatalf("stale write: err = %v, want ErrStaleReview", err)
	}
	if stale.Current.Version != 1 || stale.Current.State != ReviewAcknowledged {
		t.Errorf("stale error carries %+v, want the current review", stale.Current)
	}

	// The same state with a new note is a write: version moves, history
	// records it.
	second, err := st.SetFindingReview(ctx, "f1", ReviewInput{State: ReviewAcknowledged, Note: "still looking", Version: 1})
	if err != nil || second.Version != 2 || second.Note != "still looking" {
		t.Errorf("note change = %+v (%v), want version 2 with the new note", second, err)
	}
	// An unreachable transition is refused and changes nothing.
	third, err := st.SetFindingReview(ctx, "f1", ReviewInput{State: ReviewResolved, Version: 2})
	if err != nil || third.Version != 3 {
		t.Fatalf("resolve: %+v (%v)", third, err)
	}
	_, err = st.SetFindingReview(ctx, "f1", ReviewInput{State: ReviewNew, Version: 3})
	var bad *ErrReviewTransition
	if !errors.As(err, &bad) {
		t.Fatalf("resolved → new: err = %v, want ErrReviewTransition", err)
	}
	if cur, _ := st.GetFindingReview(ctx, "f1"); cur.Version != 3 || cur.State != ReviewResolved {
		t.Errorf("a refused transition changed the review: %+v", cur)
	}

	hist, err := st.FindingReviewHistory(ctx, "f1")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) != 3 {
		t.Fatalf("history has %d entries, want 3 accepted writes", len(hist))
	}
	if hist[0].FromState != ReviewNew || hist[0].ToState != ReviewAcknowledged || hist[0].Version != 1 {
		t.Errorf("first history entry = %+v", hist[0])
	}
	if hist[2].ToState != ReviewResolved || hist[2].Version != 3 {
		t.Errorf("last history entry = %+v", hist[2])
	}
}

func TestReviewNotesAreBoundedPlainText(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedOneFinding(t, st, "f1", time.Now())

	// Markup stays as the literal characters it is; control characters go.
	r, err := st.SetFindingReview(ctx, "f1", ReviewInput{
		State: ReviewAcknowledged, Version: 0,
		Note: "  <script>alert(1)</script>\x1b[31m ticket 42\nline two\x00  ",
	})
	if err != nil {
		t.Fatalf("SetFindingReview: %v", err)
	}
	if r.Note != "<script>alert(1)</script>[31m ticket 42\nline two" {
		t.Errorf("note = %q; markup must survive as text and control characters must not", r.Note)
	}

	_, err = st.SetFindingReview(ctx, "f1", ReviewInput{State: ReviewAcknowledged, Version: 1, Note: strings.Repeat("x", MaxReviewNote+1)})
	if !errors.Is(err, ErrReviewInvalid) {
		t.Errorf("over-long note: err = %v, want ErrReviewInvalid", err)
	}
	_, err = st.SetFindingReview(ctx, "f1", ReviewInput{State: "escalated", Version: 1})
	if !errors.Is(err, ErrReviewInvalid) {
		t.Errorf("unknown state: err = %v, want ErrReviewInvalid", err)
	}
	if cur, _ := st.GetFindingReview(ctx, "f1"); cur.Version != 1 {
		t.Errorf("a refused write moved the version to %d", cur.Version)
	}
}

func TestReviewingAFindingLeavesTheFindingUntouched(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedOneFinding(t, st, "f1", time.Now())
	before, err := st.GetFinding(ctx, "f1")
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}

	if _, err := st.SetFindingReview(ctx, "f1", ReviewInput{State: ReviewFalsePositive, Note: "printer", Version: 0}); err != nil {
		t.Fatalf("SetFindingReview: %v", err)
	}

	after, err := st.GetFinding(ctx, "f1")
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if after.Detail != before.Detail || after.Severity != before.Severity || after.Score != before.Score ||
		after.Confidence != before.Confidence || !after.Time.Equal(before.Time) || after.Summary != before.Summary {
		t.Errorf("the finding changed when reviewed:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestReviewStateFiltersAndCounts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i, id := range []string{"a", "b", "c", "d"} {
		seedOneFinding(t, st, id, now.Add(-time.Duration(i)*time.Minute))
	}
	seedOneFinding(t, st, "old", now.Add(-72*time.Hour))
	must := func(id, state string, version int64) {
		t.Helper()
		if _, err := st.SetFindingReview(ctx, id, ReviewInput{State: state, Version: version}); err != nil {
			t.Fatalf("review %s → %s: %v", id, state, err)
		}
	}
	must("a", ReviewAcknowledged, 0)
	must("b", ReviewFalsePositive, 0)
	must("old", ReviewResolved, 0)
	// c and d stay new; "a" goes back to new, which must still count as new.
	must("a", ReviewNew, 1)

	counts, err := st.ReviewStateCounts(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("ReviewStateCounts: %v", err)
	}
	if counts[ReviewNew] != 3 || counts[ReviewFalsePositive] != 1 || counts[ReviewResolved] != 0 || counts[ReviewAcknowledged] != 0 {
		t.Errorf("counts = %v, want new 3, false_positive 1, and the resolved one outside the window", counts)
	}

	rows, _, err := st.ListFindings(ctx, FindingFilter{State: ReviewNew, Limit: 10})
	if err != nil {
		t.Fatalf("ListFindings(new): %v", err)
	}
	ids := map[string]bool{}
	for _, r := range rows {
		ids[r.ID] = true
	}
	if len(rows) != 3 || !ids["a"] || !ids["c"] || !ids["d"] {
		t.Errorf("new findings = %v, want a, c, d", ids)
	}
	rows, _, err = st.ListFindings(ctx, FindingFilter{State: ReviewFalsePositive, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != "b" {
		t.Errorf("false-positive findings = %v (%v), want b", rows, err)
	}
	// The other filters and the cursor still apply alongside the state.
	rows, next, err := st.ListFindings(ctx, FindingFilter{State: ReviewNew, Severity: "high", Limit: 2})
	if err != nil || len(rows) != 2 || next == "" {
		t.Errorf("paged new findings: %d rows, cursor %q, %v", len(rows), next, err)
	}

	reviews, err := st.FindingReviews(ctx, []string{"a", "b", "c", "zzz"})
	if err != nil {
		t.Fatalf("FindingReviews: %v", err)
	}
	if reviews["b"].State != ReviewFalsePositive || reviews["a"].State != ReviewNew || reviews["a"].Version != 2 {
		t.Errorf("reviews = %+v", reviews)
	}
	if _, ok := reviews["c"]; ok {
		t.Error("an unreviewed finding has a review row")
	}
}

func TestReviewsFollowTheFindingWhenItIsPruned(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedOneFinding(t, st, "gone", time.Now().Add(-100*24*time.Hour))
	if _, err := st.SetFindingReview(ctx, "gone", ReviewInput{State: ReviewResolved, Version: 0}); err != nil {
		t.Fatalf("SetFindingReview: %v", err)
	}
	if _, err := st.PruneFindings(ctx, 30); err != nil {
		t.Fatalf("PruneFindings: %v", err)
	}
	var reviews, history int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM finding_reviews`).Scan(&reviews); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM finding_review_history`).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if reviews != 0 || history != 0 {
		t.Errorf("review rows survived their finding: %d reviews, %d history entries", reviews, history)
	}
}
