package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
)

func newEvidenceStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func claim(source, text string, observed time.Time) evidence.Evidence {
	return evidence.Evidence{
		Subject:    evidence.Domain("evil.example"),
		Kind:       evidence.KindFeed,
		Source:     source,
		SourceName: strings.ToUpper(source),
		Claim:      text,
		Category:   "malware",
		Confidence: evidence.ConfidenceHigh,
		ObservedAt: observed,
	}
}

func TestEvidenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)

	in := claim("f_urlhaus", "listed as a malicious host", now)
	in.Detail = map[string]any{"listed_at": "2026-09-01", "reference": "https://urlhaus.example/x"}

	out, err := st.PutEvidence(ctx, in)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if out.ID == "" {
		t.Fatal("no id assigned")
	}

	all, err := st.EvidenceFor(ctx, evidence.Domain("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("got %d rows, want 1", len(all))
	}
	got := all[0]
	if got.Claim != in.Claim || got.SourceName != "F_URLHAUS" || got.Category != "malware" {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if got.Confidence != evidence.ConfidenceHigh {
		t.Errorf("confidence = %q", got.Confidence)
	}
	if !got.ObservedAt.Equal(now) {
		t.Errorf("observedAt = %s, want %s", got.ObservedAt, now)
	}
	if got.Detail["reference"] != "https://urlhaus.example/x" {
		t.Errorf("detail did not survive: %+v", got.Detail)
	}
	// Subject normalisation applies at the storage boundary too.
	if got.Subject.Value != "evil.example" || got.Subject.Type != evidence.SubjectDomain {
		t.Errorf("subject = %+v", got.Subject)
	}
}

// A feed that lists the same domain at every refresh must update its claim,
// not accumulate a row an hour. This is what makes the table a store of what
// is known rather than a log of when we looked.
func TestARefreshUpdatesRatherThanAccumulates(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)
	first := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Millisecond)

	if _, err := st.PutEvidence(ctx, claim("f_a", "listed as a malicious host", first)); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		later := claim("f_a", "listed as a malicious host", first.Add(time.Duration(i)*time.Hour))
		later.Confidence = evidence.ConfidenceMedium
		if _, err := st.PutEvidence(ctx, later); err != nil {
			t.Fatal(err)
		}
	}

	all, err := st.EvidenceFor(ctx, evidence.Domain("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("six refreshes produced %d rows, want 1", len(all))
	}
	// The first observation is preserved: "first seen three days ago,
	// confirmed since" is more useful than either half alone.
	if !all[0].ObservedAt.Equal(first) {
		t.Errorf("observedAt = %s, want the first observation %s", all[0].ObservedAt, first)
	}
	// But the mutable fields moved.
	if all[0].Confidence != evidence.ConfidenceMedium {
		t.Errorf("confidence = %q, want the refreshed value", all[0].Confidence)
	}
}

// Two sources making the same claim are two rows. Collapsing them would
// destroy the only thing corroboration is made of.
func TestDifferentSourcesAreDistinctRows(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)
	now := time.Now()

	for _, src := range []string{"f_a", "f_b", "f_c"} {
		if _, err := st.PutEvidence(ctx, claim(src, "listed as a malicious host", now)); err != nil {
			t.Fatal(err)
		}
	}
	all, err := st.EvidenceFor(ctx, evidence.Domain("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d rows, want one per source", len(all))
	}
	a := evidence.Assess(evidence.Domain("evil.example"), all, now)
	if !a.Corroborated || len(a.Sources) != 3 {
		t.Errorf("three sources did not read as corroboration: %+v", a.Sources)
	}
}

func TestInvalidEvidenceIsRefused(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)

	bad := claim("f_a", "listed", time.Now())
	bad.Confidence = "certain"
	if _, err := st.PutEvidence(ctx, bad); err == nil {
		t.Fatal("evidence with an invented confidence was stored")
	}
	n, err := st.CountEvidence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d rows were written despite the rejection", n)
	}
}

// Detail is a third party's data. A hostile provider must not be able to fill
// the disk one evidence row at a time.
func TestAnOversizedDetailIsDroppedNotStored(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)

	huge := claim("p_hostile", "flagged", time.Now())
	huge.Kind = evidence.KindProvider
	huge.Detail = map[string]any{"blob": strings.Repeat("A", 64<<10)}

	out, err := st.PutEvidence(ctx, huge)
	if err != nil {
		t.Fatalf("an oversized detail failed the write instead of being dropped: %v", err)
	}
	// The claim survives — that is the load-bearing part.
	if out.Claim != "flagged" {
		t.Errorf("the claim was lost: %+v", out)
	}
	if len(out.Detail) != 0 {
		t.Errorf("a %d-byte detail was stored", len(huge.Detail["blob"].(string)))
	}
}

// Deleting a feed must take its assertions with it. Otherwise a deleted
// source goes on influencing assessments with no row explaining where the
// claim came from.
func TestDeletingASourceRemovesItsClaims(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)
	now := time.Now()

	for _, src := range []string{"f_going", "f_staying"} {
		if _, err := st.PutEvidence(ctx, claim(src, "listed as a malicious host", now)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.DeleteEvidenceFrom(ctx, "f_going")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("deleted %d rows, want 1", n)
	}
	all, err := st.EvidenceFor(ctx, evidence.Domain("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Source != "f_staying" {
		t.Errorf("the wrong rows survived: %+v", all)
	}
}

// Expiry prunes; absence of expiry does not. An operator decision and a local
// first-seen observation are facts about the past and are kept.
func TestPruneRemovesOnlyExpiredClaims(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	expired := claim("f_expired", "listed as a malicious host", now.Add(-48*time.Hour))
	expired.ExpiresAt = &past
	live := claim("f_live", "listed as a malicious host", now)
	live.ExpiresAt = &future
	permanent := evidence.Evidence{
		Subject: evidence.Domain("evil.example"), Kind: evidence.KindOperator,
		Source: "operator", SourceName: "operator",
		Claim: "allow-listed by an operator", Category: "allowed",
		Confidence: evidence.ConfidenceHigh, ObservedAt: now,
	}
	for _, e := range []evidence.Evidence{expired, live, permanent} {
		if _, err := st.PutEvidence(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.PruneEvidence(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want only the expired one", n)
	}
	all, err := st.EvidenceFor(ctx, evidence.Domain("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d rows after pruning, want 2", len(all))
	}
	for _, e := range all {
		if e.Source == "f_expired" {
			t.Error("an expired claim survived the prune")
		}
	}
}

// A decision cites evidence by ID so its explanation is what was there at the
// time, not a re-read of a subject that has since changed.
func TestEvidenceByIDPreservesRequestOrderAndSkipsMissing(t *testing.T) {
	ctx := context.Background()
	st := newEvidenceStore(t)
	now := time.Now()

	// Eight rows, asked for in reverse. Three would not have been enough: the
	// implementation reads into a map, and Go's randomised map order coincides
	// with a three-element request often enough that the first version of this
	// test passed against an implementation that ignored the order entirely.
	// At eight, a coincidence is one run in forty thousand.
	var ids []string
	for _, src := range []string{"f_a", "f_b", "f_c", "f_d", "f_e", "f_f", "f_g", "f_h"} {
		e, err := st.PutEvidence(ctx, claim(src, "listed as a malicious host", now))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}

	want := make([]string, 0, len(ids)+1)
	for i := len(ids) - 1; i >= 0; i-- {
		want = append(want, ids[i])
		if i == 4 {
			// A cited row that has since been pruned, in the middle.
			want = append(want, "ev_deadbeef")
		}
	}

	got, err := st.EvidenceByID(ctx, want)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ids) {
		t.Fatalf("got %d rows, want the %d that exist", len(got), len(ids))
	}
	for i := range ids {
		if wantID := ids[len(ids)-1-i]; got[i].ID != wantID {
			t.Fatalf("position %d = %s, want %s — request order was not preserved",
				i, got[i].ID, wantID)
		}
	}
}
