package decisions_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/decisions"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func roleStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// recordAndRead pushes one event through a live recorder and reads the stored
// decision back, so what is asserted is what an operator would see.
func recordAndRead(t *testing.T, st *store.Store, e decisions.Event) store.Decision {
	t.Helper()

	r := decisions.New(st, decisions.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)

	r.Record(e)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		list, err := st.ListDecisions(context.Background(), store.DecisionFilter{Limit: 10})
		if err != nil {
			t.Fatalf("ListDecisions: %v", err)
		}
		if len(list) > 0 {
			cancel()
			r.Wait()
			full, err := st.DecisionWithEvidence(context.Background(), list[0].ID)
			if err != nil {
				t.Fatalf("DecisionWithEvidence: %v", err)
			}
			return full
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	r.Wait()
	t.Fatal("no decision was recorded")
	return store.Decision{}
}

func blockEvent() decisions.Event {
	return decisions.Event{
		Time: time.Now().UTC(), Domain: "evil.example", QType: "A",
		Action: "blocked", Blocked: true, Reason: "Blocked by a feed",
		Basis: &policy.Basis{
			Rule: policy.RuleCategory, Category: "malware",
			FeedID: "f_threat", FeedName: "Threat feed",
			PolicyID: "p_standard", PolicyName: "Standard",
		},
	}
}

func roleOf(d store.Decision, source string) (store.Role, bool) {
	for _, c := range d.Cited {
		if c.Evidence.Source == source || c.Evidence.SourceName == source {
			return c.Role, true
		}
	}
	return "", false
}

// TestAFeedBlockIsRecordedAsCaused.
func TestAFeedBlockIsRecordedAsCaused(t *testing.T) {
	st := roleStore(t)
	d := recordAndRead(t, st, blockEvent())

	if d.Action != "blocked" {
		t.Errorf("action = %q", d.Action)
	}
	role, ok := roleOf(d, "f_threat")
	if !ok {
		t.Fatalf("the feed is not cited: %+v", d.Cited)
	}
	if role != store.RoleCaused {
		t.Errorf("role = %q, want caused", role)
	}
	if d.Completeness != store.CompleteRecord {
		t.Errorf("completeness = %q, want complete", d.Completeness)
	}
}

// TestAnAllowListWinCitesBothWithTheOverrideContributing.
//
// The operator's question is "why is this domain my feed calls malware
// resolving?", and an answer naming only the allow-list does not answer it.
// Both appear; only the allow-list caused the outcome.
func TestAnAllowListWinCitesBothWithTheOverrideContributing(t *testing.T) {
	st := roleStore(t)
	d := recordAndRead(t, st, decisions.Event{
		Time: time.Now().UTC(), Domain: "vendor.example", QType: "A",
		Action: "allowed", Blocked: false, Reason: "Allowed by policy allow-list",
		Basis: &policy.Basis{
			Rule: policy.RuleAllowList, PolicyID: "p_standard", PolicyName: "Standard",
			OverrodeFeedID: "f_threat", OverrodeFeedName: "Threat feed",
			OverrodeCategory: "malware",
		},
	})

	if len(d.Cited) != 2 {
		t.Fatalf("cited %d pieces of evidence, want the allow-list and what it beat: %+v", len(d.Cited), d.Cited)
	}
	if role, _ := roleOf(d, "operator"); role != store.RoleCaused {
		t.Errorf("the allow-list role = %q, want caused", role)
	}
	if role, ok := roleOf(d, "f_threat"); !ok || role != store.RoleContributed {
		t.Errorf("the overridden feed role = %q (found %v), want contributed", role, ok)
	}
	for _, want := range []string{"allow-list", "overrode", "malware"} {
		if !strings.Contains(strings.ToLower(d.Explanation), want) {
			t.Errorf("explanation %q does not mention %q", d.Explanation, want)
		}
	}
}

// TestAnObserveEngineIsNeverCaused, and never contributed either.
//
// This is the invariant the three-way role exists for. Daddybound in Learn
// mode cannot change an answer; a record that let it read as the reason for a
// block would be asserting enforcement this project does not do.
func TestAnObserveEngineIsNeverCaused(t *testing.T) {
	st := roleStore(t)
	e := blockEvent()
	e.Observed = []decisions.Observation{
		{Engine: "daddybound", Mode: "observe", CorrelationID: "obs_123"},
	}
	d := recordAndRead(t, st, e)

	role, ok := roleOf(d, "daddybound")
	if !ok {
		t.Fatalf("daddybound is not cited: %+v", d.Cited)
	}
	if role != store.RoleObserved {
		t.Fatalf("daddybound role = %q, want observed", role)
	}
	if role.Contributing() {
		t.Error("an observed role reported itself as contributing")
	}

	// And the sentence must not read as though it decided anything.
	lower := strings.ToLower(d.Explanation)
	if strings.Contains(lower, "blocked because daddybound") ||
		strings.Contains(lower, "allowed because daddybound") {
		t.Errorf("the explanation credits an observe engine with the outcome: %q", d.Explanation)
	}
	if !strings.Contains(lower, "threat feed") {
		t.Errorf("the explanation does not name what actually caused the block: %q", d.Explanation)
	}
}

// TestAQueryThatDecidedNothingButWasObservedSaysSo.
//
// This is the recorder's own contract, and deliberately not reachable from the
// resolver: the handler will not build an event out of observations alone,
// because Daddybound in Learn mode looks at every resolved query and that
// would make one row per query (see
// TestAnObserveEngineAloneDoesNotCreateADecisionRecord in internal/dnsserver).
//
// It is tested anyway because the recorder is the last thing between an event
// and the database, and the property it must never lose is the wording: if
// such an event ever arrives, the sentence says plainly that nothing changed
// the outcome rather than dressing an observation up as a reason.
func TestAQueryThatDecidedNothingButWasObservedSaysSo(t *testing.T) {
	st := roleStore(t)
	d := recordAndRead(t, st, decisions.Event{
		Time: time.Now().UTC(), Domain: "ordinary.example", QType: "A",
		Action: "allowed", Reason: "Resolved",
		Observed: []decisions.Observation{
			{Engine: "daddybound", Mode: "observe", CorrelationID: "obs_9"},
		},
	})

	if d.Action != "allowed" {
		t.Errorf("action = %q, want allowed", d.Action)
	}
	for _, c := range d.Cited {
		if c.Role != store.RoleObserved {
			t.Errorf("evidence %q has role %q on a query nothing decided", c.Evidence.Source, c.Role)
		}
	}
	lower := strings.ToLower(d.Explanation)
	if !strings.Contains(lower, "no rule changed this outcome") {
		t.Errorf("explanation %q does not say that nothing decided", d.Explanation)
	}
	if strings.Contains(lower, "because") {
		t.Errorf("explanation %q asserts a cause where there was none", d.Explanation)
	}
}

// TestAnOrdinaryAllowedQueryRecordsNothing. The decision table must not become
// a second query log: one row per configuration-relevant decision, never one
// per DNS query, or an attacker fills it with traffic.
func TestAnOrdinaryAllowedQueryRecordsNothing(t *testing.T) {
	st := roleStore(t)
	r := decisions.New(st, decisions.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)

	for i := 0; i < 50; i++ {
		r.Record(decisions.Event{
			Time: time.Now().UTC(), Domain: "plain.example", QType: "A", Action: "allowed",
		})
	}
	time.Sleep(120 * time.Millisecond)
	cancel()
	r.Wait()

	n, err := st.CountDecisions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d decisions recorded for queries that decided nothing", n)
	}
}

// TestTheEvidenceListIsCappedAndSaysSo. A row whose size is set by how many
// engines happen to be enabled is a row that will one day be enormous.
func TestTheEvidenceListIsCappedAndSaysSo(t *testing.T) {
	st := roleStore(t)
	e := blockEvent()
	for i := 0; i < decisions.MaxEvidence+10; i++ {
		e.Observed = append(e.Observed, decisions.Observation{
			Engine: "engine" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Mode:   "observe",
		})
	}
	d := recordAndRead(t, st, e)

	if len(d.Cited) > decisions.MaxEvidence {
		t.Errorf("cited %d pieces, cap is %d", len(d.Cited), decisions.MaxEvidence)
	}
	if d.Completeness != store.TruncatedRecord {
		t.Errorf("completeness = %q, want truncated", d.Completeness)
	}
	// The cap must drop the least load-bearing evidence, not the reason.
	if role, ok := roleOf(d, "f_threat"); !ok || role != store.RoleCaused {
		t.Error("truncation dropped the evidence that caused the block")
	}
}

// TestALegacyRowWithoutARoleStillReadsAsCaused. Rows written before the role
// column existed carried only the evidence that decided; reading them as
// merely contributory would understate what they said.
func TestALegacyRowWithoutARoleStillReadsAsCaused(t *testing.T) {
	st := roleStore(t)
	d := recordAndRead(t, st, blockEvent())

	// Blank the role the way a pre-migration row would have it.
	if _, err := st.DB().Exec(
		`UPDATE decision_evidence SET role = '' WHERE decision_id = ?`, d.ID); err != nil {
		t.Fatal(err)
	}
	got, err := st.DecisionWithEvidence(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Cited) == 0 {
		t.Fatal("no evidence came back")
	}
	if got.Cited[0].Role != store.RoleCaused {
		t.Errorf("a legacy row read as %q, want caused", got.Cited[0].Role)
	}
}
