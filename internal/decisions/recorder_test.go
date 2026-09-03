package decisions

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func newRecorder(t *testing.T) (*Recorder, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	r := New(st, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	t.Cleanup(func() { cancel(); r.Wait() })
	return r, st
}

// drain waits until the recorder has finished everything it was given.
func drain(t *testing.T, r *Recorder) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := r.Stats()
		if s.Depth == 0 && s.Written+s.Failed+s.Dropped >= s.Queued {
			time.Sleep(20 * time.Millisecond)
			s = r.Stats()
			if s.Depth == 0 && s.Written+s.Failed+s.Dropped >= s.Queued {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the recorder never drained: %+v", r.Stats())
}

func feedBlock(domain string) Event {
	return Event{
		Time: time.Now().UTC(), Domain: domain, QType: "A",
		ClientIP: "192.0.2.10", ClientName: "workstation-14",
		NetworkID: "n_1", NetworkName: "Office",
		Action: store.ActionBlocked, Blocked: true,
		Reason: "Blocked because it is known to host malware",
		Basis: policy.Basis{
			Rule: policy.RuleCategory, PolicyID: "p_std", PolicyName: "Standard",
			FeedID: "f_urlhaus", FeedName: "URLhaus", Category: "malware",
		},
	}
}

// The core success criterion for this phase: a DNS event becomes evidence,
// becomes a decision record, becomes an explanation — and every step is
// readable back from storage.
func TestADnsEventBecomesEvidenceADecisionAndAnExplanation(t *testing.T) {
	ctx := context.Background()
	r, st := newRecorder(t)

	r.Record(feedBlock("evil.example"))
	drain(t, r)

	// 1. Evidence exists, attributed to the feed that decided.
	ev, err := st.EvidenceFor(ctx, evidence.Domain("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("got %d evidence rows, want 1: %+v", len(ev), ev)
	}
	if ev[0].Kind != evidence.KindFeed || ev[0].Source != "f_urlhaus" {
		t.Errorf("evidence is not attributed to the feed: %+v", ev[0])
	}
	if ev[0].SourceName != "URLhaus" {
		t.Errorf("sourceName = %q", ev[0].SourceName)
	}

	// 2. A decision record exists.
	rows, err := st.ListDecisions(ctx, store.DecisionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d decisions, want 1", len(rows))
	}
	d := rows[0]
	if d.Action != store.ActionBlocked || d.Subject.Value != "evil.example" {
		t.Errorf("decision does not describe the block: %+v", d)
	}
	if d.ClientName != "workstation-14" || d.ClientIP != "192.0.2.10" {
		t.Errorf("client context was lost: %+v", d)
	}
	if d.QType != "A" {
		t.Errorf("qtype = %q", d.QType)
	}
	if d.Time.IsZero() {
		t.Error("no timestamp")
	}

	// 3. The policy path is the readable trace.
	for _, want := range []string{"network:Office", "policy:Standard", "category:malware", "BLOCK"} {
		if !strings.Contains(d.PolicyPath, want) {
			t.Errorf("policy path %q is missing %q", d.PolicyPath, want)
		}
	}

	// 4. The explanation names the source and its claim.
	if !strings.Contains(d.Explanation, "URLhaus") {
		t.Errorf("the explanation does not name what decided: %q", d.Explanation)
	}
	if !strings.Contains(d.Explanation, "malware") {
		t.Errorf("the explanation does not say what was claimed: %q", d.Explanation)
	}

	// 5. The decision links to the evidence, and says it was load-bearing.
	full, err := st.DecisionWithEvidence(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Cited) != 1 {
		t.Fatalf("the decision cites %d pieces of evidence, want 1", len(full.Cited))
	}
	if full.Cited[0].Evidence.ID != ev[0].ID {
		t.Error("the decision cites evidence that is not the evidence that was stored")
	}
	if !full.Cited[0].Contributed {
		t.Error("the evidence that decided is not marked as having contributed")
	}
}

// The property the whole feature rests on: an explanation is what was true
// when the decision was made. A feed dropping the domain tomorrow must not
// rewrite why it was blocked today.
func TestAnExplanationDoesNotChangeWhenTheFeedDoes(t *testing.T) {
	ctx := context.Background()
	r, st := newRecorder(t)

	r.Record(feedBlock("evil.example"))
	drain(t, r)

	before, err := st.ListDecisions(ctx, store.DecisionFilter{})
	if err != nil || len(before) != 1 {
		t.Fatalf("setup: %v %d", err, len(before))
	}
	original := before[0]

	// The world moves on: the feed that decided is deleted, and a different
	// source makes a fresh claim about the same domain.
	//
	// Both halves matter. Deleting alone would leave "cited evidence" and
	// "current evidence" both empty, so a decision that re-read the subject
	// would look identical to one that cited by ID — which is exactly how an
	// earlier version of this test passed against the wrong implementation.
	if _, err := st.DeleteEvidenceFrom(ctx, "f_urlhaus"); err != nil {
		t.Fatal(err)
	}
	later := feedBlock("evil.example")
	later.Basis.FeedID, later.Basis.FeedName = "f_other", "Some Other Feed"
	r.Record(later)
	drain(t, r)

	after, err := st.DecisionWithEvidence(ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The stored sentence is unchanged: it was written down, not regenerated.
	if after.Explanation != original.Explanation {
		t.Errorf("the explanation changed after the feed went away:\n before %q\n after  %q",
			original.Explanation, after.Explanation)
	}
	if after.PolicyPath != original.PolicyPath {
		t.Error("the policy path changed after the fact")
	}
	// The original decision cites nothing now, because the row it cited was
	// deleted. It must NOT have picked up the newer feed's claim: that claim
	// did not exist when this decision was made and citing it would be
	// rewriting history in the other direction.
	for _, c := range after.Cited {
		if c.Evidence.Source == "f_other" {
			t.Errorf("the decision cites evidence recorded after it was made: %+v", c.Evidence)
		}
	}
	if len(after.Cited) != 0 {
		t.Errorf("evidence deleted from the store still came back: %+v", after.Cited)
	}

	// And the domain does now have current evidence, so the check above is
	// distinguishing "cited by ID" from "re-read the subject" rather than
	// comparing two empty lists.
	current, err := st.EvidenceFor(ctx, evidence.Domain("evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 1 {
		t.Fatalf("the domain has %d current evidence rows, want the newer feed's claim", len(current))
	}
}

// No basis, no record. An explanation with nothing behind it is exactly what
// this feature exists to make impossible.
func TestNothingIsRecordedWithoutABasis(t *testing.T) {
	ctx := context.Background()
	r, st := newRecorder(t)

	e := feedBlock("ordinary.example")
	e.Basis = policy.Basis{} // an allowed query: no rule fired
	r.Record(e)

	// Also a basis whose rule this build does not understand.
	e2 := feedBlock("mystery.example")
	e2.Basis.Rule = policy.Rule("from_the_future")
	r.Record(e2)
	drain(t, r)

	rows, err := st.ListDecisions(ctx, store.DecisionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range rows {
		if d.Subject.Value == "ordinary.example" {
			t.Error("a query with no basis produced a decision record")
		}
		if d.Subject.Value == "mystery.example" && d.Explanation != "" {
			t.Errorf("an unknown rule produced an explanation from nothing: %q", d.Explanation)
		}
	}
}

// Explain must produce nothing when there is no evidence. This is the
// fabrication guard, tested directly rather than only through the recorder.
func TestExplainRefusesToWriteAnUnsupportedSentence(t *testing.T) {
	if got := Explain(feedBlock("x.example"), nil); got != "" {
		t.Errorf("an explanation was written with no evidence behind it: %q", got)
	}
	if got := Explain(feedBlock("x.example"), []store.CitedEvidence{}); got != "" {
		t.Errorf("an explanation was written from an empty citation list: %q", got)
	}
}

// Each rule produces evidence of the right kind, with wording that belongs to
// the source rather than to us. A provider's automated answer and a curated
// listing must not read as the same claim.
func TestEachRuleProducesItsOwnKindOfEvidence(t *testing.T) {
	for _, tc := range []struct {
		rule       policy.Rule
		wantKind   evidence.Kind
		wantConf   evidence.Confidence
		wantClaim  string
		setBasis   func(*policy.Basis)
		wantSource string
	}{
		{
			rule: policy.RuleCategory, wantKind: evidence.KindFeed,
			wantConf: evidence.ConfidenceHigh, wantClaim: "listed as malware",
			setBasis:   func(b *policy.Basis) { b.FeedID, b.FeedName = "f_x", "Feed X" },
			wantSource: "f_x",
		},
		{
			rule: policy.RuleReputation, wantKind: evidence.KindProvider,
			// Medium, not high: a third party's automated verdict is a weaker
			// claim than a curated listing and must not be shown as equal.
			wantConf: evidence.ConfidenceMedium, wantClaim: "reported as malware",
			setBasis:   func(b *policy.Basis) { b.ProviderName = "VirusTotal" },
			wantSource: "VirusTotal",
		},
		{
			rule: policy.RuleBlockList, wantKind: evidence.KindOperator,
			wantConf: evidence.ConfidenceHigh, wantClaim: "block-listed by an operator",
			setBasis:   func(b *policy.Basis) {},
			wantSource: "operator",
		},
		{
			rule: policy.RuleAllowList, wantKind: evidence.KindOperator,
			wantConf: evidence.ConfidenceHigh, wantClaim: "allow-listed by an operator",
			setBasis:   func(b *policy.Basis) {},
			wantSource: "operator",
		},
	} {
		t.Run(string(tc.rule), func(t *testing.T) {
			e := feedBlock("subject.example")
			e.Basis = policy.Basis{Rule: tc.rule, Category: "malware"}
			tc.setBasis(&e.Basis)

			got, ok := evidenceFor(e)
			if !ok {
				t.Fatal("no evidence produced")
			}
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("confidence = %q, want %q", got.Confidence, tc.wantConf)
			}
			if got.Claim != tc.wantClaim {
				t.Errorf("claim = %q, want %q", got.Claim, tc.wantClaim)
			}
			if got.Source != tc.wantSource {
				t.Errorf("source = %q, want %q", got.Source, tc.wantSource)
			}
		})
	}
}

// A full queue drops and counts rather than blocking. This is the property
// that keeps recording off the DNS path, so it is asserted rather than assumed.
func TestAFullQueueDropsRatherThanBlocking(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	// Deliberately never started: nothing drains, so the queue fills.
	r := New(st, Options{QueueSize: 4})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			r.Record(feedBlock("evil.example"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a full queue — this would put SQLite latency in the DNS path")
	}

	s := r.Stats()
	if s.Dropped == 0 {
		t.Error("a queue of four accepted a thousand events without dropping any")
	}
	if s.Queued+s.Dropped != 1000 {
		t.Errorf("events went missing: queued %d + dropped %d != 1000", s.Queued, s.Dropped)
	}
}

// The policy path omits what was not in force rather than rendering gaps. A
// deployment with one network and one policy should not be shown blanks.
func TestThePolicyPathOmitsWhatWasNotInForce(t *testing.T) {
	e := feedBlock("evil.example")
	e.NetworkName = ""
	e.Basis.PolicyName = ""

	got := PolicyPath(e)
	if strings.Contains(got, "network:") || strings.Contains(got, "policy:") {
		t.Errorf("path names things that were not set: %q", got)
	}
	if strings.Contains(got, "→ →") || strings.HasPrefix(got, "→") {
		t.Errorf("path has empty segments: %q", got)
	}
	if !strings.Contains(got, "BLOCK") {
		t.Errorf("path does not state the action: %q", got)
	}
}
