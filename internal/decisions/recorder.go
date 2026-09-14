// Package decisions turns what the resolver decided into a record of why.
//
// # Where this sits
//
// The policy engine decides on the hot path and returns a Basis: which rule
// fired, which feed or provider was behind it, which policy was in force. That
// is all string headers already held by the compiled snapshot, so producing it
// costs nothing.
//
// This package takes that Basis somewhere else entirely — a bounded queue
// drained by its own worker — and does the expensive part there: writing the
// evidence rows, writing the decision, linking the two. Nothing in here is
// reachable from a DNS answer.
//
// # The one rule
//
// Every explanation is built from facts that were true at decision time and
// then stored. Nothing is re-derived at display time. A feed that drops a
// domain tomorrow must not change why it was blocked today, and the only way
// to guarantee that is to write the explanation down when it is made.
//
// This is also why the recorder never invents evidence. If the basis says a
// feed listed the domain, that is one piece of evidence with that feed as its
// source. If the basis says nothing, no decision is recorded at all — an
// explanation with no source behind it is worse than no explanation.
package decisions

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Event is everything the recorder needs, captured at decision time.
//
// A value, not a pointer into resolver state: by the time the worker reads it
// the query is long finished and anything it pointed at may have been reused.
type Event struct {
	// ID is the correlation the answer path minted, so the query-log row and
	// this record name each other. Empty lets the store assign one, which is
	// what a caller with nothing to correlate wants.
	ID          string
	Time        time.Time
	Domain      string
	QType       string
	ClientIP    string
	ClientName  string
	NetworkID   string
	NetworkName string
	Action      string
	Blocked     bool
	Reason      string
	Basis       *policy.Basis

	// Observed names the observe-mode engines that looked at this query and
	// what correlation each left behind.
	//
	// Deliberately not their verdicts. Every observe engine in this resolver
	// is asynchronous — detect.Engine.Observe is a channel send that returns
	// nothing, and Daddybound's verdict lands in its own table seconds later —
	// so at decision time there is no conclusion to record. What can be
	// recorded is that the engine saw the query and where its answer will be,
	// which is enough to join later and is true when written.
	//
	// This is also why nothing here can ever be read as the cause of a block:
	// it is written with RoleObserved and the recorder has no path that writes
	// an observe engine any other way.
	Observed []Observation
}

// Observation is one observe-mode engine's involvement in a query.
type Observation struct {
	// Engine is the short name: daddybound, detectors, first_seen.
	Engine string
	// Mode is what that engine is doing today. "observe" for all of them; the
	// field exists so a record written while an engine observed still says so
	// after that engine learns to enforce.
	Mode string
	// CorrelationID points at where this engine's conclusion will be found,
	// when it produces one. Empty when the engine leaves no row.
	CorrelationID string
}

// Recorder queues decisions and writes them off the resolution path.
type Recorder struct {
	store *store.Store
	log   *slog.Logger
	ch    chan Event
	done  chan struct{}
	// stopped is checked before every send so a queue that is being drained
	// does not accept work nobody will do.
	stopped atomic.Bool

	queued  atomic.Uint64
	dropped atomic.Uint64
	written atomic.Uint64
	failed  atomic.Uint64
}

// Options configures a Recorder.
type Options struct {
	// QueueSize bounds the queue. Full means drop and count, never block.
	QueueSize int
	Log       *slog.Logger
}

// New returns a Recorder. Run must be called to start draining.
func New(st *store.Store, o Options) *Recorder {
	size := o.QueueSize
	if size <= 0 {
		size = 1024
	}
	lg := o.Log
	if lg == nil {
		lg = slog.Default()
	}
	return &Recorder{store: st, log: lg, ch: make(chan Event, size), done: make(chan struct{})}
}

// Record offers a decision to the queue.
//
// Non-blocking, and that is the single most important line in this package.
// A blocking send would put SQLite's write latency into the DNS path: with the
// worker busy, every blocked query would wait for a disk write, and a slow
// disk would become a slow resolver. Dropping and counting is the same
// behaviour the query log already has, for the same reason.
func (r *Recorder) Record(e Event) {
	if r == nil || r.stopped.Load() {
		return
	}
	// An ordinary allowed query that nothing looked at has nothing to explain,
	// and recording one per query would turn this table into a second query
	// log that an attacker could fill with traffic.
	if !e.Basis.Decided() && len(e.Observed) == 0 {
		return
	}
	select {
	case r.ch <- e:
		r.queued.Add(1)
	default:
		r.dropped.Add(1)
	}
}

// Run drains the queue until ctx is cancelled.
func (r *Recorder) Run(ctx context.Context) {
	defer close(r.done)
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-r.ch:
			r.write(ctx, e)
		}
	}
}

// Wait blocks until Run has returned.
func (r *Recorder) Wait() {
	if r == nil {
		return
	}
	r.stopped.Store(true)
	<-r.done
}

// write persists one decision and the evidence behind it.
func (r *Recorder) write(ctx context.Context, e Event) {
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cited, truncated, err := r.recordEvidence(wctx, e)
	if err != nil {
		r.failed.Add(1)
		// The domain is in the query log already, so naming it here discloses
		// nothing new, and without it the operator cannot tell which decision
		// went unrecorded.
		r.log.Warn("could not record the evidence behind a decision",
			"domain", e.Domain, "rule", string(basisRule(e.Basis)), "error", err.Error())
		return
	}

	d := store.Decision{
		ID:         e.ID,
		Time:       e.Time,
		Subject:    evidence.Domain(e.Domain),
		Action:     e.Action,
		Category:   basisCategory(e.Basis),
		Rule:       string(basisRule(e.Basis)),
		PolicyPath: PolicyPath(e),
		PolicyID:   basisPolicyID(e.Basis),
		NetworkID:  e.NetworkID,
		ClientIP:   e.ClientIP,
		ClientName: e.ClientName,
		QType:      e.QType,
	}
	d.Completeness = store.CompleteRecord
	if truncated {
		d.Completeness = store.TruncatedRecord
	}
	d.Explanation = Explain(e, cited)

	if _, err := r.store.RecordDecision(wctx, d, cited); err != nil {
		r.failed.Add(1)
		r.log.Warn("could not record a decision",
			"domain", e.Domain, "rule", string(basisRule(e.Basis)), "error", err.Error())
		return
	}
	r.written.Add(1)
}

// MaxEvidence caps how many pieces of evidence one decision may cite.
//
// A decision today cites one or two things, so the cap is not load-bearing
// yet — it is here because the list grows with every engine that learns to
// contribute, and a row whose size is set by how many engines happen to be
// enabled is a row that will one day be enormous. Past the cap the record says
// truncated rather than presenting what fitted as the whole story.
const MaxEvidence = 16

// recordEvidence writes the evidence behind a decision and returns it, with
// the role each piece played.
//
// Ordered deliberately: what caused the outcome first, then what it overrode,
// then what merely watched. The cap therefore drops the least load-bearing
// evidence first — losing the record of an observe engine's involvement is a
// smaller loss than losing the listing that caused a block.
func (r *Recorder) recordEvidence(ctx context.Context, e Event) ([]store.CitedEvidence, bool, error) {
	type pending struct {
		ev   evidence.Evidence
		role store.Role
	}
	var want []pending

	if ev, ok := evidenceFor(e); ok {
		want = append(want, pending{ev, store.RoleCaused})
	}
	if ev, ok := overriddenEvidence(e); ok {
		want = append(want, pending{ev, store.RoleContributed})
	}
	for _, o := range e.Observed {
		if ev, ok := observedEvidence(e, o); ok {
			want = append(want, pending{ev, store.RoleObserved})
		}
	}

	truncated := false
	if len(want) > MaxEvidence {
		want = want[:MaxEvidence]
		truncated = true
	}

	out := make([]store.CitedEvidence, 0, len(want))
	for _, w := range want {
		stored, err := r.store.PutEvidence(ctx, w.ev)
		if err != nil {
			return nil, false, err
		}
		out = append(out, store.CitedEvidence{Evidence: stored, Role: w.role})
	}
	return out, truncated, nil
}

// overriddenEvidence is the listing an operator allow-list beat.
//
// Recorded as contributed rather than caused, because it did not cause this
// outcome — it caused the outcome that did not happen. An operator asking why
// a domain their feed calls malware is resolving needs to see both facts, and
// needs to see which one won.
func overriddenEvidence(e Event) (evidence.Evidence, bool) {
	if e.Basis == nil || e.Basis.Rule != policy.RuleAllowList {
		return evidence.Evidence{}, false
	}
	if e.Basis.OverrodeFeedName == "" && e.Basis.OverrodeFeedID == "" {
		return evidence.Evidence{}, false
	}
	ev := evidence.Evidence{
		Subject:    evidence.Domain(e.Domain),
		ObservedAt: e.Time,
		Kind:       evidence.KindFeed,
		Source:     e.Basis.OverrodeFeedID,
		SourceName: e.Basis.OverrodeFeedName,
		Category:   e.Basis.OverrodeCategory,
		Claim: "listed as " + categoryOr(e.Basis.OverrodeCategory, "malicious") +
			", overridden by the operator's allow-list",
		Confidence: evidence.ConfidenceHigh,
	}
	if ev.Source == "" {
		ev.Source = e.Basis.OverrodeFeedName
	}
	// The dates come across too. "Why is this malware domain resolving?" is
	// half-answered by naming the feed; the other half is how long it has been
	// saying so.
	applyListing(&ev, e.Basis.OverrodeListing)
	if err := ev.Validate(); err != nil {
		return evidence.Evidence{}, false
	}
	return ev, true
}

// observedEvidence records that an observe-mode engine looked at this query.
//
// The claim is about involvement, not about a conclusion, and it is worded
// that way on purpose. Writing "Daddybound found this bogus" here would be
// inventing a verdict that does not exist yet; writing "Daddybound examined
// this answer" is true at the moment it is written and stays true.
func observedEvidence(e Event, o Observation) (evidence.Evidence, bool) {
	if strings.TrimSpace(o.Engine) == "" {
		return evidence.Evidence{}, false
	}
	mode := o.Mode
	if mode == "" {
		mode = "observe"
	}
	claim := "examined this query in " + mode + " mode; it cannot change an outcome"
	if o.CorrelationID != "" {
		claim += " (record " + o.CorrelationID + ")"
	}
	ev := evidence.Evidence{
		Subject:    evidence.Domain(e.Domain),
		ObservedAt: e.Time,
		Kind:       evidence.KindLocal,
		Source:     o.Engine,
		SourceName: o.Engine,
		Claim:      claim,
		// Low, and that is the honest level for "this engine was present".
		// It is not a finding.
		Confidence: evidence.ConfidenceLow,
	}
	if err := ev.Validate(); err != nil {
		return evidence.Evidence{}, false
	}
	return ev, true
}

// evidenceFor turns a basis into the claim it represents.
//
// The wording of each claim is the source's, not ours: a feed listing is
// described as a listing, a provider's answer as that provider's answer, and
// an operator's rule as a decision somebody made. Confidence follows the same
// logic — an operator's own rule and a curated feed are things somebody stands
// behind, a provider's automated verdict is not quite the same claim.
func evidenceFor(e Event) (evidence.Evidence, bool) {
	// The nil check comes first, and it has to.
	//
	// It used to sit below the struct literal, which read e.Basis.Category and
	// therefore dereferenced the pointer it was about to test. That was
	// unreachable while Record refused every event whose basis had not
	// decided, so a nil basis never got this far. Admitting events that
	// decided nothing but were observed made it reachable, and the first such
	// event panicked the recorder's goroutine — taking the process with it,
	// from a statistics path that is not allowed to affect resolution at all.
	if e.Basis == nil {
		return evidence.Evidence{}, false
	}
	base := evidence.Evidence{
		Subject:    evidence.Domain(e.Domain),
		ObservedAt: e.Time,
		Category:   e.Basis.Category,
	}
	switch e.Basis.Rule {
	case policy.RuleAllowList:
		base.Kind = evidence.KindOperator
		base.Source, base.SourceName = "operator", "Operator allow-list"
		base.Claim = "allow-listed by an operator"
		base.Category = "allowed"
		base.Confidence = evidence.ConfidenceHigh

	case policy.RuleBlockList:
		base.Kind = evidence.KindOperator
		base.Source, base.SourceName = "operator", "Operator block-list"
		base.Claim = "block-listed by an operator"
		base.Confidence = evidence.ConfidenceHigh

	case policy.RuleCategory:
		base.Kind = evidence.KindFeed
		base.Source = e.Basis.FeedID
		base.SourceName = e.Basis.FeedName
		if base.Source == "" {
			base.Source = e.Basis.FeedName
		}
		base.Claim = "listed as " + categoryOr(e.Basis.Category, "malicious")
		// A curated feed is a human somewhere deciding a domain is malicious.
		base.Confidence = evidence.ConfidenceHigh
		applyListing(&base, e.Basis.Listing)

	case policy.RuleReputation:
		base.Kind = evidence.KindProvider
		base.Source, base.SourceName = e.Basis.ProviderName, e.Basis.ProviderName
		base.Claim = "reported as " + categoryOr(e.Basis.Category, "malicious")
		// Medium, not high: an automated answer from a third party is a
		// weaker claim than a curated listing, and the difference should be
		// visible to whoever reads the explanation.
		base.Confidence = evidence.ConfidenceMedium

	default:
		return evidence.Evidence{}, false
	}

	if err := base.Validate(); err != nil {
		return evidence.Evidence{}, false
	}
	return base, true
}

func categoryOr(category, fallback string) string {
	if strings.TrimSpace(category) == "" {
		return fallback
	}
	return category
}

// PolicyPath renders the decision trace an operator reads.
//
// Built from what was in force, so an empty segment is omitted rather than
// rendered as a gap: a deployment with one network and one policy should not
// be shown three arrows and two blanks.
func PolicyPath(e Event) string {
	parts := make([]string, 0, 4)
	if e.NetworkName != "" {
		parts = append(parts, "network:"+e.NetworkName)
	}
	if e.Basis != nil && e.Basis.PolicyName != "" {
		parts = append(parts, "policy:"+e.Basis.PolicyName)
	}
	switch basisRule(e.Basis) {
	case policy.RuleCategory:
		parts = append(parts, "category:"+categoryOr(basisCategory(e.Basis), "unknown"))
	case policy.RuleAllowList:
		parts = append(parts, "allow-list")
	case policy.RuleBlockList:
		parts = append(parts, "block-list")
	case policy.RuleReputation:
		parts = append(parts, "external intelligence")
	}
	parts = append(parts, strings.ToUpper(actionWord(e)))
	return strings.Join(parts, " → ")
}

func actionWord(e Event) string {
	if e.Blocked {
		return "block"
	}
	return "allow"
}

// Explain writes the sentence an operator reads.
//
// Derived entirely from the cited evidence. There is no branch in here that
// produces a sentence when nothing was cited, which is deliberate: an
// explanation that exists without evidence behind it is the thing this whole
// feature is meant to make impossible.
func Explain(e Event, cited []store.CitedEvidence) string {
	if len(cited) == 0 {
		return ""
	}

	// Only evidence that caused the outcome may be the subject of "because".
	//
	// Without this the sentence would be built from cited[0] whatever it was,
	// and a query that decided nothing but was looked at by an observe-mode
	// engine would read "Allowed because Daddybound examined this query" — a
	// sentence asserting that an engine which cannot change an outcome
	// produced one. The three-way role exists precisely so this function can
	// tell the difference, and this is where it has to.
	var cause *evidence.Evidence
	var overrode *evidence.Evidence
	observed := 0
	for i := range cited {
		switch cited[i].Role {
		case store.RoleCaused:
			if cause == nil {
				cause = &cited[i].Evidence
			}
		case store.RoleContributed:
			if overrode == nil {
				overrode = &cited[i].Evidence
			}
		case store.RoleObserved:
			observed++
		}
	}

	if cause == nil {
		// Nothing decided. Say so plainly rather than dressing an observation
		// up as a reason.
		if observed == 0 {
			return ""
		}
		return "No rule changed this outcome. " + observedLabel(observed) +
			" examined the query without being able to affect it."
	}

	var b strings.Builder
	if e.Blocked {
		b.WriteString("Blocked because ")
	} else {
		b.WriteString("Allowed because ")
	}
	b.WriteString(sourceLabel(*cause))
	b.WriteString(" ")
	b.WriteString(cause.Claim)
	b.WriteString(".")

	// The listing an allow-list beat is named rather than counted. It is the
	// one thing an operator asking "why is this malware domain resolving?"
	// actually wants, and folding it into "and 1 other" would hide it.
	if overrode != nil {
		b.WriteString(" This overrode ")
		b.WriteString(sourceLabel(*overrode))
		b.WriteString(", which ")
		b.WriteString(overriddenClaim(*overrode))
		b.WriteString(".")
	}
	if observed > 0 {
		b.WriteString(" ")
		b.WriteString(observedLabel(observed))
		b.WriteString(" also examined it, without affecting the outcome.")
	}
	return b.String()
}

// observedLabel counts observe-mode engines in words.
func observedLabel(n int) string {
	if n == 1 {
		return "One observe-mode engine"
	}
	return fmt.Sprintf("%d observe-mode engines", n)
}

// overriddenClaim trims the trailing note from an overridden listing's claim,
// because the sentence around it already says it was overridden.
func overriddenClaim(ev evidence.Evidence) string {
	if i := strings.Index(ev.Claim, ", overridden by"); i > 0 {
		return ev.Claim[:i]
	}
	return ev.Claim
}

func sourceLabel(e evidence.Evidence) string {
	if e.SourceName != "" {
		return e.SourceName
	}
	return e.Source
}

// Stats are the recorder's counters, for metrics and the dashboard.
type Stats struct {
	Queued  uint64 `json:"queued"`
	Dropped uint64 `json:"dropped"`
	Written uint64 `json:"written"`
	Failed  uint64 `json:"failed"`
	Depth   int    `json:"queueDepth"`
}

// Stats snapshots the counters.
func (r *Recorder) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	return Stats{
		Queued:  r.queued.Load(),
		Dropped: r.dropped.Load(),
		Written: r.written.Load(),
		Failed:  r.failed.Load(),
		Depth:   len(r.ch),
	}
}

// basisRule and basisCategory read a possibly-nil basis. An event with no
// basis still renders a path — network, policy, action — and simply names no
// rule, which is more useful than an empty string.
func basisRule(b *policy.Basis) policy.Rule {
	if b == nil {
		return policy.RuleNone
	}
	return b.Rule
}

func basisCategory(b *policy.Basis) string {
	if b == nil {
		return ""
	}
	return b.Category
}

func basisPolicyID(b *policy.Basis) string {
	if b == nil {
		return ""
	}
	return b.PolicyID
}

// applyListing copies a feed's listing dates onto one piece of evidence.
//
// ObservedAt stops being the time of the query and becomes the time the feed
// first listed the domain, which is what somebody reading the record actually
// wants: "URLhaus has called this malware since March" rather than "we looked
// this up at 14:02". The query's own time is already on the decision row.
//
// A listing with no known dates leaves the evidence exactly as it was, so an
// installation that upgraded into this feature keeps recording what it always
// did rather than acquiring a field full of zeroes.
func applyListing(ev *evidence.Evidence, l policy.Listing) {
	if ev == nil || !l.Known() {
		return
	}
	if !l.FirstSeen.IsZero() {
		ev.ObservedAt = l.FirstSeen
	}
	if !l.ExpiresAt.IsZero() {
		expires := l.ExpiresAt
		ev.ExpiresAt = &expires
	}
	if !l.LastSeen.IsZero() {
		ev.Claim += ", last confirmed " + l.LastSeen.UTC().Format("2 January 2006")
	}
}
