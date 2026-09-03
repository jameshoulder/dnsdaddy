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
	Basis       policy.Basis
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
	// An ordinary allowed query has no basis and nothing to explain.
	if !e.Basis.Decided() {
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

	cited, err := r.recordEvidence(wctx, e)
	if err != nil {
		r.failed.Add(1)
		// The domain is in the query log already, so naming it here discloses
		// nothing new, and without it the operator cannot tell which decision
		// went unrecorded.
		r.log.Warn("could not record the evidence behind a decision",
			"domain", e.Domain, "rule", string(e.Basis.Rule), "error", err.Error())
		return
	}

	d := store.Decision{
		Time:       e.Time,
		Subject:    evidence.Domain(e.Domain),
		Action:     e.Action,
		Category:   e.Basis.Category,
		Rule:       string(e.Basis.Rule),
		PolicyPath: PolicyPath(e),
		PolicyID:   e.Basis.PolicyID,
		NetworkID:  e.NetworkID,
		ClientIP:   e.ClientIP,
		ClientName: e.ClientName,
		QType:      e.QType,
	}
	d.Explanation = Explain(e, cited)

	if _, err := r.store.RecordDecision(wctx, d, cited); err != nil {
		r.failed.Add(1)
		r.log.Warn("could not record a decision",
			"domain", e.Domain, "rule", string(e.Basis.Rule), "error", err.Error())
		return
	}
	r.written.Add(1)
}

// recordEvidence writes the evidence implied by the basis and returns it.
//
// One piece of evidence per basis, because one rule fired. Everything else on
// file about the subject is shown alongside by the investigation view; only
// what actually decided is cited as contributing.
func (r *Recorder) recordEvidence(ctx context.Context, e Event) ([]store.CitedEvidence, error) {
	ev, ok := evidenceFor(e)
	if !ok {
		return nil, nil
	}
	stored, err := r.store.PutEvidence(ctx, ev)
	if err != nil {
		return nil, err
	}
	return []store.CitedEvidence{{Evidence: stored, Contributed: true}}, nil
}

// evidenceFor turns a basis into the claim it represents.
//
// The wording of each claim is the source's, not ours: a feed listing is
// described as a listing, a provider's answer as that provider's answer, and
// an operator's rule as a decision somebody made. Confidence follows the same
// logic — an operator's own rule and a curated feed are things somebody stands
// behind, a provider's automated verdict is not quite the same claim.
func evidenceFor(e Event) (evidence.Evidence, bool) {
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
	if e.Basis.PolicyName != "" {
		parts = append(parts, "policy:"+e.Basis.PolicyName)
	}
	switch e.Basis.Rule {
	case policy.RuleCategory:
		parts = append(parts, "category:"+categoryOr(e.Basis.Category, "unknown"))
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
	var b strings.Builder
	first := cited[0].Evidence

	if e.Blocked {
		b.WriteString("Blocked because ")
	} else {
		b.WriteString("Allowed because ")
	}
	b.WriteString(sourceLabel(first))
	b.WriteString(" ")
	b.WriteString(first.Claim)
	b.WriteString(".")

	if len(cited) > 1 {
		b.WriteString(" ")
		b.WriteString(othersLabel(len(cited) - 1))
	}
	return b.String()
}

func sourceLabel(e evidence.Evidence) string {
	if e.SourceName != "" {
		return e.SourceName
	}
	return e.Source
}

func othersLabel(n int) string {
	if n == 1 {
		return "One further source was on file at the time."
	}
	return "Further sources were on file at the time."
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
