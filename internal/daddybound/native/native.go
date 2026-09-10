// Package native resolves a question from the root and validates what it
// found, as one operation.
//
// The two halves already existed and were separate: internal/daddybound/recursive
// walks delegations from the root hints to an authoritative server, and
// internal/daddybound/dnssec walks a chain of trust from a trust anchor to an
// RRset. Putting them together is not plumbing. It is the point at which
// Daddybound stops being a validator that reads records somebody else fetched
// and becomes a resolver that authenticates its own answers.
//
// The property this package exists to guarantee is the one that separates a
// real Live mode from a theatrical one:
//
//	the message returned is the message that was validated.
//
// Not "a message that agrees with the one that was validated", and not "a
// forwarded answer whose name was separately checked". Those are the two
// shapes a Live mode goes wrong in, and both look identical from outside. The
// guarantee here is structural rather than careful: the resolution happens
// once, its per-hop replies are pinned, and the validator is handed those
// exact replies instead of being allowed to ask the network again. If the
// validator saw it, it is what comes back; if it comes back, that is what was
// validated. There is no second fetch for the two to disagree about.
//
// Learn mode uses the same engine and discards the message, keeping only the
// verdict and the cost. That is deliberate: the evidence Learn collects is
// evidence about the code path Live will run, not about a similar one.
package native

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

// Config builds an Engine.
type Config struct {
	// Resolver does the recursion. Required.
	Resolver *recursive.Resolver

	// Anchors are the trust anchors validation starts from. An Engine with
	// none returns Indeterminate for everything, which is the honest answer
	// and is why no anchor is invented here.
	Anchors  dnssec.TrustAnchors
	Policy   dnssec.Policy
	Clock    dnssec.Clock
	Verifier dnssec.SignatureVerifier
	Limits   dnssec.Limits
}

// Engine resolves and validates.
//
// Safe for concurrent use. It holds no per-question state: everything one
// question needs lives in the Answer being built, which is what lets Learn run
// several workers against one Engine and share the resolver's cache and
// priming between them.
type Engine struct {
	cfg Config
	src *recursive.Source

	// dnssecCfg is the validator configuration, built once. A Validator is
	// constructed per question because each one is given that question's own
	// pinned source; the configuration behind it never changes.
	dnssecCfg dnssec.Config
}

// New builds an Engine.
func New(cfg Config) (*Engine, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("native: a resolver is required")
	}
	return &Engine{
		cfg: cfg,
		src: recursive.NewSource(cfg.Resolver),
		dnssecCfg: dnssec.Config{
			Anchors:  cfg.Anchors,
			Policy:   cfg.Policy,
			Clock:    cfg.Clock,
			Verifier: cfg.Verifier,
			Limits:   cfg.Limits,
		},
	}, nil
}

// Answer is one completed native resolution and the verdict on it.
type Answer struct {
	// Msg is the answer, spliced from the replies the authoritative servers
	// gave. This is the message Validation describes: see the package
	// comment.
	Msg *dns.Msg

	// Validation is what Daddybound concluded about Msg, walking the chain of
	// trust from a configured anchor.
	Validation dnssec.ValidationResult

	// Zone is the zone the answer came from — the deepest cut traversed.
	Zone string
	// Delegations are the zone cuts crossed, parent first.
	Delegations []recursive.Delegation
	// Trace is what the resolver did, in order.
	Trace []recursive.Step

	// Queries is how many questions left the process resolving the name.
	Queries int
	// Lookups is how many record lookups validation asked for. Ones the pin
	// answered cost no network traffic and are counted separately.
	Lookups int
	// Pinned is how many of those lookups were answered from the resolution
	// already in hand rather than by asking again. Every pinned lookup is a
	// link in the same-answer guarantee, so a zero here on an answer that had
	// records is a defect worth noticing.
	Pinned int

	// ResolveElapsed and ValidateElapsed split the cost, because they fail
	// for different reasons and are tuned by different limits.
	ResolveElapsed  time.Duration
	ValidateElapsed time.Duration
}

// Elapsed is the whole operation.
func (a *Answer) Elapsed() time.Duration { return a.ResolveElapsed + a.ValidateElapsed }

// Resolve answers one question from the root and validates the answer.
//
// A resolution failure is returned as an error and never as a verdict. "I
// could not reach the servers for this zone" and "this zone's data does not
// authenticate" are different facts about different things, and a caller that
// received the second when the first happened would be reading network weather
// as a security state. Callers that need a verdict for an unreachable name get
// it from the error, classified where the caller knows what it means.
func (e *Engine) Resolve(ctx context.Context, name string, rrtype uint16) (*Answer, error) {
	start := time.Now()
	res, err := e.cfg.Resolver.Resolve(ctx, name, rrtype)
	if err != nil {
		return nil, err
	}
	resolved := time.Now()

	// The pin is built from the resolution's own per-hop replies, which is
	// what makes this exact rather than approximate. An aliased answer is
	// several resolutions against several sets of servers, and pinning only
	// the spliced result would leave the chain's later links to be fetched
	// again — the second fetch usually agrees, and "usually" is not a
	// guarantee anybody should build a resolver on.
	p := newPin(res).bind(e.src)
	v := dnssec.New(p, e.dnssecCfg)
	verdict := v.Validate(ctx, name, rrtype)

	lookups, pinned := p.counts()
	return &Answer{
		Msg:             res.Msg,
		Validation:      verdict,
		Zone:            res.Zone,
		Delegations:     res.Delegations,
		Trace:           res.Trace,
		Queries:         res.Queries,
		Lookups:         lookups,
		Pinned:          pinned,
		ResolveElapsed:  resolved.Sub(start),
		ValidateElapsed: time.Since(resolved),
	}, nil
}

// Resolver exposes the underlying resolver, for status and diagnostics.
func (e *Engine) Resolver() *recursive.Resolver { return e.cfg.Resolver }

// question is a pin key.
type question struct {
	name   string
	rrtype uint16
}

// pin is a dnssec.Source that answers from a resolution already in hand and
// forwards everything else.
//
// This is the mechanism behind the same-answer guarantee. The validator asks
// for many things while walking a chain — DNSKEY and DS RRsets, denial proofs,
// the zone cuts along the way — and all of those go to the live source,
// because they are supporting evidence and the resolution did not fetch them.
// What the resolution *did* fetch is the answer itself, one reply per hop of
// the alias chain, and those are served from the pin. The validator therefore
// forms its opinion of the answer by looking at the answer, not at a
// re-fetched copy of it.
//
// It is deliberately not a cache. A cache would answer any question it happens
// to hold and would grow; this holds exactly the replies one resolution
// produced, answers only those questions, and is discarded when the answer is.
type pin struct {
	src dnssec.DelegationSource

	// answers is keyed by the questions the resolution answered. Read-only
	// after construction, so no lock guards it.
	answers map[question]dnssec.Response

	mu      sync.Mutex
	lookups int
	pinned  int
}

func newPin(res *recursive.Result) *pin {
	answers := make(map[question]dnssec.Response, len(res.Chain))
	for _, hop := range res.Chain {
		if hop.Msg == nil {
			continue
		}
		answers[question{name: dns.CanonicalName(hop.QName), rrtype: hop.QType}] = dnssec.Response{
			Rcode:     hop.Msg.Rcode,
			Answer:    hop.Msg.Answer,
			Authority: hop.Msg.Ns,
		}
	}
	return &pin{answers: answers}
}

// bind attaches the live source. Split from newPin only so the Engine can hold
// one source and hand it to each question's pin.
func (p *pin) bind(src dnssec.DelegationSource) *pin { p.src = src; return p }

func (p *pin) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	q := question{name: dns.CanonicalName(name), rrtype: rrtype}
	if resp, ok := p.answers[q]; ok {
		p.mu.Lock()
		p.lookups++
		p.pinned++
		p.mu.Unlock()
		return resp, nil
	}
	p.mu.Lock()
	p.lookups++
	p.mu.Unlock()
	if p.src == nil {
		return dnssec.Response{}, fmt.Errorf("native: no source for %s %s",
			name, dns.TypeToString[rrtype])
	}
	return p.src.Lookup(ctx, name, rrtype)
}

// ZoneCutsFor forwards to the live source, which is the only thing that knows
// where the referrals were. The pin holds replies, not paths.
func (p *pin) ZoneCutsFor(ctx context.Context, name string) (map[string]bool, bool) {
	if p.src == nil {
		return nil, false
	}
	return p.src.ZoneCutsFor(ctx, name)
}

func (p *pin) counts() (lookups, pinned int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lookups, p.pinned
}
