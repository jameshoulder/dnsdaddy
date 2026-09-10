package resolution

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/resolver"
)

// Forward is the Backend over DNS Daddy's forwarding resolver.
//
// An adapter and nothing more. internal/resolver is unchanged by this
// milestone: it is the path every existing deployment runs, it has been in
// production, and replacing a working subsystem to make an interface tidier
// would be trading reliability for symmetry. What this adds is the vocabulary —
// which backend answered, what may honestly be said about DNSSEC — that lets
// the server stop knowing the difference.
//
// The DNSSEC state of a forwarded answer is always StatusUnchecked, whatever
// the upstream's AD bit says. That is the point of AuthorityUpstream: the bit
// is recorded, so an operator can see what Quad9 claimed, and it is recorded as
// a claim rather than as a verdict this deployment reached. A forwarder that
// reported "secure" because a packet arrived with a flag set would be lending
// its own credibility to a machine it does not run, over a link it may not have
// authenticated, about records it never saw.
type Forward struct {
	r      *resolver.Resolver
	window *Window
	now    func() time.Time
}

// NewForward wraps a forwarding resolver.
func NewForward(r *resolver.Resolver, now func() time.Time) *Forward {
	if now == nil {
		now = time.Now
	}
	return &Forward{r: r, window: NewWindow(now), now: now}
}

// Name identifies this backend.
func (f *Forward) Name() string { return BackendForward }

// Resolver exposes the wrapped resolver, for the surfaces that legitimately
// need forwarder-specific detail: per-upstream statistics, the cache size, the
// in-flight limit. Nothing on the answer path uses it.
func (f *Forward) Resolver() *resolver.Resolver { return f.r }

// Resolve forwards the question.
func (f *Forward) Resolve(ctx context.Context, req *dns.Msg, generation uint64) (Result, error) {
	start := f.now()
	res, err := f.r.Resolve(ctx, req, generation)
	elapsed := f.now().Sub(start)

	if err != nil {
		f.window.Record(Sample{Elapsed: elapsed, Err: true, Servfail: true})
		return Result{}, err
	}

	out := Result{
		Msg:      res.Msg,
		Backend:  BackendForward,
		Cached:   res.Cached,
		DNSSEC:   StatusUnchecked,
		Rcode:    res.Rcode,
		MinTTL:   res.MinTTL,
		Elapsed:  elapsed,
		Upstream: res.Upstream,
		// Upstream even when the bit is clear: "this upstream did not claim
		// to have validated" is still a statement about the upstream, and
		// AuthorityNone would suggest nobody was asked.
		Authority: AuthorityUpstream,
	}
	if res.Validated {
		out.DNSSECReason = "the upstream set the AD bit"
	}
	f.window.Record(Sample{
		Elapsed:  elapsed,
		Cached:   res.Cached,
		Servfail: res.Rcode == dns.RcodeServerFailure,
	})
	return out, nil
}

// Health reports the forwarder's state over the rolling window.
func (f *Forward) Health() Health {
	h := f.window.Snapshot()
	h.OK, h.Detail = judge(h)
	return h
}

// Purge drops every cached answer.
func (f *Forward) Purge() { f.r.Cache().Purge() }

// Close releases upstream connections.
func (f *Forward) Close() { f.r.Close() }

// judge decides whether a window's numbers describe a working resolver.
//
// Two rules, and the second one is the point of Part 8 of this milestone.
//
// Errors are internal failures to obtain an answer. A rate above a fifth of
// queries means the resolver is not doing its job, whatever the reason.
//
// Bogus answers are not errors and do not count. Refusing a forged or
// misconfigured signed answer is this resolver working exactly as intended, and
// a deployment whose users visit one broken signed domain must not read as ill.
// That distinction has to be made here, in the one place health is decided,
// because anywhere else it will be made differently.
//
// A window with too few queries to mean anything is healthy by default. The
// alternative — unknown reads as unhealthy — turns a quiet night into an alert.
func judge(h Health) (bool, string) {
	const (
		minSample = 20
		maxErrors = 0.20
	)
	if h.Queries < minSample {
		return true, ""
	}
	rate := float64(h.Errors) / float64(h.Queries)
	if rate > maxErrors {
		return false, "the resolver failed to obtain an answer for more than a fifth of " +
			"recent queries; this is a resolver or network fault, not a security decision"
	}
	return true, ""
}
