// Package resolution is the seam between the DNS server and whatever actually
// answers a question.
//
// DNS Daddy has two ways of obtaining a DNS answer, and until this package
// existed they were two parallel systems rather than two implementations of one
// idea. internal/resolver forwards to configured upstream resolvers and serves
// clients; internal/daddybound resolves iteratively from the root and validated
// answers on the side. The server knew about the first and had a separate,
// deliberately powerless hook for the second.
//
// That split is the thing this package removes. A Backend answers a question;
// the server does not know or care which one it is talking to. Everything that
// differs between them — how the answer was obtained, whether DNSSEC was
// checked locally or merely claimed upstream, what the resolution cost — is
// carried in the Result, where it can be logged, shown and reasoned about,
// rather than being implied by which code path ran.
//
// The rule that shapes the interface: a Backend returns the answer it obtained.
// Not an answer that agrees with the one it validated, and not a forwarded
// answer with somebody else's opinion attached. Result.Authority is the field
// that keeps that honest — it says who checked, and "the upstream set a bit" is
// never recorded as the same thing as "we validated this ourselves".
package resolution

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// Backend answers DNS questions.
//
// Implementations are safe for concurrent use: one Backend serves every client
// of a deployment.
type Backend interface {
	// Resolve answers one question.
	//
	// generation is the blocklist generation the answer is valid under. A
	// backend that caches must not serve an answer cached under an older
	// generation, or a domain that was blocked while its answer sat in cache
	// would keep resolving until the TTL ran out.
	//
	// An error means no answer was obtained. It is never a verdict about the
	// data: the caller turns it into SERVFAIL, and a backend that returned a
	// DNSSEC state alongside an error would be inviting a caller to read
	// network weather as a security fact.
	Resolve(ctx context.Context, req *dns.Msg, generation uint64) (Result, error)

	// Name identifies this backend in logs, telemetry and the dashboard.
	// One of BackendNative or BackendForward.
	Name() string

	// Health is the current operational picture, over comparable windows.
	Health() Health

	// Purge drops every cached answer.
	Purge()

	// Close releases whatever the backend holds open.
	Close()
}

// The backends, named once so a log line, a metric label, a stored row and a
// dashboard string cannot drift apart.
const (
	// BackendNative: Daddybound resolved the answer itself, from the root
	// hints to the authoritative servers, and validated what it fetched.
	BackendNative = "daddybound-native"
	// BackendForward: the answer came from a configured upstream recursive
	// resolver.
	BackendForward = "forward"
)

// Result is one answered question.
type Result struct {
	// Msg is the response to return to the client.
	//
	// For the native backend this is the message that was validated — see
	// internal/daddybound/native on why that is structural rather than
	// hopeful. For the forwarding backend it is what the upstream sent.
	Msg *dns.Msg

	// Backend names what produced this. BackendNative or BackendForward.
	Backend string

	// Cached reports that the answer came from a cache rather than from the
	// network on this query.
	Cached bool

	// Collapsed reports that this caller waited on an identical resolution
	// already in flight rather than doing the work itself.
	//
	// Distinct from Cached, and the distinction is not pedantry. A collapsed
	// caller did no network work, so counting it as a cache hit would inflate
	// the hit rate every time a burst of clients asked the same cold question
	// — precisely when the rate is being watched. It also waited the full
	// latency of the leader's resolution, so it is not fast either. It is its
	// own thing and is reported as its own thing.
	Collapsed bool

	// DNSSEC is the security state of the answer.
	DNSSEC Status
	// DNSSECReason is the typed reason behind DNSSEC, from Daddybound's own
	// taxonomy where the verdict is local. Empty when there is nothing to say.
	DNSSECReason string

	// Authority says who reached the DNSSEC verdict, and it is the most
	// important field in this struct.
	//
	// A forwarder can only report what an upstream claimed by setting the AD
	// bit, which is a statement about a machine somebody else operates. The
	// native backend authenticates the records itself. Recording both as
	// "validated" would let the weaker measurement borrow the stronger one's
	// credibility — in a log an operator reads, in a dashboard that says
	// "DNSSEC: enforcing", and in a decision about whether to serve an answer.
	Authority Authority

	// Rcode is the response code, denormalised so a caller need not reach
	// into Msg to classify the outcome.
	Rcode int
	// MinTTL is the smallest TTL in the answer section, or 0 when there is no
	// answer. The beaconing detector uses it to tell a client polling on its
	// own clock from one re-resolving because its cache expired.
	MinTTL uint32
	// Elapsed is how long this resolution took, network time included.
	Elapsed time.Duration

	// Upstream is the forwarder that answered, empty for the native backend
	// and on a cache hit.
	Upstream string
	// Queries and Delegations are what native resolution cost: questions sent
	// to authoritative servers, and zone cuts crossed. Both zero for the
	// forwarding backend and on a cache hit.
	Queries     int
	Delegations int
}

// Authority says who reached a DNSSEC verdict.
type Authority string

const (
	// AuthorityLocal: Daddybound authenticated these records against a
	// configured trust anchor. The verdict is this deployment's own.
	AuthorityLocal Authority = "local"
	// AuthorityUpstream: an upstream resolver set — or did not set — the AD
	// bit, and that is all this deployment knows.
	//
	// Not a weaker kind of validation. It is a different measurement: it says
	// what a machine somebody else runs claims, over a link that may or may
	// not be authenticated, about records this deployment never saw.
	AuthorityUpstream Authority = "upstream"
	// AuthorityNone: nothing was checked and nothing was claimed.
	AuthorityNone Authority = ""
)

// Health is a backend's operational state over comparable windows.
//
// Every rate here is computed from counters covering the same period. That is
// not pedantry: dividing errors accumulated since process start by queries
// counted over the last five minutes produces a number that means nothing and
// grows without bound, which is what this deployment's dashboard did before
// this type existed.
type Health struct {
	// OK reports that the backend is working well enough to serve.
	OK bool
	// Detail is a sentence for an operator when OK is false, empty otherwise.
	Detail string

	// Window is the period every count and rate below covers.
	Window time.Duration
	// Queries and Errors are what happened in that window. An Error is an
	// internal failure to obtain an answer — a timeout, an unreachable
	// server — and never a correct security decision.
	Queries uint64
	Errors  uint64
	// Servfail counts answers returned to clients as SERVFAIL, including the
	// ones this resolver chose to send because an answer failed validation.
	Servfail uint64
	// Bogus counts answers Daddybound refused because they did not
	// authenticate.
	//
	// Reported separately from Errors, and this is the distinction Part 8 of
	// the milestone exists to make: refusing a forged answer is the resolver
	// working, not the resolver ill. A deployment whose users visit one
	// misconfigured signed domain must not read as unhealthy.
	Bogus uint64
	// Collapsed counts callers that waited on an identical resolution already
	// in flight. Not cache hits: see Result.Collapsed.
	Collapsed uint64
	// AuthoritativeTimeouts counts authoritative servers that did not answer,
	// for the native backend. Zero for the forwarding backend, whose
	// equivalent is Errors.
	AuthoritativeTimeouts uint64

	// CacheHitRate is over the same window, as a fraction between 0 and 1.
	// Negative means not measured — no lookups in the window — which is a
	// different fact from a rate of zero and must not be displayed as one.
	CacheHitRate float64

	// P50, P95 and P99 are resolution latencies over the window.
	//
	// Bucketed rather than exact: the histogram has fixed bounds so its memory
	// is fixed too, and a percentile read from it is the upper edge of the
	// bucket the percentile falls in. Reported as such rather than as a
	// precise figure, because a resolver on a 1 vCPU box should not be
	// keeping every latency sample to answer a dashboard.
	P50, P95, P99 time.Duration
}
