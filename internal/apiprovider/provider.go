// Package apiprovider is DNS Daddy's "bring your own intelligence" layer: the
// types, registry, and resilience machinery for external threat-intelligence,
// reputation and enrichment services an operator configures themselves.
//
// Three rules shape everything here, and they are worth stating before the
// types because they explain most of the design decisions.
//
// # Nothing in this package may block a DNS answer
//
// The resolution path reads a cache and enqueues. It never dials, never waits
// on a rate limiter, and never blocks on a lock a network call holds. Even in
// the one mode where the policy engine will wait for a verdict, it waits on a
// bounded channel with a hard deadline and treats the deadline as "unknown",
// which never blocks a name. A provider outage must not become a DNS outage.
//
// # Every provider response is hostile input
//
// Bodies are read through a limit reader, JSON is decoded into typed structs,
// scores are clamped, and strings that reach the dashboard are bounded. A
// provider is a third party the operator chose to trust for intelligence; that
// is not the same as trusting it with this process's memory.
//
// # Unknown is not a verdict
//
// A provider that has not answered, failed, or returned nothing says
// DispositionUnknown, and unknown never blocks. The failure mode being
// designed against is a service outage silently turning into a network outage.
package apiprovider

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
)

// Capability is one thing a provider can do. An adapter declares which it
// supports; an operator separately chooses which to switch on.
type Capability string

const (
	// CapReputation answers "is this bad?" about one subject.
	CapReputation Capability = "reputation"
	// CapEnrichment adds context without judging.
	CapEnrichment Capability = "enrichment"
	// CapFeed is a bulk download parsed like any other blocklist.
	CapFeed Capability = "feed"
)

// Valid reports whether c is a capability this package knows.
func (c Capability) Valid() bool {
	switch c {
	case CapReputation, CapEnrichment, CapFeed:
		return true
	}
	return false
}

// ParseCapabilities keeps only the capabilities this build understands.
//
// Configuration outlives code in both directions: a downgrade reads rows
// written by a newer binary that knew a capability this one does not. Dropping
// what we cannot honour is the safe direction — the alternative is a provider
// enabled for something this binary will silently not do.
func ParseCapabilities(in []string) []Capability {
	out := make([]Capability, 0, len(in))
	seen := map[Capability]bool{}
	for _, s := range in {
		c := Capability(strings.ToLower(strings.TrimSpace(s)))
		if c.Valid() && !seen[c] {
			out = append(out, c)
			seen[c] = true
		}
	}
	return out
}

// SubjectKind says what is being asked about.
type SubjectKind string

const (
	SubjectDomain SubjectKind = "domain"
	SubjectURL    SubjectKind = "url"
	SubjectIP     SubjectKind = "ip"
)

// Subject is the thing a lookup is about.
type Subject struct {
	Kind SubjectKind
	// Value is normalised by the caller: lower-cased, trailing dot stripped.
	// Adapters must not re-normalise, because the cache is keyed on this exact
	// string and a second opinion about normalisation is a cache that misses
	// every time.
	Value string
}

// DomainSubject builds a normalised domain subject.
func DomainSubject(name string) Subject {
	return Subject{Kind: SubjectDomain, Value: NormaliseDomain(name)}
}

// NormaliseDomain lower-cases a name and strips the root dot.
//
// The cache key. It has to agree exactly with what the policy engine passes,
// or every lookup is a miss and every miss is a paid API call.
func NormaliseDomain(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	return strings.TrimSuffix(name, ".")
}

// Descriptor is an adapter's self-description, used by the dashboard to render
// a provider and by the engine to decide what it may be asked.
type Descriptor struct {
	// Kind is the registry key. Stable: it is stored in the database.
	Kind string `json:"kind"`
	// DisplayName is what an operator sees.
	DisplayName string `json:"displayName"`
	// Capabilities is what this adapter can do, not what is switched on.
	Capabilities []Capability `json:"capabilities"`
	// DocsURL points at the vendor's own documentation, so an operator can
	// check what they are agreeing to send.
	DocsURL string `json:"docsUrl,omitempty"`
	// PrivacyNote states, in one sentence, what leaves the network. Required
	// of every adapter: a provider whose disclosure nobody wrote down is one
	// an operator cannot make an informed decision about.
	PrivacyNote string `json:"privacyNote"`
}

// Verdict is a provider's normalised answer.
type Verdict struct {
	// Score is 0..1. Adapters clamp; the store clamps again.
	Score float64
	// Disposition is the judgement. Unknown never blocks.
	Disposition Disposition
	// Categories are catalogue names where they map, dropped where they do not.
	Categories []string
	// TTL is how long this answer is good for, if the provider said. Zero
	// means "use the provider's configured default".
	TTL time.Duration
	// Raw is a bounded excerpt of what the provider actually returned, so an
	// operator can check the normalisation rather than trust it.
	Raw string
}

// Disposition mirrors store.Disposition without importing it.
//
// The dependency would be the wrong way round: store is persistence and this
// is domain logic, and a provider adapter should not need the database package
// in scope to say "malicious". The two are converted at the one boundary that
// writes rows.
type Disposition string

const (
	DispositionUnknown    Disposition = "unknown"
	DispositionBenign     Disposition = "benign"
	DispositionSuspicious Disposition = "suspicious"
	DispositionMalicious  Disposition = "malicious"
)

// Enrichment is context about a subject. Never a judgement.
type Enrichment struct {
	Data map[string]string
	TTL  time.Duration
}

// Provider is the minimum: something that can say what it is.
type Provider interface {
	Descriptor() Descriptor
}

// ReputationProvider answers whether a subject is malicious.
type ReputationProvider interface {
	Provider
	Reputation(ctx context.Context, s Subject) (Verdict, error)
}

// Enricher adds context to a subject.
type Enricher interface {
	Provider
	Enrich(ctx context.Context, s Subject) (Enrichment, error)
}

// FeedSource offers a bulk list, parsed like any other blocklist feed.
type FeedSource interface {
	Provider
	// Fetch returns the body and its content type. The caller closes.
	Fetch(ctx context.Context) (io.ReadCloser, string, error)
}

// HealthChecker proves the credential works.
//
// Separate from Reputation on purpose: on a metered API, testing a connection
// should not spend a lookup from the operator's quota, and several services
// have a dedicated quota or account endpoint that costs nothing.
type HealthChecker interface {
	Provider
	CheckHealth(ctx context.Context) error
}

// Errors an adapter or the engine may return. Callers distinguish them because
// they mean different things to an operator: a missing capability is a
// configuration mistake, an open circuit is a service that is down, and an
// auth failure is a credential to re-enter.
var (
	// ErrNotSupported means the adapter does not implement the capability.
	// Returned rather than a zero value, which would read as a real answer.
	ErrNotSupported = errors.New("apiprovider: capability not supported by this provider")

	// ErrCircuitOpen means the breaker is open and no call was attempted.
	ErrCircuitOpen = errors.New("apiprovider: circuit open, provider not called")

	// ErrUnauthorised means the provider rejected the credential.
	ErrUnauthorised = errors.New("apiprovider: provider rejected the credential")

	// ErrRateLimited means the provider said to slow down.
	ErrRateLimited = errors.New("apiprovider: provider rate-limited this request")

	// ErrNoCredential means no credential is stored, or it could not be
	// opened. Distinguished from ErrUnauthorised: one is fixed by entering a
	// key, the other by restoring secrets.key.
	ErrNoCredential = errors.New("apiprovider: no usable credential")

	// ErrBadResponse means the provider answered in a shape this adapter does
	// not understand.
	ErrBadResponse = errors.New("apiprovider: provider response could not be understood")
)

// InstanceConfig is what an adapter is constructed with: the operator's
// non-secret settings, the credential, and the shared client.
//
// The credential is passed as a value rather than fetched by the adapter, so
// there is exactly one place in the codebase that opens a sealed secret and
// every adapter is downstream of it.
type InstanceConfig struct {
	// ID is the provider row's identifier, used for cache keys, metrics
	// labels, and log fields. Never a credential.
	ID string
	// Name is the operator's label.
	Name string
	// Settings are the non-secret adapter settings.
	Settings map[string]string
	// Secret is the opened credential, or empty when none is stored.
	//
	// Adapters must never log it, wrap it into an error, or return it. The
	// leak test in this package scans for exactly that.
	Secret string
	// Client is the shared resilient HTTP client, already carrying this
	// provider's timeout, rate limiter and breaker.
	Client *Client
	// CacheTTL is the operator's configured default freshness.
	CacheTTL time.Duration
}

// Setting reads a non-secret setting, returning fallback when unset.
func (c InstanceConfig) Setting(key, fallback string) string {
	if v, ok := c.Settings[key]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

// RedactedPlaceholder is what a credential is replaced with.
//
// Visible rather than silent: an operator looking at a stored excerpt should
// be able to tell that something was removed, both because it explains a gap
// in the JSON and because it is evidence their provider is echoing the key
// back — which is worth knowing.
const RedactedPlaceholder = "[redacted]"

// Redact removes the credential from a string.
//
// Needed because Verdict.Raw is a slice of a third party's response, and that
// response is not guaranteed not to contain the credential we just sent it.
// Safe Browsing takes its key in the query string, so any service — or any
// proxy in front of one — that echoes the request URL back in an error puts
// the key straight into a string this code then writes to the database and
// renders on the dashboard.
//
// Found by a test, not by review: the first version of the leak test only
// exercised the failure path, where the client returns an error and no
// response at all, so a deliberately planted leak into Raw went undetected.
func (c InstanceConfig) Redact(s string) string {
	if c.Secret == "" || s == "" {
		return s
	}
	out := strings.ReplaceAll(s, c.Secret, RedactedPlaceholder)
	// And the percent-encoded form, because a credential that travelled in a
	// URL comes back encoded and a plain replace would miss it.
	if enc := url.QueryEscape(c.Secret); enc != c.Secret {
		out = strings.ReplaceAll(out, enc, RedactedPlaceholder)
	}
	return out
}

// SafeExcerpt is Excerpt with the credential removed.
//
// The only excerpt an adapter should use. Response.Excerpt has no idea what
// the credential is — it is a method on a body, not on a provider — so the
// redaction has to happen at the one layer that knows both.
func (c InstanceConfig) SafeExcerpt(r *Response, limit int) string {
	if r == nil {
		return ""
	}
	return c.Redact(r.Excerpt(limit))
}

// Clamp01 bounds a score to [0, 1].
//
// Exported because every adapter needs it and because a score outside the
// range is the single easiest way for a hostile or buggy provider to clear
// every threshold downstream.
func Clamp01(f float64) float64 {
	switch {
	case f < 0:
		return 0
	case f > 1:
		return 1
	// NaN compares false against everything above, so it lands here and is
	// caught by the self-comparison. Left implicit it would flow into the
	// database and make every threshold comparison false, which reads as
	// "benign" rather than as the broken value it is.
	case f != f:
		return 0
	default:
		return f
	}
}

// DispositionFor maps a score to a disposition using conventional thresholds.
//
// Adapters that have a better signal than a score — an explicit verdict field,
// a vendor's own category — should set the disposition directly and ignore
// this. It exists for the ones that genuinely only have a number.
func DispositionFor(score float64) Disposition {
	switch {
	case score >= 0.75:
		return DispositionMalicious
	case score >= 0.4:
		return DispositionSuspicious
	default:
		return DispositionBenign
	}
}
