package trustanchors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// RFC 5011 automated trust-anchor rollover.
//
// The problem it solves: a validating resolver's trust anchor is the one thing
// it cannot learn from the DNS, and the root's key changes. Shipping the
// digest in the binary works until the key rolls, at which point every
// deployment that has not upgraded stops validating — or, worse, keeps
// validating against a key nobody signs with any more and reports the whole
// Internet Bogus.
//
// RFC 5011's answer is that a zone can announce its own key changes, and a
// resolver can accept them, *if* every announcement is signed by a key the
// resolver already trusts and every addition waits out a hold-down long enough
// that an operator would notice. That is the entire security argument, and
// both halves are load-bearing:
//
//   - signed by a currently trusted key, so an attacker who cannot sign cannot
//     introduce a key. This is why a DNSKEY RRset that fails to authenticate
//     changes nothing at all rather than changing something cautiously;
//   - held down for thirty days, so an attacker who *has* stolen a key cannot
//     quietly install their own alongside it and wait for the theft to be
//     forgotten. The zone's operators have thirty days to notice a key they
//     did not publish.
//
// What this implementation refuses to do, and why it is a deviation worth
// stating: RFC 5011 §5 says a trust point whose anchors have all been revoked
// is deleted, after which the data below it is evaluated as though no anchor
// were configured — which means Insecure. For a general-purpose resolver that
// is reasonable. For DNS Daddy it is the worst available outcome, because Live
// mode's entire premise is that answers are validated, and a resolver that
// silently stopped validating the root while continuing to serve would be
// lying by omission. So the trust point is kept, marked as needing an
// operator, and left with no trusted keys — which makes every verdict
// Indeterminate ("this validator cannot tell") rather than Insecure ("this
// data is provably unsigned"). RFC 5011 §8.2 says the same thing about what
// has to happen next: "A manual or other out-of-band update of all resolvers
// will be required."

// Hold-down and refresh timers, from RFC 5011 §2.3 and §2.4.
const (
	// DefaultAddHoldDown is RFC 5011 §2.4.1's thirty days. The RFC makes it
	// "30 days or the expiration time of the original TTL of the first trust
	// point DNSKEY RRSet that contained the new key, whichever is greater",
	// and the larger of the two is taken in addHoldDown below.
	DefaultAddHoldDown = 30 * 24 * time.Hour
	// DefaultRemoveHoldDown is RFC 5011 §2.4.2's thirty days, flat.
	DefaultRemoveHoldDown = 30 * 24 * time.Hour

	// maxQueryInterval, minQueryInterval and the retry bounds are §2.3's:
	//
	//	queryInterval = MAX(1 hr, MIN(15 days, 1/2*OrigTTL, 1/2*RRSigExpirationInterval))
	//	retryTime     = MAX(1 hour, MIN(1 day, .1*origTTL, .1*expireInterval))
	maxQueryInterval = 15 * 24 * time.Hour
	minQueryInterval = time.Hour
	maxRetryInterval = 24 * time.Hour
	minRetryInterval = time.Hour
)

// KeySource fetches a zone's apex DNSKEY RRset.
//
// Narrow on purpose. This package must not know how resolution works, and the
// wiring supplies a source backed by the native recursive resolver — so the
// keys that decide what this resolver trusts are fetched the same way
// everything else is, from the authoritative servers, rather than from a
// forwarder or over HTTPS from anywhere.
//
// Which is worth saying plainly: nothing here downloads a trust anchor. A key
// arriving from the network is evidence to be checked against a key already
// trusted, never a thing to be adopted because it arrived.
type KeySource interface {
	DNSKEY(ctx context.Context, zone string) (records []dns.RR, err error)
}

// ManagerConfig configures a Manager.
type ManagerConfig struct {
	// Zone is the trust point. "." for the root.
	Zone string
	// Configured are the anchors this build ships or the operator supplied,
	// in DS form. They seed a trust point with no stored state and they are
	// the fallback whenever managed state cannot be used.
	//
	// They are never discarded. A managed key set is an addition to these,
	// not a replacement for them: if the state file is lost, corrupt or
	// unwritable, the resolver falls back to validating with what it shipped
	// rather than with nothing.
	Configured dnssec.TrustAnchors

	Store  Store
	Source KeySource

	// Policy, Verifier and Limits are the same ones the validator uses. The
	// DNSKEY RRset that decides the next thirty days of trust is
	// authenticated by the same code and the same rules as any other RRset.
	Policy   dnssec.Policy
	Verifier dnssec.SignatureVerifier
	Limits   dnssec.Limits

	// Now is the clock. A test drives thirty days of hold-down through it.
	Now func() time.Time
	Log *slog.Logger

	// AddHoldDown and RemoveHoldDown override RFC 5011's thirty days.
	//
	// For tests, and for nothing else: a deployment that shortened these
	// would be shortening the window in which a stolen key's misuse can be
	// noticed, which is the only thing the hold-down buys. There is no
	// configuration path to them.
	AddHoldDown    time.Duration
	RemoveHoldDown time.Duration
}

func (c ManagerConfig) withDefaults() ManagerConfig {
	if c.Zone == "" {
		c.Zone = "."
	}
	c.Zone = dns.CanonicalName(c.Zone)
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.AddHoldDown <= 0 {
		c.AddHoldDown = DefaultAddHoldDown
	}
	if c.RemoveHoldDown <= 0 {
		c.RemoveHoldDown = DefaultRemoveHoldDown
	}
	return c
}

// Manager maintains one trust point's keys.
//
// Safe for concurrent use: Anchors is read on every validation and refresh runs
// on a timer.
type Manager struct {
	cfg ManagerConfig

	mu sync.RWMutex
	tp TrustPoint
	// anchors is the set Anchors returns, recomputed whenever tp changes so
	// that the hot path is a read of a prepared value.
	anchors dnssec.TrustAnchors
}

// NewManager loads the stored trust point, or seeds one from the configured
// anchors.
//
// A load failure is not fatal. It is logged, the configured anchors are used,
// and the first refresh will try to re-establish managed state — because a
// resolver that refused to start over an unreadable state file would be one
// that a deleted file takes offline, and the configured anchors are exactly as
// trustworthy as they were the day they were compiled in.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	cfg = cfg.withDefaults()
	if cfg.Store == nil {
		return nil, errors.New("trustanchors: a manager needs a store")
	}
	if len(cfg.Configured.Anchors()) == 0 {
		// Refused rather than defaulted. A manager with no configured
		// anchors has nothing to seed from and nothing to fall back to, and
		// the first validly signed DNSKEY RRset it saw would have to be
		// trusted on its own word — which is precisely the thing RFC 5011
		// exists not to do.
		return nil, errors.New("trustanchors: a manager needs configured anchors to start from")
	}

	m := &Manager{cfg: cfg}
	tp, err := cfg.Store.Load()
	switch {
	case errors.Is(err, ErrNoState):
		tp = TrustPoint{Zone: cfg.Zone}
	case err != nil:
		cfg.Log.Error("stored DNSSEC trust anchors could not be read; "+
			"validating with the configured anchors until a refresh succeeds",
			"zone", cfg.Zone, "error", err)
		tp = TrustPoint{Zone: cfg.Zone}
	case tp.Zone != cfg.Zone:
		cfg.Log.Error("stored DNSSEC trust anchors are for a different zone; ignoring them",
			"stored", tp.Zone, "configured", cfg.Zone)
		tp = TrustPoint{Zone: cfg.Zone}
	}

	m.tp = tp
	m.recompute()
	return m, nil
}

// Anchors returns the anchors to validate with, right now.
//
// Called on every validation, so it is a read of a value prepared by the last
// state change rather than a computation.
//
// The set is the union of the configured anchors and the trusted managed keys.
// Union rather than replacement: a managed set is what this resolver has
// learned in addition to what it shipped with, and dropping the configured
// anchors the moment managed state existed would mean one bad state file could
// leave a resolver trusting nothing.
func (m *Manager) Anchors() dnssec.TrustAnchors {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.anchors
}

// TrustPoint returns a snapshot of the managed state, for the status surface.
func (m *Manager) TrustPoint() TrustPoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tp := m.tp
	tp.Keys = append([]ManagedKey(nil), m.tp.Keys...)
	return tp
}

// recompute rebuilds the anchor set from the trust point. Called with the
// write lock held, or before the manager is shared.
//
// The set is the configured anchors that have not been revoked, plus the
// managed keys in a trusted state.
//
// Union rather than replacement, so that a lost or unwritable state file
// leaves a resolver validating with what it shipped rather than with nothing —
// but a *filtered* union, and the filter is not optional. RFC 5011 §2.2 makes
// a revoked key unusable for every purpose, and a configured digest still
// naming one does not change that: the operator's configuration is out of date
// rather than authoritative about the zone's current keys. Without this filter
// a revoked root key would go on being a trust anchor for as long as the
// digest stayed in the binary, which is the one outcome the REVOKE bit exists
// to prevent.
func (m *Manager) recompute() {
	revoked := m.revokedKeys()

	var anchors []dnssec.TrustAnchor
	seen := map[string]bool{}
	add := func(a dnssec.TrustAnchor) {
		if seen[anchorKey(a)] {
			return
		}
		seen[anchorKey(a)] = true
		anchors = append(anchors, a)
	}

	for _, a := range m.cfg.Configured.Anchors() {
		if matchesAny(m.cfg.Policy, a, revoked) {
			m.cfg.Log.Error("a configured DNSSEC trust anchor names a key the zone has revoked; "+
				"it is no longer being used",
				"zone", m.tp.Zone, "keyTag", a.KeyTag)
			continue
		}
		add(a)
	}

	for _, k := range m.tp.Keys {
		if !k.State.Trusted() {
			continue
		}
		key, err := k.DNSKEY()
		if err != nil {
			// A stored key that will not parse is dropped rather than
			// guessed at, and loudly: it is one fewer thing this resolver
			// trusts, which is the safe direction, but it is also a defect.
			m.cfg.Log.Error("a stored trust anchor could not be parsed and is being ignored",
				"zone", m.tp.Zone, "keyTag", k.KeyTag, "error", err)
			continue
		}
		a, err := anchorFromKey(m.tp.Zone, key)
		if err != nil {
			m.cfg.Log.Error("a stored trust anchor could not be converted to a digest",
				"zone", m.tp.Zone, "keyTag", k.KeyTag, "error", err)
			continue
		}
		add(a)
	}

	set, err := dnssec.NewTrustAnchors(anchors...)
	if err != nil {
		// Keep whatever was already in force. Replacing a working anchor set
		// with an empty one because a rebuild failed is the exact failure
		// this package is written to avoid.
		m.cfg.Log.Error("the trust anchor set could not be rebuilt; keeping the previous one",
			"zone", m.tp.Zone, "error", err)
		return
	}
	m.anchors = set
}

// revokedKeys returns the stored keys the zone has withdrawn.
func (m *Manager) revokedKeys() []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, k := range m.tp.Keys {
		if k.State != StateRevoked && k.State != StateRemoved {
			continue
		}
		// The stored form is the key as it was before revocation, which is
		// what a configured digest was computed over — so the comparison
		// below can still recognise it. That is what makes a revocation
		// detectable against a digest at all.
		key, err := k.DNSKEY()
		if err != nil {
			continue
		}
		out = append(out, key)
	}
	return out
}

// matchesAny reports whether an anchor names any of these keys.
func matchesAny(p dnssec.Policy, a dnssec.TrustAnchor, keys []*dns.DNSKEY) bool {
	for _, k := range keys {
		if a.MatchesKey(p, k) == dnssec.ReasonNone {
			return true
		}
	}
	return false
}

// Viable reports whether this trust point still has anything to validate with.
//
// False means every key has been revoked and the resolver can authenticate
// nothing under this trust point until an operator intervenes. It is not the
// same as "insecure": see checkViability.
func (m *Manager) Viable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.anchors.Anchors()) > 0
}

// anchorKey identifies an anchor for de-duplication.
func anchorKey(a dnssec.TrustAnchor) string {
	return fmt.Sprintf("%s|%d|%d|%d|%x", a.Name, a.KeyTag, a.Algorithm, a.DigestType, a.Digest)
}

// anchorFromKey turns a DNSKEY into an anchor by computing its digest.
//
// SHA-256, because that is what the root is published with and what RFC 8624
// makes mandatory to implement. The digest type is not read from anywhere an
// attacker could choose it.
func anchorFromKey(zone string, k *dns.DNSKEY) (dnssec.TrustAnchor, error) {
	ds := k.ToDS(dns.SHA256)
	if ds == nil {
		return dnssec.TrustAnchor{}, fmt.Errorf("no SHA-256 digest could be computed for key %d", k.KeyTag())
	}
	return dnssec.ParseTrustAnchorDS(fmt.Sprintf("%s %d %d %d %s",
		dns.CanonicalName(zone), ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest))
}
