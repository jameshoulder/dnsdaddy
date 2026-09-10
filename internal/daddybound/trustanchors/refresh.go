package trustanchors

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// RefreshResult is what one refresh did.
type RefreshResult struct {
	// At is when the refresh ran.
	At time.Time
	// OK reports that a validly signed DNSKEY RRset was obtained and the
	// state machine was advanced. False means nothing was changed.
	OK bool
	// Err is why it failed, empty on success.
	Err string
	// Changes lists the state transitions, in the order they were applied,
	// for the log and the status surface. Empty on a refresh that found
	// nothing new, which is the normal case.
	Changes []string
	// NextRefresh is when the next attempt is due.
	NextRefresh time.Time
}

// Refresh performs one RFC 5011 active refresh.
//
// The order of operations is the security argument, so it is worth reading as
// a sequence rather than as five paragraphs:
//
//  1. fetch the trust point's DNSKEY RRset;
//  2. authenticate it against the keys this resolver *already* trusts — and
//     only those, never against the RRset's own new keys;
//  3. if that fails, change nothing and record why;
//  4. otherwise advance the state machine, which can move a key into
//     add-pending, promote one whose hold-down has passed, mark one missing,
//     revoke one, or forget one;
//  5. persist, and only then let the new set take effect.
//
// Step 3 is the one that is easy to get wrong in a way that looks like
// robustness. A refresh that could not authenticate the RRset has learned
// nothing — not that the keys have changed, not that they have not — and
// anything it did to the state on that basis would be a change an attacker who
// can drop or corrupt packets got to choose.
func (m *Manager) Refresh(ctx context.Context) RefreshResult {
	now := m.cfg.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	res := RefreshResult{At: now}
	m.tp.LastRefresh = now

	records, err := m.fetch(ctx)
	if err != nil {
		return m.failed(&res, now, err)
	}

	set, sigs, origTTL, sigExpiry, err := splitDNSKEY(m.cfg.Zone, records, now)
	if err != nil {
		return m.failed(&res, now, err)
	}

	// The keys this resolver trusts at this instant. Note what is *not* here:
	// the keys that just arrived. RFC 5011 §5 step 2 — the RRset must be
	// validated by a key that is already a trust anchor — and it is the whole
	// of the protocol's resistance to key injection.
	trusted := m.trustedKeys(set)

	// Plus the one carve-out RFC 5011 §2.2 allows. A revoked key may be used
	// for nothing except validating the RRSIG it made over the RRset that
	// announces its own revocation — so a key that was trusted before it was
	// revoked, and that signed this RRset itself, is admitted here and
	// nowhere else. Without it the last key at a trust point could never be
	// retired: revoking it would make the announcement unauthenticatable and
	// the resolver would go on trusting a withdrawn key for ever.
	selfRevoked := m.selfRevokedKeys(ctx, set, sigs, now)
	trusted = append(trusted, selfRevoked...)

	if len(trusted) == 0 {
		return m.failed(&res, now, fmt.Errorf(
			"no trusted key is present in the %s DNSKEY RRset, so it cannot be authenticated; "+
				"the configured anchors remain in force", m.cfg.Zone))
	}

	reason, _ := dnssec.AuthenticateRRset(ctx, m.validatorConfig(), set, sigs, m.cfg.Zone, trusted, now)
	if reason != dnssec.ReasonVerified && reason != dnssec.ReasonNone {
		return m.failed(&res, now, fmt.Errorf(
			"the %s DNSKEY RRset did not authenticate against a currently trusted key (%s); "+
				"nothing was changed", m.cfg.Zone, reason))
	}

	res.Changes = m.advance(set.Records, proven(selfRevoked), now, origTTL)

	m.tp.LastSuccess = now
	m.tp.LastError = ""
	m.tp.NextRefresh = now.Add(queryInterval(origTTL, sigExpiry))
	res.OK = true
	res.NextRefresh = m.tp.NextRefresh

	m.persist()

	for _, c := range res.Changes {
		m.cfg.Log.Warn("DNSSEC trust anchor state changed", "zone", m.cfg.Zone, "change", c)
	}
	return res
}

// failed records a refresh that learned nothing, leaving the anchors alone.
func (m *Manager) failed(res *RefreshResult, now time.Time, err error) RefreshResult {
	res.Err = err.Error()
	m.tp.LastError = res.Err
	m.tp.NextRefresh = now.Add(retryInterval(m.lastTTL()))
	res.NextRefresh = m.tp.NextRefresh

	// The failure is persisted; the key states are untouched because nothing
	// above this line touched them. Persisting matters: an operator needs to
	// see that refreshes have been failing for a fortnight, and a state file
	// that only recorded successes would look healthy the whole time.
	m.persist()

	m.cfg.Log.Warn("a DNSSEC trust anchor refresh failed; the anchors in force are unchanged",
		"zone", m.cfg.Zone, "error", err, "retryAt", m.tp.NextRefresh)
	return *res
}

// persist writes the trust point, treating a write failure as non-fatal.
//
// A resolver that could not save its state must keep validating with the
// anchors it has. The cost of an unwritable file is that hold-down progress is
// lost across a restart, which is a delay; the cost of treating it as fatal
// would be an outage.
func (m *Manager) persist() {
	if err := m.cfg.Store.Save(m.tp); err != nil {
		m.cfg.Log.Error("DNSSEC trust anchor state could not be saved; "+
			"the anchors in force are unaffected, but hold-down progress will be lost on restart",
			"zone", m.cfg.Zone, "error", err)
	}
}

func (m *Manager) validatorConfig() dnssec.Config {
	return dnssec.Config{
		Policy:   m.cfg.Policy,
		Verifier: m.cfg.Verifier,
		Limits:   m.cfg.Limits,
		Clock:    dnssec.FixedClock{Instant: m.cfg.Now()},
	}
}

func (m *Manager) fetch(ctx context.Context) ([]dns.RR, error) {
	if m.cfg.Source == nil {
		return nil, fmt.Errorf("no key source is configured for %s", m.cfg.Zone)
	}
	records, err := m.cfg.Source.DNSKEY(ctx, m.cfg.Zone)
	if err != nil {
		return nil, fmt.Errorf("fetching the %s DNSKEY RRset: %w", m.cfg.Zone, err)
	}
	return records, nil
}

// trustedKeys returns the keys from the fetched RRset that this resolver
// already trusts.
//
// Selected out of the arriving RRset rather than reconstructed from stored key
// material, because a signature has to be checked against the key as
// published. A stored key and an arriving key that agree on tag and algorithm
// but differ in their material are not the same key, and the digest comparison
// below is what says so.
func (m *Manager) trustedKeys(set dnssec.RRset) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range set.Records {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		if m.isTrusted(key) {
			out = append(out, key)
		}
	}
	return out
}

// selfRevokedKeys returns the revoked keys in this RRset that were trusted
// before their revocation and that signed this RRset themselves.
//
// RFC 5011 §2.2 defines revocation as seeing the key "in a self-signed RRSet"
// with the REVOKE bit set, and the self-signature is not a formality. Accepting
// a revocation announced by *any* trusted key would mean one stolen key could
// revoke every other key at the trust point — and since a trust point with all
// its keys revoked can no longer be maintained automatically, that turns a
// single key compromise into a resolver that has to be fixed by hand
// everywhere. Requiring each revocation to be signed by the key being revoked
// bounds the damage to the key that was actually stolen.
//
// The cost is real and worth stating: a key whose private half has been
// destroyed can never be revoked, only left to sit in Missing until an
// operator retires it. That is the trade RFC 5011 makes, and it is the right
// way round.
//
// Each candidate is checked on its own — the RRset is authenticated against a
// key set containing only that key — because "some signature here verifies"
// and "this key signed this" are different questions and only the second one
// justifies a revocation.
func (m *Manager) selfRevokedKeys(
	ctx context.Context, set dnssec.RRset, sigs []*dns.RRSIG, now time.Time,
) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range set.Records {
		key, ok := rr.(*dns.DNSKEY)
		if !ok || key.Flags&dns.REVOKE == 0 {
			continue
		}
		// Was this key trusted before it was revoked? The stored and
		// configured forms carry no REVOKE bit, so the comparison is made
		// against the key with the bit cleared.
		unrevoked := *key
		unrevoked.Flags &^= dns.REVOKE
		if !m.isTrusted(&unrevoked) {
			continue
		}
		reason, _ := dnssec.AuthenticateRRset(ctx, m.validatorConfig(), set, sigs,
			m.cfg.Zone, []*dns.DNSKEY{key}, now)
		if reason == dnssec.ReasonNone || reason == dnssec.ReasonVerified {
			out = append(out, key)
		}
	}
	return out
}

// proven indexes keys by their material, for advance.
func proven(keys []*dns.DNSKEY) map[string]bool {
	out := map[string]bool{}
	for _, k := range keys {
		out[material(k)] = true
	}
	return out
}

// isTrusted reports whether a key arriving in the RRset is one this resolver
// currently trusts — either because it matches a configured anchor's digest,
// or because it is a managed key in a trusted state.
//
// A revoked key is never trusted here, however it matches. RFC 5011 §2.2: once
// revoked, a key may be used for nothing except validating the RRSIG it made
// over the DNSKEY RRset announcing its own revocation — and that use is handled
// in advance, not here.
func (m *Manager) isTrusted(key *dns.DNSKEY) bool {
	if key.Flags&dns.REVOKE != 0 {
		return false
	}
	for _, a := range m.cfg.Configured.Anchors() {
		if a.MatchesKey(m.cfg.Policy, key) == dnssec.ReasonNone {
			return true
		}
	}
	for _, k := range m.tp.Keys {
		if !k.State.Trusted() {
			continue
		}
		stored, err := k.DNSKEY()
		if err != nil {
			continue
		}
		if sameKey(stored, key) {
			return true
		}
	}
	return false
}

// sameKey compares two DNSKEYs by everything a signature depends on.
//
// The public key material is compared, not just the tag. A key tag is a 16-bit
// checksum over the RDATA (RFC 4034 Appendix B) and two different keys can
// share one; matching on the tag alone would let an attacker who found a
// collision have their key treated as one this resolver already trusts, which
// is the whole game.
func sameKey(a, b *dns.DNSKEY) bool {
	return a.Algorithm == b.Algorithm &&
		a.Protocol == b.Protocol &&
		a.Flags == b.Flags &&
		a.PublicKey == b.PublicKey
}

// splitDNSKEY pulls the apex DNSKEY RRset and its signatures out of a reply,
// and reports the timers RFC 5011 §2.3 computes its intervals from.
func splitDNSKEY(zone string, records []dns.RR, now time.Time) (
	set dnssec.RRset, sigs []*dns.RRSIG, origTTL, sigExpiry time.Duration, err error,
) {
	zone = dns.CanonicalName(zone)
	data, signatures := dnssec.SplitSignaturesAt(records, zone, dns.TypeDNSKEY)
	if len(data) == 0 {
		return set, nil, 0, 0, fmt.Errorf("the reply for %s carried no DNSKEY records", zone)
	}
	set, reason := dnssec.NewRRset(data)
	if reason != dnssec.ReasonNone {
		return set, nil, 0, 0, fmt.Errorf("the %s DNSKEY records are not a well-formed RRset (%s)", zone, reason)
	}

	// The RRset's own TTL, which §2.3 calls OrigTTL. Taken from the records
	// rather than from an RRSIG's Original TTL field, because a refresh
	// interval is an operational schedule and should not be a number an
	// attacker can shrink by rewriting a signature they cannot forge anyway.
	origTTL = time.Duration(set.Records[0].Header().Ttl) * time.Second

	// The expiration interval: how long the freshest usable signature has
	// left. The furthest-away expiry among the signatures, because that is
	// the one that decides when this answer stops being usable.
	for _, sig := range signatures {
		exp := time.Unix(int64(sig.Expiration), 0).Sub(now)
		if exp > sigExpiry {
			sigExpiry = exp
		}
	}
	return set, signatures, origTTL, sigExpiry, nil
}

// queryInterval is RFC 5011 §2.3:
//
//	queryInterval = MAX(1 hr, MIN(15 days, 1/2*OrigTTL, 1/2*RRSigExpirationInterval))
//
// A zero or negative input is left out of the MIN rather than dragging the
// result to zero: a reply with no usable signature expiry has already failed
// authentication, and one with a zero TTL is telling us not to cache it, not
// telling us to refresh continuously.
func queryInterval(origTTL, sigExpiry time.Duration) time.Duration {
	d := maxQueryInterval
	if origTTL > 0 && origTTL/2 < d {
		d = origTTL / 2
	}
	if sigExpiry > 0 && sigExpiry/2 < d {
		d = sigExpiry / 2
	}
	if d < minQueryInterval {
		d = minQueryInterval
	}
	return d
}

// retryInterval is RFC 5011 §2.3's retry schedule:
//
//	retryTime = MAX(1 hour, MIN(1 day, .1*origTTL, .1*expireInterval))
//
// With no TTL to work from — a refresh that failed before it read one — the
// bound is the RFC's one-day maximum, which is the conservative direction: a
// resolver that could not reach the root should not spend the outage asking it
// every hour.
func retryInterval(origTTL time.Duration) time.Duration {
	d := maxRetryInterval
	if origTTL > 0 && origTTL/10 < d {
		d = origTTL / 10
	}
	if d < minRetryInterval {
		d = minRetryInterval
	}
	return d
}

// lastTTL is the TTL of the last RRset that authenticated, or zero.
func (m *Manager) lastTTL() time.Duration {
	// Not stored: the retry schedule is allowed to be coarse, and keeping a
	// TTL in the state file for the sake of the failure path would be state
	// nothing else reads. retryInterval treats zero as "use the maximum".
	return 0
}
