package dnssec

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// This file exports the two questions an RFC 5011 trust-anchor manager has to
// ask, and nothing else.
//
// It exists so that internal/daddybound/trustanchors does not grow a second
// implementation of either. A key-rollover manager decides what this resolver
// will trust for the next thirty days; if it authenticated a DNSKEY RRset by
// its own slightly different rules, then the resolver would have two answers
// to "is this signature good" and the weaker one would be the one that chose
// the trust anchors. Every defence in authenticate.go — the RFC 6840 §5.12
// algorithm-downgrade rule, key-tag collisions, policy before cryptography,
// signature ordering — has to apply to that decision too, so the manager calls
// the same code rather than a copy of it.

// AuthenticateRRset reports whether an RRset is authenticated by one of the
// given keys, and why not when it is not.
//
// The same rules the chain walk applies, on the same code path: this
// constructs a walk and calls authenticate. Nothing is relaxed because the
// caller is a trust-anchor manager rather than a resolution.
//
// zone is the name whose keys these are, and a signature naming any other
// signer is refused — which for a trust point means the RRset has to be
// self-signed, since the zone signing its own apex DNSKEY RRset is the only
// thing RFC 5011 will accept as evidence about that zone's keys.
//
// No Source is consulted and none is needed: the records and the keys are both
// supplied. That is what makes this usable before a chain of trust exists.
func AuthenticateRRset(
	ctx context.Context,
	cfg Config,
	set RRset,
	sigs []*dns.RRSIG,
	zone string,
	keys []*dns.DNSKEY,
	now time.Time,
) (Reason, []ValidationStep) {
	// New fills the defaults that fail safe. The nil source is deliberate and
	// safe: authenticate reads cfg and the recorder, never src.
	v := New(nil, cfg)
	w := v.newWalk(ctx, set.Name, set.RRType, now)
	reason := w.authenticate(set, sigs, dns.CanonicalName(zone), keys)
	return reason, w.rec.steps
}

// MatchesKey reports whether this anchor authenticates the given DNSKEY, and
// why not when it does not.
//
// An anchor is a DS record in all but name, so this is the DS comparison of
// RFC 4034 §5.1.4 and nothing else. It is what lets a trust-anchor manager
// start from the digests IANA publishes rather than from a key blob: the
// resolver fetches the zone's DNSKEY RRset, and the keys that match a
// configured digest are the ones it may begin trusting.
func (a TrustAnchor) MatchesKey(policy Policy, k *dns.DNSKEY) Reason {
	return a.matchesKey(policy, k)
}

// Anchors returns the configured anchors.
//
// A copy, because the slice inside a TrustAnchors is what every validation
// starts from and a caller that reordered or truncated it would be changing
// what this resolver trusts by accident.
func (t TrustAnchors) Anchors() []TrustAnchor {
	return append([]TrustAnchor(nil), t.anchors...)
}
