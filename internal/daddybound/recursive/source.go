package recursive

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// Source adapts the recursive resolver to the interface Daddybound's DNSSEC
// engine reads records through.
//
// This is the join that makes local validation independent. Until now the
// validator's records came from netsource, which asks a public recursive
// resolver — so a DNSKEY "Daddybound validated" was a DNSKEY Cloudflare chose
// to hand over. Through this source the same validator sees records the
// resolver fetched from the authoritative servers itself.
type Source struct {
	r *Resolver
}

// NewSource wraps a Resolver as a dnssec.Source.
func NewSource(r *Resolver) *Source { return &Source{r: r} }

// Lookup resolves one RRset.
func (s *Source) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	res, err := s.r.Resolve(ctx, name, rrtype)
	if err != nil {
		return dnssec.Response{}, err
	}
	return dnssec.Response{
		Rcode:     res.Msg.Rcode,
		Answer:    res.Msg.Answer,
		Authority: res.Msg.Ns,
	}, nil
}

// ZoneCutsFor reports which of the candidate names are zone cuts, established
// from referrals the resolver actually followed.
//
// This is what closes the assumption issue #64 describes. A validator working
// through a forwarder cannot tell "this name is not a zone cut" from "the
// server did not say", and Daddybound has until now assumed the former —
// one-sided, costing a false Bogus and never a false Secure, but costing it
// on a lot of the deployed Internet.
//
// A resolver that followed referrals does not have to assume. It crossed the
// zone cuts on the way to the answer, so it can say which names are
// delegations and, just as usefully, which are not: a name the walk passed
// through without being referred at is not a zone cut, and that is an
// observation rather than a guess.
//
// The second return value reports whether the resolver has an opinion at all.
// False means it never resolved anything under this name — from a cold cache,
// say — and the caller must fall back rather than read an empty answer as
// "none of these are zone cuts".
func (s *Source) ZoneCutsFor(ctx context.Context, name string) (map[string]bool, bool) {
	// Resolving the name is what produces the delegation evidence. It is
	// almost always a cache hit by the time a validator asks, because the
	// validator is validating something the resolver just fetched.
	res, err := s.r.Resolve(ctx, name, dns.TypeNS)
	if err != nil || res == nil {
		return nil, false
	}

	cuts := map[string]bool{}
	for _, d := range res.Delegations {
		cuts[dns.CanonicalName(d.Child)] = true
	}

	// Every name strictly between the deepest cut and the queried name was
	// passed through without a referral, so it is not a zone cut. Recording
	// that explicitly is the half that removes the assumption: without it a
	// caller only learns which names *are* cuts and still has to guess about
	// the rest.
	deepest := "."
	for cut := range cuts {
		if len(cut) > len(deepest) {
			deepest = cut
		}
	}
	for n := dns.CanonicalName(name); n != "." && n != deepest; {
		if !cuts[n] {
			cuts[n] = false
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i+1 >= len(n) {
			break
		}
		n = n[i+1:]
	}
	return cuts, true
}

// Delegations returns the zone cuts crossed while resolving name, for a trace.
func (s *Source) Delegations(ctx context.Context, name string, rrtype uint16) ([]Delegation, error) {
	res, err := s.r.Resolve(ctx, name, rrtype)
	if err != nil {
		return nil, fmt.Errorf("delegations for %s: %w", name, err)
	}
	return res.Delegations, nil
}

// Resolver exposes the underlying resolver, for status and diagnostics.
func (s *Source) Resolver() *Resolver { return s.r }
