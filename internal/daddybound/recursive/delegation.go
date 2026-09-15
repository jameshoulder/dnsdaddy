package recursive

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

// Establishing a zone cut by asking, rather than inferring one from silence.
//
// Source.ZoneCutsFor answers from what a resolution happened to observe: the
// referrals it crossed, plus the delegations the cache already holds. That is
// sound evidence and it is also incomplete, in a way that bites exactly where
// it hurts. A resolution that starts from a cached delegation walks no part of
// the tree above that delegation, so it observes nothing there and must say
// nothing there — and with a warm cache, "there" is most of the names a chain
// walk asks about. The validator then falls back to assuming the name is not a
// zone cut, which is v0.1's behaviour and costs a false Bogus on every real
// delegation whose parent published no readable DS.
//
// The assumption is reached because the source declines to answer, not because
// the answer is unknowable. This file makes it answerable: a bounded,
// QNAME-minimised walk down from the deepest ancestor the resolver has already
// proved, asking NS at each step, reading the boundary from the shape of the
// reply rather than from the absence of one.
//
// # What is and is not concluded
//
// A referral whose NS RRset is owned by the name itself, from a server that
// did not set AA, is a delegation: the zone above it has told us to go
// elsewhere, which is what a zone cut is. An authoritative reply for the name
// itself that refers nowhere is the opposite statement from the only party
// entitled to make it: the name lives inside this zone. Everything else —
// a timeout, a lame server, a malformed reply, a budget exhausted — is
// unknown, and unknown is returned as such so that the validator keeps its
// existing fallback rather than reading a failure as evidence.
//
// # Why this cannot weaken a verdict
//
// Both answers are safe, for different reasons, and neither creates a route to
// Secure that did not exist before:
//
//   - "this is a cut" sends the validator to noDSAtDelegation's Indeterminate
//     branch, never to Insecure. An NS referral arrives unauthenticated, and
//     treating one as proof of DS absence is the classic downgrade; the
//     validator refuses to, and this file supplies no reason to revisit that.
//   - "this is not a cut" produces exactly what the assumption produced, so a
//     wrong answer here costs what being wrong already cost — a false Bogus,
//     because the records below a real cut are signed by keys the parent's
//     DNSKEY RRset does not contain.
//
// So the change is one-way: it removes refusals without adding acceptances.
// TestDiscoveringDelegationsNeverProducesSecure is the evidence.

// maxProbeSteps bounds one DelegationAt walk.
//
// A name has at most 127 labels and a probe consumes one per step, so this is
// an operational bound rather than a protocol one. It exists because every
// step is a query an adversary's hierarchy chooses the length of: a zone that
// refers downwards for ever would otherwise turn one validator question into
// an unbounded number of packets.
const maxProbeSteps = 24

// DelegationAt reports whether name is a zone cut, by establishing the
// boundary rather than inferring it.
//
// The two return values are deliberately separate. "Not a zone cut" and "I
// could not tell" lead to different behaviour in the validator, and collapsing
// them into one boolean is how ignorance gets promoted to evidence.
func (r *Resolver) DelegationAt(ctx context.Context, name string) (isCut bool, known bool) {
	n := dns.CanonicalName(name)
	if n == "." {
		// The root has no parent to be delegated from, so the question is
		// not meaningful rather than false. Saying "not a cut" here would be
		// a claim about a boundary that cannot exist.
		return false, false
	}

	if v, ok := r.cache.GetCut(n); ok {
		return v, true
	}

	// A live delegation already cached at this exact name is a referral that
	// was received — by this resolver, from the zone above — and needs no
	// second opinion. Checking here rather than only in ZoneCutsFor keeps the
	// probe off the wire for the common case.
	if r.cache.HasDelegation(n) {
		r.cache.PutCut(n, true)
		return true, true
	}

	rs := &resolution{r: r, ctx: ctx, start: r.now()}
	isCut, known = rs.delegationAt(n)
	if known {
		r.cache.PutCut(n, isCut)
	}
	return isCut, known
}

// delegationAt walks down to name, one label at a time, and reads the
// boundary off the replies.
//
// The walk starts at the deepest delegation the cache holds strictly above
// name — not at the zone a previous resolution for name happened to start in.
// That distinction is the whole fix. Starting at a cached delegation *for
// name* would ask the child zone whether it is a child, and a zone's own
// servers answer authoritatively for their apex: the reply refers nowhere, and
// reading it as "not a cut" inverts the answer for every name the cache
// already knows about.
func (rs *resolution) delegationAt(name string) (isCut bool, known bool) {
	zone, servers, ok := rs.probeStart(name)
	if !ok {
		return false, false
	}

	// probe advances one label at a time from just below the starting zone
	// down to name. Each question tells the server it is put to exactly one
	// label more than it already had to know, which is what QNAME
	// minimisation is; asking the starting zone about the full name directly
	// would hand every ancestor the whole name for no gain here.
	probe := nextLabel(zone, name)

	for step := 0; step < maxProbeSteps; step++ {
		if rs.ctx.Err() != nil {
			return false, false
		}
		// Unminimised at this level deliberately: probe is already the
		// shortest question that makes progress, and letting ask() minimise
		// it again would ask about a name shorter than the one whose answer
		// is about to be interpreted.
		msg, err := rs.askZoneDirect(zone, servers, probe, dns.TypeNS)
		if err != nil {
			return false, false
		}

		child, ns, glue, isReferral := rs.classifyReferral(zone, probe, msg)
		if isReferral {
			// A referral is an observation worth keeping whether or not it
			// is the one being asked about: the next probe, and every later
			// resolution, starts from a deeper proven point.
			rs.r.cache.PutDelegation(child, ns, glue)
			if child == name {
				return true, true
			}
			if child != probe {
				// A referral to somewhere other than the name asked about.
				// classifyReferral has already refused anything outside the
				// bailiwick, so this is a well-formed but unexpected shape;
				// nothing is concluded from it.
				return false, false
			}
			next, err := rs.serversFor(child, ns, glue, 0)
			if err != nil {
				return false, false
			}
			zone, servers = child, next
			probe = nextLabel(zone, name)
			continue
		}

		if !msg.Authoritative {
			// Neither a referral nor an authoritative statement. A lame or
			// broken server has said nothing this walk may act on.
			return false, false
		}
		if msg.Rcode != dns.RcodeSuccess {
			// An authoritative NXDOMAIN for the full name settles it: a name
			// that does not exist is not a delegation. For a *shorter* probe
			// it would settle it too under RFC 8020, but only if the server
			// implements empty non-terminals correctly, and enough do not
			// that the inference is not worth making — the fallback it
			// declines into reaches the same conclusion anyway.
			if probe == name && msg.Rcode == dns.RcodeNameError {
				return false, true
			}
			return false, false
		}

		if probe == name {
			// The zone above is authoritative for this name and refers
			// nowhere at it. That is the positive statement that no cut
			// exists here, made by the only party entitled to make it.
			return false, true
		}

		// The probe exists inside this zone with no NS records, so it is not
		// a cut — but that is a statement about the probe, not about name.
		// Advance one more label, still asking the same servers, which are
		// still the deepest authority anyone has established.
		probe = nextLabel(probe, name)
	}
	return false, false
}

// probeStart returns the deepest delegation the cache holds strictly above
// name, with usable addresses, falling back to the root.
//
// Strictly above is the point. BestDelegation(name) would return name itself
// when the cache holds a delegation there, which is the child zone — and the
// child's servers answer authoritatively for their own apex, so the probe
// would read "not a cut" about a name the resolver has already been referred
// to.
func (rs *resolution) probeStart(name string) (string, []netip.AddrPort, bool) {
	if zone, addrs, ok := rs.r.cache.BestDelegation(parentOf(name)); ok && len(addrs) > 0 {
		return zone, addrs, true
	}
	addrs, err := rs.r.rootServers(rs.ctx)
	if err != nil {
		return "", nil, false
	}
	return ".", addrs, true
}
