package dnssec

import "github.com/miekg/dns"

// NSEC denial proofs: RFC 4035 §5.4 as corrected by RFC 6840 §4.
//
// RFC 6840 §4.1 opens by saying that RFC 4035 §5.4 "under-specifies the
// algorithm for checking nonexistence proofs", and it is not being polite.
// Implementing §5.4 alone produces a validator that accepts a genuinely
// signed record from a parent zone as proof about a name inside its child —
// a name the parent has no authority over and never made a claim about. Both
// documents are load-bearing, so both are cited at each rule below.
//
// Everything here operates on authenticated records only. A denialProof
// cannot be constructed without verification, which is what makes "the NSEC
// says so" mean something.

// nsecHasType reports whether a type appears in an NSEC's bitmap.
func nsecHasType(n *dns.NSEC, rrtype uint16) bool {
	for _, t := range n.TypeBitMap {
		if t == rrtype {
			return true
		}
	}
	return false
}

// isAncestorDelegation reports whether an NSEC is the parent side of a zone
// cut, as RFC 6840 §4.1 defines it:
//
//	An "ancestor delegation" NSEC RR (or NSEC3 RR) is one with:
//	o  the NS bit set,
//	o  the Start of Authority (SOA) bit clear, and
//	o  a signer field that is shorter than the owner name of the NSEC RR
//
// All three conditions matter. NS with SOA is a zone apex, which is the
// child's own NSEC and says everything about that zone. NS without SOA but
// signed by the zone the record sits in — signer equal in length to the owner
// — is not a delegation either.
func isAncestorDelegation(a authenticNSEC) bool {
	owner := dns.CanonicalName(a.rr.Hdr.Name)
	signer := dns.CanonicalName(a.signer)
	return nsecHasType(a.rr, dns.TypeNS) &&
		!nsecHasType(a.rr, dns.TypeSOA) &&
		dns.CountLabel(signer) < dns.CountLabel(owner)
}

// mayDeny reports whether an authenticated NSEC is entitled to say anything
// about the (name, type) pair being asked about.
//
// This is R-DEN-06 and R-DEN-07, and it is the difference between a proof and
// a coincidence. Every zone cut has two NSEC records at the same owner name:
// one published by the parent describing the delegation, and one published by
// the child describing its apex. A validator that does not separate them will
// authenticate the parent's record — correctly, because the parent is inside
// the chain of trust — and then read it as proof that a name inside the child
// does not exist. The signature is real. The conclusion is invented.
//
// RFC 6840 §4.1:
//
//	Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume
//	nonexistence of any RRs below that zone cut, which include all RRs at
//	that (original) owner name other than DS RRs, and all RRs below that
//	owner name regardless of type.
//
//	An NSEC or NSEC3 RR with the DNAME bit set MUST NOT be used to assume
//	the nonexistence of any subdomain of that NSEC/NSEC3 RR's (original)
//	owner name.
//
// Note the exception the RFC writes into the middle of its own prohibition:
// "other than DS RRs". A DS lives in the parent, so the parent's delegation
// NSEC is precisely the record that may speak about it — and, per RFC 4035
// §5.2, the only one that may.
func mayDeny(a authenticNSEC, target string, rrtype uint16) bool {
	owner := dns.CanonicalName(a.rr.Hdr.Name)
	name := dns.CanonicalName(target)

	if isAncestorDelegation(a) {
		if name == owner {
			return rrtype == dns.TypeDS
		}
		if isSubDomainOf(owner, name) {
			return false
		}
	}

	// A DNAME redirects everything beneath it, so an NSEC at its owner name
	// cannot speak for names below.
	if nsecHasType(a.rr, dns.TypeDNAME) && name != owner && isSubDomainOf(owner, name) {
		return false
	}
	return true
}

// matching returns the authenticated NSEC whose owner name is exactly name
// and which is entitled to speak about rrtype there, or nil.
func (d *denialProof) matching(name string, rrtype uint16) *authenticNSEC {
	want := dns.CanonicalName(name)
	for i := range d.nsec {
		a := d.nsec[i]
		if dns.CanonicalName(a.rr.Hdr.Name) != want {
			continue
		}
		if !mayDeny(a, want, rrtype) {
			continue
		}
		return &d.nsec[i]
	}
	return nil
}

// matchingAny returns any authenticated NSEC whose owner name is exactly
// name, without applying the entitlement rules.
//
// Used where the *existence* of a record at that name is the fact in
// question — the closest encloser walk needs to know that a name exists, and
// a delegation NSEC proves its owner exists just as well as any other.
func (d *denialProof) matchingAny(name string) *authenticNSEC {
	want := dns.CanonicalName(name)
	for i := range d.nsec {
		if dns.CanonicalName(d.nsec[i].rr.Hdr.Name) == want {
			return &d.nsec[i]
		}
	}
	return nil
}

// covering returns an authenticated NSEC whose interval strictly contains
// name and which is entitled to deny it, or nil.
//
// R-DEN-04, RFC 4035 §5.4:
//
//	If the requested RR name would appear after an authenticated NSEC RR's
//	owner name and before the name listed in that NSEC RR's Next Domain Name
//	field according to the canonical DNS name order defined in [RFC4034],
//	then no RRsets with the requested name exist in the zone.
func (d *denialProof) covering(name string, rrtype uint16) *authenticNSEC {
	want := dns.CanonicalName(name)
	if !validNameForProof(want) {
		// A name the canonical ordering cannot place cannot be inside an
		// interval in any meaningful sense. Refusing here means no interval
		// arithmetic is ever performed on a name whose position is
		// undefined.
		return nil
	}
	for i := range d.nsec {
		a := d.nsec[i]
		if !validNameForProof(a.rr.Hdr.Name) || !validNameForProof(a.rr.NextDomain) {
			continue
		}
		if !nameInInterval(want, a.rr.Hdr.Name, a.rr.NextDomain) {
			continue
		}
		if !mayDeny(a, want, rrtype) {
			continue
		}
		return &d.nsec[i]
	}
	return nil
}

// closestEncloser derives the deepest ancestor of qname that is known to
// exist, given an NSEC that covers qname.
//
// The derivation, and why it is sound: the covering NSEC's owner name exists,
// because a zone publishes an NSEC only at names it has. Its Next Domain Name
// exists for the same reason. Every ancestor of an existing name also exists —
// at worst as an empty non-terminal, which is still a name in the zone. So
// the longest suffix qname shares with either of those two names is an
// ancestor of qname that exists, and the longer of the two is the deepest
// such ancestor this record can establish.
//
// RFC 4592 §3.3.1 defines the closest encloser and RFC 5155 §1.3 restates it
// as "the longest existing ancestor of a name". This is that name, derived
// from one record rather than looked up.
func closestEncloser(qname string, a authenticNSEC) string {
	fromOwner := longestCommonSuffix(qname, a.rr.Hdr.Name)
	fromNext := longestCommonSuffix(qname, a.rr.NextDomain)
	if dns.CountLabel(fromNext) > dns.CountLabel(fromOwner) {
		return fromNext
	}
	return fromOwner
}

// longestCommonSuffix returns the longest sequence of trailing labels a and b
// share, as a name. The root is the answer when they share nothing.
func longestCommonSuffix(a, b string) string {
	an := dns.CanonicalName(a)
	bn := dns.CanonicalName(b)

	ai := dns.Split(an)
	bi := dns.Split(bn)

	best := "."
	for x, y := len(ai)-1, len(bi)-1; x >= 0 && y >= 0; x, y = x-1, y-1 {
		if !equalNames(an[ai[x]:], bn[bi[y]:]) {
			break
		}
		best = an[ai[x]:]
	}
	return best
}

// equalNames compares two names case-insensitively in canonical form.
func equalNames(a, b string) bool {
	return dns.CanonicalName(a) == dns.CanonicalName(b)
}

// proveNoData establishes that qname exists and carries no RRset of rrtype.
//
// R-DEN-02, RFC 4035 §5.4:
//
//	If the requested RR name matches the owner name of an authenticated NSEC
//	RR, then the NSEC RR's type bit map field lists all RR types present at
//	that owner name, and a resolver can prove that the requested RR type does
//	not exist by checking for the RR type in the bit map.
//
// R-DEN-03, RFC 6840 §4.3, is the correction that stops an attacker turning a
// CNAME answer into a NODATA one by deleting the CNAME RRset:
//
//	When validating a NOERROR/NODATA response, validators MUST check the
//	CNAME bit in the matching NSEC or NSEC3 RR's type bitmap in addition to
//	the bit for the query type.
//
// The CNAME check is skipped when the query is itself for CNAME, where the
// bit is the query type and the first check has already covered it.
func (d *denialProof) proveNoData(qname string, rrtype uint16) Reason {
	if d.empty() {
		return d.denialUnavailable()
	}

	match := d.matching(qname, rrtype)
	if match == nil {
		// A NODATA proof needs the NSEC at the name itself. If one exists
		// but is not entitled to speak — the parent's delegation record
		// offered as proof about the child's data — say so specifically,
		// because its signature is perfectly good and an investigator sent
		// to look at the cryptography will find nothing wrong with it.
		if d.matchingAny(qname) != nil {
			return ReasonDenialWrongZone
		}
		// One legitimate case remains: an empty non-terminal, which owns no
		// records and therefore has no NSEC of its own. See emptyNonTerminal.
		if d.emptyNonTerminal(qname, rrtype) {
			return ReasonNone
		}
		return ReasonDenialIncomplete
	}

	if nsecHasType(match.rr, rrtype) {
		return ReasonDenialContradicted
	}
	if rrtype != dns.TypeCNAME && nsecHasType(match.rr, dns.TypeCNAME) {
		return ReasonDenialContradicted
	}
	return ReasonNone
}

// proveNameError establishes that qname does not exist at all.
//
// Two proofs are required, and the second is the one that is easy to leave
// out and hard to notice missing. R-DEN-04 covers the name; R-DEN-05 covers
// the wildcard that could otherwise have answered for it. RFC 4035 §5.4:
//
//	However, it is possible that a wildcard could be used to match the
//	requested RR owner name and type, so proving that the requested RRset
//	does not exist also requires proving that no possible wildcard RRset
//	exists that could have been used to generate a positive response.
//
// A response that proves only the first half has proved nothing about a zone
// containing a wildcard, and a validator that stops there accepts a forged
// NXDOMAIN for every name in every such zone.
func (d *denialProof) proveNameError(qname string, rrtype uint16) Reason {
	if d.empty() {
		return d.denialUnavailable()
	}

	// The name itself must be shown absent. A record matching it exactly
	// would say the opposite.
	if d.matchingAny(qname) != nil {
		return ReasonDenialContradicted
	}
	cover := d.covering(qname, rrtype)
	if cover == nil {
		return ReasonDenialIncomplete
	}
	// A covering NSEC whose next name is *below* the queried name proves the
	// opposite of NXDOMAIN. That next name exists, every ancestor of an
	// existing name exists, and the queried name is one of those ancestors —
	// so it exists as an empty non-terminal and the answer should have been
	// NODATA.
	//
	// Without this check an attacker upgrades a NODATA into an NXDOMAIN by
	// changing one field of the response header, and the very same signed
	// NSEC that proved the weaker claim is accepted as proof of the stronger
	// one.
	if isProperSubDomain(qname, cover.rr.NextDomain) {
		return ReasonDenialContradicted
	}

	// The wildcard that could have synthesised an answer sits directly below
	// the closest encloser, which the covering record itself establishes.
	wildcard := wildcardAt(closestEncloser(qname, *cover))

	// A record matching the wildcard exactly means the wildcard exists, so
	// the response should have been a wildcard expansion rather than
	// NXDOMAIN. That is a contradiction, not an incomplete proof.
	if d.matchingAny(wildcard) != nil {
		return ReasonDenialContradicted
	}
	if d.covering(wildcard, rrtype) == nil {
		return ReasonDenialIncomplete
	}
	return ReasonNone
}

// dsDenial is what a proof says about the DS record at a delegation name.
type dsDenial int

const (
	// dsDenialNone: the proof establishes nothing about this name.
	dsDenialNone dsDenial = iota
	// dsDenialInsecure: NS present, DS absent — an insecure delegation, and
	// the only authenticated route to RFC 4033 §5's Insecure.
	dsDenialInsecure
	// dsDenialNotADelegation: the name exists and is not a zone cut, so the
	// walk stays in the same zone. Proved rather than assumed.
	dsDenialNotADelegation
	// dsDenialNameAbsent: the name does not exist, so it is not a zone cut
	// either. The answer below it will have its own denial to prove.
	dsDenialNameAbsent
	// dsDenialContradicted: the proof says a DS is present at a name the
	// response claimed had none.
	dsDenialContradicted
)

// proveNoDS reads what an authenticated proof says about the DS record at a
// delegation name.
//
// R-DEN-08 is the shape of the answer. RFC 4035 §5.2 requires the absence of
// DS, and RFC 6840 §4.4 adds the check without which the absence proves the
// wrong thing:
//
//	The validator also MUST check for the presence of the NS bit in the
//	matching NSEC (or NSEC3) RR (proving that there is, indeed, a
//	delegation) ...
//
//	Without this check, an attacker could reuse an NSEC or NSEC3 RR matching
//	a non-delegation name to spoof an unsigned delegation at that name. This
//	would claim that an existing signed RRset (or set of signed RRsets) is
//	below an unsigned delegation, thus not signed and vulnerable to further
//	attack.
//
// R-DEN-09 decides which record may be read at all. Two NSECs exist at every
// delegation name, and RFC 4035 §5.2 is explicit about which one counts:
//
//	The parent NSEC RR and child NSEC RR can always be distinguished because
//	the SOA bit will be set in the child NSEC RR and clear in the parent NSEC
//	RR.  A security-aware resolver MUST use the parent NSEC RR when
//	attempting to prove that a DS RRset does not exist.
func (d *denialProof) proveNoDS(child string) dsDenial {
	if d.empty() {
		return dsDenialNone
	}

	for i := range d.nsec {
		a := d.nsec[i]
		if !equalNames(a.rr.Hdr.Name, child) {
			continue
		}
		// R-DEN-09: the child's own apex record says what is at the apex of
		// the child zone, which is a different question and not one the
		// parent's chain of trust settles.
		if nsecHasType(a.rr, dns.TypeSOA) {
			continue
		}
		if nsecHasType(a.rr, dns.TypeDS) {
			return dsDenialContradicted
		}
		if nsecHasType(a.rr, dns.TypeNS) {
			return dsDenialInsecure
		}
		// The name exists, has no NS and no DS: not a zone cut at all,
		// which is true of nearly every name a chain walk passes through.
		return dsDenialNotADelegation
	}

	// No record at the name. If one covers it, the name does not exist, so
	// it is certainly not a delegation.
	if d.covering(child, dns.TypeDS) != nil {
		return dsDenialNameAbsent
	}
	return dsDenialNone
}

// proveWildcardAnswer establishes that a wildcard-expanded positive answer
// was the right answer — that no closer name existed.
//
// R-DEN-11, RFC 4035 §5.3.4:
//
//	If the number of labels in an RRset's owner name is greater than the
//	Labels field of the covering RRSIG RR, then the RRset and its covering
//	RRSIG RR were created as a result of wildcard expansion. Once the
//	validator has verified the signature ... it must take additional steps to
//	verify the non-existence of an exact match or closer wildcard match for
//	the query.
//
// The signature on such an answer is genuine: the zone really did sign
// "*.example." and the server really did expand it. What the signature does
// not establish is that expansion was legitimate, because the same signed
// wildcard answers for every name under the encloser. Without this check an
// attacker replays a wildcard answer over a name that has its own records,
// and every signature verifies.
func (d *denialProof) proveWildcardAnswer(qname string, expandedFrom int, rrtype uint16) Reason {
	if d.empty() {
		return d.denialUnavailable()
	}

	// The wildcard sat directly below an encloser with expandedFrom labels,
	// so the name one label longer than that encloser — the next closer
	// name — is what must be shown absent. If it existed, it and not the
	// wildcard would have answered.
	encloser := ancestorWithLabels(qname, expandedFrom)
	if encloser == "" {
		return ReasonDenialIncomplete
	}
	closer, ok := nextCloser(qname, encloser)
	if !ok {
		// qname is the encloser itself, so no expansion happened and there
		// is nothing this rule can check. Reaching here means the label
		// arithmetic disagrees with the RRSIG, which is a malformed claim
		// rather than a proved one.
		return ReasonDenialIncomplete
	}
	if d.matchingAny(closer) != nil {
		return ReasonDenialContradicted
	}
	if d.covering(closer, rrtype) == nil {
		return ReasonDenialIncomplete
	}
	return ReasonNone
}

// ancestorWithLabels returns the ancestor of name having exactly n labels, or
// "" if name has fewer.
func ancestorWithLabels(name string, n int) string {
	c := dns.CanonicalName(name)
	have := dns.CountLabel(c)
	if n < 0 || n > have {
		return ""
	}
	if n == 0 {
		return "."
	}
	idx := dns.Split(c)
	drop := have - n
	if drop < 0 || drop >= len(idx) {
		return ""
	}
	return c[idx[drop]:]
}

// emptyNonTerminal reports whether the proof establishes that qname exists
// with no records of its own, which is the one NODATA shape that has no NSEC
// at the queried name.
//
// An empty non-terminal is "a domain name that owns no resource records, but
// has one or more subdomains that do" (RFC 5155 §1.3). RFC 4035 §2.3 requires
// an NSEC only "in the zone that has authoritative data or a delegation point
// NS RRset", so a zone publishes none at such a name — RFC 7129 §5.1 states
// the consequence directly: "An empty non-terminal will get an NSEC3 record
// but not an NSEC record."
//
// The proof is therefore an NSEC that spans the name and whose Next Domain
// Name lies below it. That next name exists, because a zone publishes NSEC
// records only at names it has; every ancestor of an existing name exists, at
// worst as an empty non-terminal; qname is one of those ancestors. So qname
// exists — and since the zone published no NSEC at it, it owns nothing, so
// every type is absent.
//
// This cannot be turned into a forged NODATA for a name that does have
// records: a name owning records owns an NSEC too, so no NSEC interval spans
// across it, and no such record could be produced by the real zone.
func (d *denialProof) emptyNonTerminal(qname string, rrtype uint16) bool {
	cover := d.covering(qname, rrtype)
	return cover != nil && isProperSubDomain(qname, cover.rr.NextDomain)
}

// isProperSubDomain reports whether child is strictly below parent.
func isProperSubDomain(parent, child string) bool {
	p := dns.CanonicalName(parent)
	c := dns.CanonicalName(child)
	return p != c && isSubDomainOf(p, c)
}
