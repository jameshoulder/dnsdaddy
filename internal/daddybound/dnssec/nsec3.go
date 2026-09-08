package dnssec

import "github.com/miekg/dns"

// NSEC3 denial proofs: RFC 5155 §8, with the parameter limits of RFC 9276.
//
// NSEC3 replaces "the name sorts between these two names" with "the hash of
// the name sorts between these two hashes". Everything else follows from that
// one substitution, including the two things that do not survive it:
//
//   - A name's position no longer reveals its ancestry, so "the closest
//     encloser" cannot be read off a single record the way it can from an
//     NSEC's next name. It has to be proved, one ancestor at a time (§8.3).
//   - Opt-out breaks the link between "covered" and "does not exist". An
//     opt-out record "does not assert the existence or non-existence of the
//     insecure delegations that it may cover" (§6), so it can establish that
//     a delegation is insecure and almost nothing else.
//
// Every hash here is work an attacker chose the cost of, so every hash is
// charged against a budget.

// authenticNSEC3 is an NSEC3 RR whose RRset was verified against a zone's
// keys, with the parts of its owner name already taken apart.
type authenticNSEC3 struct {
	rr     *dns.NSEC3
	signer string
	// hash is the owner's first label, upper-cased: the hashed owner name.
	hash string
	// zone is the rest of the owner name, which must be the zone this record
	// claims to be part of.
	zone string
}

// hashBudget bounds the hash computations one validation may perform.
//
// The iteration count and the number of NSEC3 records both arrive in the
// response, and the product is the work. Bounding only the per-record
// iteration count leaves an attacker free to send many records; bounding only
// the record count leaves them free to make each one expensive. This counts
// the thing that actually costs: individual hash computations.
type hashBudget struct{ remaining int }

func (b *hashBudget) spend(n int) bool {
	if b == nil {
		return true
	}
	if n > b.remaining {
		b.remaining = 0
		return false
	}
	b.remaining -= n
	return true
}

// nsec3Set is the authenticated NSEC3 material from one response, sharing one
// parameter set.
type nsec3Set struct {
	records []authenticNSEC3
	zone    string
	alg     uint8
	iter    uint16
	salt    []byte
	budget  *hashBudget

	// exhausted records that the budget ran out mid-proof, so that "we
	// stopped early" is never reported as "the proof failed".
	exhausted bool
}

func (s *nsec3Set) empty() bool { return s == nil || len(s.records) == 0 }

// hash computes a name's hashed owner name under this set's parameters,
// charging the budget.
func (s *nsec3Set) hash(name string) (string, bool) {
	// One computation for IH(salt, x, 0) plus one per iteration.
	if !s.budget.spend(int(s.iter) + 1) {
		s.exhausted = true
		return "", false
	}
	h, ok := nsec3Hash(name, s.alg, s.iter, s.salt)
	return h, ok
}

// match returns the NSEC3 whose hashed owner name is exactly this name's.
//
// RFC 5155 §1.3: "An NSEC3 RR is said to 'match' a name if the owner name of
// the NSEC3 RR is the same as the hashed owner name of that name."
func (s *nsec3Set) match(name string) *authenticNSEC3 {
	h, ok := s.hash(name)
	if !ok {
		return nil
	}
	for i := range s.records {
		if s.records[i].hash == h {
			return &s.records[i]
		}
	}
	return nil
}

// cover returns the NSEC3 whose interval contains this name's hash.
//
// RFC 5155 §1.3: "An NSEC3 RR is said to 'cover' a name if the hash of the
// name or 'next closer' name falls between the owner name and the next hashed
// owner name of the NSEC3."
func (s *nsec3Set) cover(name string) *authenticNSEC3 {
	h, ok := s.hash(name)
	if !ok {
		return nil
	}
	for i := range s.records {
		if hashInInterval(h, s.records[i].hash, nsec3NextHash(s.records[i].rr)) {
			return &s.records[i]
		}
	}
	return nil
}

// nsec3HasType reports whether a type appears in an NSEC3's bitmap.
func nsec3HasType(n *dns.NSEC3, rrtype uint16) bool {
	for _, t := range n.TypeBitMap {
		if t == rrtype {
			return true
		}
	}
	return false
}

// optOut reports whether the Opt-Out flag is set. RFC 5155 §3.1.2 gives the
// flag bit 0 of the Flags field.
func optOut(n *dns.NSEC3) bool { return n.Flags&0x01 == 1 }

// encloserProof is the result of RFC 5155 §8.3's closest encloser proof.
type encloserProof struct {
	// encloser is the closest (provable) encloser: the deepest ancestor of
	// the queried name shown to exist.
	encloser string
	// nextCloser is the name one label longer, shown not to exist — or, when
	// optOut is set, shown only not to hold authoritative data.
	nextCloser string
	// optOut says the NSEC3 covering nextCloser had the Opt-Out flag set,
	// which is the difference between the closest encloser and the closest
	// *provable* encloser. RFC 5155 §1.3: the two are "only different from
	// the closest encloser in an Opt-Out zone".
	optOut bool
}

// closestEncloser runs RFC 5155 §8.3's algorithm, which is quoted in
// docs/daddybound/standards.md §4.8 and reproduced in outline here because
// the flag handling is where implementations go wrong:
//
//  1. Set SNAME=QNAME.  Clear the flag.
//  2. Check whether SNAME exists:
//     *  If there is no NSEC3 RR in the response that matches SNAME ...
//     clear the flag.
//     *  If there is an NSEC3 RR in the response that covers SNAME, set
//     the flag.
//     *  If there is a matching NSEC3 RR in the response and the flag was
//     set, then the proof is complete, and SNAME is the closest
//     encloser.
//     *  If there is a matching NSEC3 RR in the response, but the flag is
//     not set, then the response is bogus.
//  3. Truncate SNAME by one label from the left, go to step 2.
//
// The last bullet is the one worth stating in the negative. A match with the
// flag clear means the name exists and nothing denied the name one label
// below it — so the response has shown an ancestor exists without showing
// anything about the name asked for. Accepting that would let any NSEC3
// record from anywhere in the zone stand in for a proof.
func (s *nsec3Set) closestEncloser(qname string) (encloserProof, Reason) {
	if s.empty() {
		return encloserProof{}, ReasonNoDenialProof
	}
	if !isSubDomainOf(s.zone, qname) {
		// The records belong to a zone that does not contain the name, so
		// they say nothing about it.
		return encloserProof{}, ReasonDenialWrongZone
	}

	// Bounded by the label count of a name that has already been parsed, so
	// the loop cannot be driven unboundedly by a response.
	names := ancestorsOf(qname, s.zone)

	flag := false
	previous := ""
	optedOut := false

	for _, sname := range names {
		if m := s.match(sname); m != nil {
			if !flag {
				// A matching record with nothing covering the name below it.
				return encloserProof{}, ReasonDenialIncomplete
			}
			if reason := enclosingRecordUsable(m); reason != ReasonNone {
				return encloserProof{}, reason
			}
			return encloserProof{encloser: sname, nextCloser: previous, optOut: optedOut}, ReasonNone
		}
		if s.exhausted {
			return encloserProof{}, ReasonResourceLimit
		}

		flag = false
		if c := s.cover(sname); c != nil {
			flag = true
			optedOut = optOut(c.rr)
		}
		if s.exhausted {
			return encloserProof{}, ReasonResourceLimit
		}
		previous = sname
	}
	return encloserProof{}, ReasonDenialIncomplete
}

// enclosingRecordUsable applies R-N3-04 to the NSEC3 matching the closest
// encloser.
//
// RFC 5155 §8.3:
//
//	Once the closest encloser has been discovered, the validator MUST check
//	that the NSEC3 RR that has the closest encloser as the original owner
//	name is from the proper zone. The DNAME type bit must not be set and the
//	NS type bit may only be set if the SOA type bit is set. If this is not
//	the case, it would be an indication that an attacker is using them to
//	falsely deny the existence of RRs for which the server is not
//	authoritative.
//
// This is NSEC3's form of the ancestor-delegation rule: NS without SOA is a
// delegation point, and a delegation point's record belongs to the parent and
// says nothing about what lies below the cut.
func enclosingRecordUsable(a *authenticNSEC3) Reason {
	if nsec3HasType(a.rr, dns.TypeDNAME) {
		return ReasonDenialWrongZone
	}
	if nsec3HasType(a.rr, dns.TypeNS) && !nsec3HasType(a.rr, dns.TypeSOA) {
		return ReasonDenialWrongZone
	}
	return ReasonNone
}

// proveNameError establishes that qname does not exist.
//
// R-N3-05, RFC 5155 §8.4:
//
//	A validator MUST verify that there is a closest encloser proof for QNAME
//	present in the response and that there is an NSEC3 RR that covers the
//	wildcard at the closest encloser (i.e., the name formed by prepending the
//	asterisk label to the closest encloser).
//
// Opt-out is not treated as disqualifying here, and that is a deliberate
// reading rather than an oversight. §8.4 imposes no such condition, and every
// opt-out zone — which is most large TLDs — answers NXDOMAIN from within an
// opt-out span routinely; refusing those would be a false Bogus across most of
// the Internet. RFC 5155 §12.2 states the residual weakness plainly and treats
// it as inherent to opt-out rather than as a validator's choice: "the primary
// difference in security when using Opt-Out is the loss of the ability to
// prove the existence or nonexistence of an insecure delegation within the
// span of an Opt-Out NSEC3 RR".
func (s *nsec3Set) proveNameError(qname string) Reason {
	proof, reason := s.closestEncloser(qname)
	if reason != ReasonNone {
		return reason
	}
	if s.cover(wildcardAt(proof.encloser)) == nil {
		if s.exhausted {
			return ReasonResourceLimit
		}
		return ReasonDenialIncomplete
	}
	return ReasonNone
}

// proveNoData establishes that qname exists and carries no RRset of rrtype.
//
// R-N3-06, RFC 5155 §8.5, for every type but DS:
//
//	The validator MUST verify that an NSEC3 RR that matches QNAME is present
//	and that both the QTYPE and the CNAME type are not set in its Type Bit
//	Maps field.
//
// R-N3-08, §8.7, is the wildcard form: where no NSEC3 matches QNAME, a
// NOERROR/NODATA may still be legitimate if a wildcard would have matched and
// that wildcard has no such type either. It needs a closest encloser proof and
// a record matching the wildcard.
//
// The empty non-terminal case needs no special handling, unlike NSEC: §8.5
// notes that the test "also covers the case where the NSEC3 RR exists because
// it corresponds to an empty non-terminal, in which case the NSEC3 RR will
// have an empty Type Bit Maps field". NSEC3 zones publish records for empty
// non-terminals; NSEC zones do not.
func (s *nsec3Set) proveNoData(qname string, rrtype uint16) Reason {
	if s.empty() {
		return ReasonNoDenialProof
	}
	if rrtype == dns.TypeDS {
		return s.proveNoDSData(qname)
	}

	if m := s.match(qname); m != nil {
		if nsec3HasType(m.rr, rrtype) || nsec3HasType(m.rr, dns.TypeCNAME) {
			return ReasonDenialContradicted
		}
		return ReasonNone
	}
	if s.exhausted {
		return ReasonResourceLimit
	}

	// No record at the name: the answer can only be legitimate if a wildcard
	// would have matched and has no such type.
	proof, reason := s.closestEncloser(qname)
	if reason != ReasonNone {
		return reason
	}
	wildcard := s.match(wildcardAt(proof.encloser))
	if wildcard == nil {
		if s.exhausted {
			return ReasonResourceLimit
		}
		return ReasonDenialIncomplete
	}
	if nsec3HasType(wildcard.rr, rrtype) || nsec3HasType(wildcard.rr, dns.TypeCNAME) {
		return ReasonDenialContradicted
	}
	return ReasonNone
}

// proveNoDSData is R-N3-07, RFC 5155 §8.6, which is the one place opt-out is
// allowed to establish something:
//
//	If there is an NSEC3 RR that matches QNAME present in the response, then
//	that NSEC3 RR MUST NOT have the bits corresponding to DS and CNAME set in
//	its Type Bit Maps field.
//
//	If there is no such NSEC3 RR, then the validator MUST verify that a
//	closest provable encloser proof for QNAME is present in the response, and
//	that the NSEC3 RR that covers the "next closer" name has the Opt-Out bit
//	set.
//
// The opt-out branch is what makes NSEC3 usable for a TLD with millions of
// unsigned delegations, and it is confined to this question. It says only
// that no DS is published, which is all an insecure delegation needs.
func (s *nsec3Set) proveNoDSData(qname string) Reason {
	if m := s.match(qname); m != nil {
		if nsec3HasType(m.rr, dns.TypeDS) || nsec3HasType(m.rr, dns.TypeCNAME) {
			return ReasonDenialContradicted
		}
		return ReasonNone
	}
	if s.exhausted {
		return ReasonResourceLimit
	}

	proof, reason := s.closestEncloser(qname)
	if reason != ReasonNone {
		return reason
	}
	if !proof.optOut {
		// Without opt-out, the absence of a record at the name is not a
		// statement about the name. Accepting it would let a response prove
		// an insecure delegation by omission.
		return ReasonDenialIncomplete
	}
	return ReasonNone
}

// proveNoDS reads what an NSEC3 proof says about the DS at a delegation name.
//
// R-N3-10, RFC 5155 §8.9:
//
//	If there is an NSEC3 RR present in the response that matches the
//	delegation name, then the validator MUST ensure that the NS bit is set
//	and that the DS bit is not set in the Type Bit Maps field of the NSEC3
//	RR.  The validator MUST also ensure that the NSEC3 RR is from the correct
//	(i.e., parent) zone.  This is done by ensuring that the SOA bit is not
//	set in the Type Bit Maps field of this NSEC3 RR.
//
//	If there is no NSEC3 RR present that matches the delegation name, then
//	the validator MUST verify a closest provable encloser proof for the
//	delegation name.  The validator MUST verify that the Opt-Out bit is set
//	in the NSEC3 RR that covers the "next closer" name to the delegation
//	name.
func (s *nsec3Set) proveNoDS(child string) dsDenial {
	if s.empty() {
		return dsDenialNone
	}

	if m := s.match(child); m != nil {
		// The child's own apex record answers a different question.
		if nsec3HasType(m.rr, dns.TypeSOA) {
			return dsDenialNone
		}
		if nsec3HasType(m.rr, dns.TypeDS) {
			return dsDenialContradicted
		}
		if nsec3HasType(m.rr, dns.TypeNS) {
			return dsDenialInsecure
		}
		return dsDenialNotADelegation
	}
	if s.exhausted {
		return dsDenialNone
	}

	proof, reason := s.closestEncloser(child)
	if reason != ReasonNone {
		return dsDenialNone
	}
	if proof.optOut {
		// An opt-out span may hold insecure delegations without records of
		// their own, which is exactly what this is.
		return dsDenialInsecure
	}
	// Covered without opt-out: the name genuinely does not exist, so it is
	// not a delegation.
	return dsDenialNameAbsent
}

// proveWildcardAnswer is R-N3-09, RFC 5155 §8.8:
//
//	The verified wildcard answer RRSet in the response provides the validator
//	with a (candidate) closest encloser for QNAME.  This closest encloser is
//	the immediate ancestor to the generating wildcard.
//
//	Validators MUST verify that there is an NSEC3 RR that covers the "next
//	closer" name to QNAME present in the response.  This proves that QNAME
//	itself did not exist and that the correct wildcard was used to generate
//	the response.
//
// The encloser is taken from the RRSIG's Labels field rather than proved,
// which is what "candidate" means: the signature establishes how many labels
// the signed name had, and covering the next closer name is what turns the
// candidate into the real one.
func (s *nsec3Set) proveWildcardAnswer(qname string, expandedFrom int) Reason {
	if s.empty() {
		return ReasonNoDenialProof
	}
	encloser := ancestorWithLabels(qname, expandedFrom)
	if encloser == "" {
		return ReasonDenialIncomplete
	}
	closer, ok := nextCloser(qname, encloser)
	if !ok {
		return ReasonDenialIncomplete
	}
	if s.cover(closer) == nil {
		if s.exhausted {
			return ReasonResourceLimit
		}
		return ReasonDenialIncomplete
	}
	return ReasonNone
}
