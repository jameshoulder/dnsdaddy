package dnssec

import (
	"sort"

	"github.com/miekg/dns"
)

// Authenticated denial of existence: the frame shared by NSEC and NSEC3.
//
// The single most important line in RFC 4035 §5.4 is not one of the two
// bulleted rules. It is this one (R-DEN-01):
//
//	In addition, security-aware resolvers MUST authenticate the NSEC RRsets
//	that comprise the non-existence proof as described in Section 5.3.
//
// Receiving an NSEC record proves nothing whatsoever. Anyone can put an NSEC
// record in a response, and an attacker forging a denial will happily supply
// one that covers exactly the name they want denied. What makes a denial a
// proof is that the records carrying it were signed by a key this walk has
// already authenticated, and that the intervals they assert genuinely entail
// the claim being made.
//
// So this file does the first half — turning received records into
// authenticated ones, and discarding everything that does not survive — and
// nsec.go does the second. Nothing downstream is allowed to see an
// unauthenticated denial record, which is enforced by the proof type carrying
// only authenticated ones.

// authenticNSEC is an NSEC RR whose RRset was verified against a zone's keys.
//
// The signer is carried alongside because RFC 6840 §4.1's ancestor-delegation
// test is defined partly in terms of it: an NSEC is an ancestor delegation
// record when, among other things, its "signer field ... is shorter than the
// owner name of the NSEC RR". Recomputing that later from the zone name would
// be the same value by construction here, but the rule is written about the
// signer field, so the signer field is what gets stored.
type authenticNSEC struct {
	rr     *dns.NSEC
	signer string

	// intervalUnusable marks a record merged from several that disagreed
	// about their Next Domain Name. Such a group still says what types
	// exist at its owner — the union — but it asserts two different
	// intervals, and no interval arithmetic over that is sound.
	intervalUnusable bool
}

// denialProof is the authenticated denial material from one response.
//
// There is no constructor that takes records without authenticating them, and
// no field that holds unauthenticated ones. That is the type doing the work
// the comment above describes: code holding a denialProof cannot accidentally
// reason about a record that was merely received.
type denialProof struct {
	// nsec holds every NSEC RR that verified.
	nsec []authenticNSEC

	// nsec3 holds the authenticated NSEC3 material, already reduced to one
	// parameter set. Nil when the response carried none.
	nsec3 *nsec3Set

	// refusedNSEC3 records that a usable NSEC3 record was set aside because
	// of this validator's iteration ceiling.
	//
	// Only that one reason. Records ignored under RFC 5155 §8.1 and §8.2 —
	// unassigned hash algorithms, reserved flag bits — are ignored on the
	// standard's instruction, by every validator, so a response left
	// unproved by them has failed to prove its claim and is Bogus. The
	// ceiling is Daddybound's own choice, so a response left unproved by
	// that is Indeterminate. Conflating the two was a real bug here, and
	// both reference validators caught it.
	refusedNSEC3 bool

	// unauthenticated counts denial records that were present and did not
	// verify. Recorded for the trace: "no proof" and "a proof that failed to
	// verify" read very differently to somebody investigating.
	unauthenticated int

	// truncated records that the response carried more denial RRsets than
	// MaxDenialRecords and collection stopped early.
	//
	// It changes what a subsequent failure is allowed to say. Records that
	// were read and found wanting support an accusation; records that were
	// never read support only an admission. Without this a response could be
	// padded until the real proof fell off the end and the verdict came back
	// Bogus, which blames the zone for the attacker's padding.
	truncated bool
}

// empty reports whether the proof carries no NSEC records. NSEC3 is asked
// about separately, because the two are alternative proofs of the same fact
// and a zone publishes one or the other.
func (d *denialProof) empty() bool { return len(d.nsec) == 0 }

// hasNSEC3 reports whether usable NSEC3 material is present.
func (d *denialProof) hasNSEC3() bool { return !d.nsec3.empty() }

// collectDenial authenticates the NSEC and NSEC3 records in an authority
// section against a zone whose apex DNSKEY RRset is already trusted.
//
// Records are grouped into RRsets by owner name before verification, because
// that is what a signature covers (R-SET-01). Verifying record by record
// would ask each signature to cover a subset of what it actually signed, and
// every multi-record NSEC RRset would fail for a reason pointing at the
// cryptography.
//
// A group that fails to verify is dropped rather than escalated. Dropping is
// right because the response may legitimately carry denial records from more
// than one place — a referral carries the parent's, and a validator asking
// about something else entirely may see records it has no key for — and
// because the caller decides what an insufficient proof means. Escalating
// here would make an irrelevant unverifiable record poison a proof that is
// otherwise complete.
func (w *walk) collectDenial(zone *zoneState, authority []dns.RR) denialProof {
	var proof denialProof

	// One budget across both mechanisms, so a response cannot get a full
	// allowance of each by mixing them.
	budget := w.v.cfg.Limits.MaxDenialRecords

	for _, group := range groupByOwner(authority, dns.TypeNSEC) {
		if budget <= 0 {
			proof.truncated = true
			break
		}
		budget--
		set, reason := NewRRset(group.data)
		if reason != ReasonNone {
			proof.unauthenticated++
			w.rec.skip(ValidationStep{
				Kind: StepDenial, Zone: zone.name, Name: group.owner, RRType: dns.TypeNSEC,
			}, reason)
			continue
		}
		if reason := w.authenticate(set, group.sigs, zone.name, zone.keys); reason != ReasonNone {
			proof.unauthenticated++
			w.rec.skip(ValidationStep{
				Kind: StepDenial, Zone: zone.name, Name: group.owner, RRType: dns.TypeNSEC,
				Note: "not authenticated by this zone's keys, so it proves nothing",
			}, reason)
			continue
		}

		// The signer of whichever RRSIG authenticated the set. authenticate
		// has already required it to be exactly this zone (the strong form
		// of R-SIG-02), so this is the zone name; it is read from the
		// signature rather than assumed, because R-DEN-06 is written about
		// the signer field.
		signer := zone.name
		for _, rr := range group.data {
			if nsec, ok := rr.(*dns.NSEC); ok {
				proof.nsec = append(proof.nsec, authenticNSEC{rr: nsec, signer: signer})
			}
		}
		w.rec.ok(ValidationStep{
			Kind: StepDenial, Zone: zone.name, Name: group.owner, RRType: dns.TypeNSEC,
		})
	}

	proof.nsec = mergeNSECByOwner(proof.nsec)

	var n3truncated bool
	proof.nsec3, proof.refusedNSEC3, n3truncated = w.collectNSEC3(zone, authority, budget)
	proof.truncated = proof.truncated || n3truncated
	if proof.truncated {
		w.rec.skip(ValidationStep{
			Kind: StepDenial, Zone: zone.name,
			Note: "more denial records than the configured budget; the rest were not read",
		}, ReasonResourceLimit)
	}
	return proof
}

// ownerGroup is one RRset's worth of records plus the signatures over it.
type ownerGroup struct {
	owner string
	data  []dns.RR
	sigs  []*dns.RRSIG
}

// groupByOwner partitions records of one type into RRsets by owner name.
//
// Deterministic order: owners appear in the order they were first seen in the
// section. A trace that reordered between runs could not be diffed, and this
// package's evidence is its traces.
func groupByOwner(records []dns.RR, rrtype uint16) []ownerGroup {
	index := make(map[string]*ownerGroup)
	var order []string

	get := func(name string) *ownerGroup {
		if g, seen := index[name]; seen {
			return g
		}
		g := &ownerGroup{owner: name}
		index[name] = g
		order = append(order, name)
		return g
	}

	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.TypeCovered == rrtype {
				g := get(dns.CanonicalName(sig.Hdr.Name))
				g.sigs = append(g.sigs, sig)
			}
			continue
		}
		if rr.Header().Rrtype == rrtype {
			g := get(dns.CanonicalName(rr.Header().Name))
			g.data = append(g.data, rr)
		}
	}

	out := make([]ownerGroup, 0, len(order))
	for _, name := range order {
		// An owner with signatures but no records is a signature over
		// nothing. It is not an RRset and there is nothing for it to prove.
		if len(index[name].data) == 0 {
			continue
		}
		out = append(out, *index[name])
	}
	return out
}

// denialUnavailable turns "this proof carries nothing usable" into the right
// reason, which depends on whose fault it is.
//
// Getting this distinction wrong in either direction is a real bug. Reporting
// a missing proof as a Daddybound limitation excuses a response that owed one;
// reporting a proof this build declines to read as a fault in the response
// accuses a correctly signed zone of forgery.
func (d *denialProof) denialUnavailable() Reason {
	if d.refusedNSEC3 {
		return ReasonDenialNotImplemented
	}
	return ReasonNoDenialProof
}

// unreadOverReported turns a failure reason into an admission when the proof
// was truncated before it could be read in full.
//
// Only the reasons that mean "not enough evidence" are converted. A
// contradiction or a wrong-zone finding comes from a record that *was* read
// and verified, so it stands on its own however many records went unread
// afterwards — and downgrading it would let padding hide a lie as easily as
// it hides a proof.
func (d *denialProof) unreadOverReported(reason Reason) Reason {
	if !d.truncated {
		return reason
	}
	switch reason {
	case ReasonNoDenialProof, ReasonDenialIncomplete:
		return ReasonResourceLimit
	default:
		return reason
	}
}

// mergeNSECByOwner collapses authenticated NSEC records sharing an owner name
// into one record per name.
//
// A correct zone publishes one NSEC per name (RFC 4034 §4.1), and RFC 5155
// §7.1 step 6 tells an NSEC3 signer to combine records with identical hashed
// owner names "with the Type Bit Maps field consisting of the union of the
// types represented by the set". Nothing enforces that on the wire, though: a
// signer can emit two, both are then genuinely signed as one RRset, and a
// validator that reads "the" record at a name has to pick.
//
// Picking the first was a defect, and an exploitable one. The records arrive
// in whatever order an on-path attacker chooses, so if one bitmap lists the
// queried type and the other does not, the attacker decides between "the type
// exists, this NODATA is a lie" and "proved". They would choose the second.
//
// The union is both order-independent and the safe direction: a type present
// in any record is treated as present, which produces refusals rather than
// proofs. The interval is different — coverage is what licenses a proof, not
// what withholds one — so records that disagree about their Next Domain Name
// yield a group whose bitmap is still usable and whose interval is not.
func mergeNSECByOwner(records []authenticNSEC) []authenticNSEC {
	if len(records) < 2 {
		return records
	}

	index := make(map[string]int, len(records))
	out := make([]authenticNSEC, 0, len(records))

	for _, a := range records {
		owner := dns.CanonicalName(a.rr.Hdr.Name)
		at, seen := index[owner]
		if !seen {
			index[owner] = len(out)
			out = append(out, a)
			continue
		}

		merged, ok := dns.Copy(out[at].rr).(*dns.NSEC)
		if !ok {
			// Cannot merge what cannot be copied. Refusing the interval
			// leaves the group able to say what exists and unable to prove
			// what does not, which is the direction to fail in.
			out[at].intervalUnusable = true
			continue
		}
		merged.TypeBitMap = unionTypes(out[at].rr.TypeBitMap, a.rr.TypeBitMap)
		out[at].rr = merged
		if !equalNames(out[at].rr.NextDomain, a.rr.NextDomain) {
			out[at].intervalUnusable = true
		}
	}
	return out
}

// unionTypes merges two NSEC type bitmaps, sorted ascending as the wire
// format requires.
func unionTypes(a, b []uint16) []uint16 {
	seen := make(map[uint16]bool, len(a)+len(b))
	out := make([]uint16, 0, len(a)+len(b))
	for _, list := range [][]uint16{a, b} {
		for _, t := range list {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
