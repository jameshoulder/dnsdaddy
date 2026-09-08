package dnssec

import "github.com/miekg/dns"

// RRset is a set of records sharing one owner name, class and type, as
// RFC 2181 §5 defines it (R-SET-01).
//
// It is a distinct type rather than a bare slice because "these records are
// an RRset" is a claim that has to be checked somewhere, and a slice lets
// every caller assume someone else checked. Constructing one goes through
// NewRRset, which does the checking; there is no other way to make a valid
// one from outside this package.
type RRset struct {
	Name   string // canonical form
	Class  uint16
	RRType uint16
	// Records are the members. Order is the caller's; canonicalisation sorts
	// its own copy, so nothing downstream depends on this order.
	Records []dns.RR
}

// NewRRset groups records into an RRset, verifying they belong together.
//
// The check is not a formality. Signed data is built over "the RRset", and a
// caller that hands over records with mixed owner names would get a signature
// verified against a set the signer never signed. Comparing names in
// canonical form is deliberate: a resolver that randomises query case
// (0x20 encoding) returns answers whose owner name differs from the query in
// case alone, and rejecting those as inconsistent would break validation
// against most of the deployed Internet.
func NewRRset(records []dns.RR) (RRset, Reason) {
	if len(records) == 0 {
		return RRset{}, ReasonEmptyRRset
	}
	if len(records) > maxRRsetSize {
		return RRset{}, ReasonResourceLimit
	}

	first := records[0].Header()
	set := RRset{
		Name:    dns.CanonicalName(first.Name),
		Class:   first.Class,
		RRType:  first.Rrtype,
		Records: records,
	}

	for _, rr := range records[1:] {
		h := rr.Header()
		if dns.CanonicalName(h.Name) != set.Name || h.Class != set.Class || h.Rrtype != set.RRType {
			return RRset{}, ReasonInconsistentRRset
		}
	}
	return set, ReasonNone
}

// SplitSignatures separates RRSIG records from the records they cover.
//
// A response carries both together, and the two are validated against each
// other, so keeping them in one slice invites a signature ending up inside
// the data it signs.
//
// RRSIGs covering a type other than rrType are discarded here rather than
// carried forward and rejected later. The type-covered check (R-SIG-03)
// still exists in rrsigAdmissible and is still tested; this is a filter on
// what is even a candidate, not a substitute for it.
func SplitSignatures(records []dns.RR, rrType uint16) (data []dns.RR, sigs []*dns.RRSIG) {
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.TypeCovered == rrType {
				sigs = append(sigs, sig)
			}
			continue
		}
		if rr.Header().Rrtype == rrType {
			data = append(data, rr)
		}
	}
	return data, sigs
}

// SplitSignaturesAt is SplitSignatures restricted to one owner name.
//
// The answer to a query for (QNAME, QTYPE) is the RRset at QNAME, or a CNAME
// chain leading to one (RFC 1034 §4.3.2). Nothing else in the answer section
// answers the question, and a real response routinely carries something else:
// a server that follows a CNAME within its own zone returns the alias and the
// records it points at together, so an answer section holding records at two
// different owner names is the normal case rather than an odd one.
//
// Filtering by owner is therefore not tidiness. Without it a validator picks
// up whichever records match the queried *type*, authenticates them — they are
// genuinely signed, just not an answer to this question — and reports Secure.
// An attacker needs no forgery for that: any signed RRset of the right type
// from anywhere in the zone will do, returned in answer to a query for a name
// it has nothing to do with. This package did exactly that until the review
// that added this function.
func SplitSignaturesAt(records []dns.RR, owner string, rrType uint16) (data []dns.RR, sigs []*dns.RRSIG) {
	want := dns.CanonicalName(owner)
	at := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if dns.CanonicalName(rr.Header().Name) == want {
			at = append(at, rr)
		}
	}
	return SplitSignatures(at, rrType)
}

// dnskeysOf returns the DNSKEY records from a set, ignoring anything else.
func dnskeysOf(records []dns.RR) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, rr := range records {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys
}

// dsOf returns the DS records from a set, ignoring anything else.
func dsOf(records []dns.RR) []*dns.DS {
	var out []*dns.DS
	for _, rr := range records {
		if ds, ok := rr.(*dns.DS); ok {
			out = append(out, ds)
		}
	}
	return out
}
