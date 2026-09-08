package dnssec

import (
	"bytes"
	"strings"

	"github.com/miekg/dns"
)

// Canonical DNS name ordering, and the interval reasoning that every denial
// proof is built on.
//
// RFC 4034 §6.1:
//
//	For the purposes of DNS security, owner names are ordered by treating
//	individual labels as unsigned left-justified octet strings. The absence
//	of a octet sorts before a zero octet.
//
//	... Domain names are sorted by comparing the sequences of labels,
//	starting from the rightmost label ...
//
// Getting this wrong is not a cosmetic bug. An NSEC record proves
// non-existence by asserting that nothing sorts between two names, so a
// comparison that orders names differently from the signer either proves
// nothing or "proves" the non-existence of a name that does exist — and the
// second is a false Secure.

// compareCanonicalNames orders two domain names as RFC 4034 §6.1 requires.
//
// It returns a negative number if a sorts before b, zero if they are the same
// name, and a positive number otherwise.
//
// Labels are compared as **wire-format octets**, not as presentation text.
// That distinction is not pedantry: the RFC says "treating individual labels
// as unsigned left-justified octet strings", and its own worked example
// depends on it. The label written \001 is a single octet, 0x01, and must
// sort before the label *, which is 0x2A. Compared as presentation strings,
// \001 begins with a backslash (0x5C) and sorts after * instead. An NSEC
// interval computed that way excludes names the signer included, so it either
// proves nothing or proves the non-existence of a name that exists.
//
// Comparison runs from the rightmost label, which is what makes the ordering
// hierarchical: every name under example.test sorts together, and the zone
// apex sorts before all of them.
func compareCanonicalNames(a, b string) int {
	al, aok := canonicalWireLabels(a)
	bl, bok := canonicalWireLabels(b)

	// A name that cannot be expressed on the wire has no place in this
	// ordering. Rather than inventing one, such names sort after every
	// well-formed name and equal to each other: a total order, so sorting
	// stays well defined, and one that cannot drop an unorderable name
	// inside an NSEC interval and have it prove something. Proof code
	// rejects such names up front — see validNameForProof.
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return 1
	case !bok:
		return -1
	}

	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		if c := bytes.Compare(al[i], bl[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	// One name ran out of labels first, making it a suffix of the other, and
	// a suffix sorts before it. That is "the absence of an octet sorts before
	// a zero octet" applied at label granularity.
	switch {
	case i < 0 && j < 0:
		return 0
	case i < 0:
		return -1
	default:
		return 1
	}
}

// canonicalWireLabels returns each label of a name as raw octets, in the
// order they appear, with the root label omitted.
//
// Packing is what turns presentation escapes into the octets the ordering is
// defined over. It also validates the name: anything that cannot be packed is
// not a name a signer could have signed.
func canonicalWireLabels(name string) ([][]byte, bool) {
	wire := make([]byte, 256)
	n, err := dns.PackDomainName(dns.CanonicalName(name), wire, 0, nil, false)
	if err != nil {
		return nil, false
	}

	var labels [][]byte
	for off := 0; off < n; {
		length := int(wire[off])
		if length == 0 {
			break // the root label terminates the name
		}
		// Compression pointers cannot occur — compression was disabled —
		// and an over-long label cannot be packed. Both are refused rather
		// than skipped past.
		if length > 63 || off+1+length > n {
			return nil, false
		}
		labels = append(labels, wire[off+1:off+1+length])
		off += 1 + length
	}
	return labels, true
}

// validNameForProof reports whether a name can take part in canonical
// ordering at all.
//
// Denial proofs are interval arithmetic over names, so a name the ordering
// cannot place is one no interval can meaningfully cover. Proof code checks
// this before reasoning, rather than letting an unorderable name silently
// land somewhere.
func validNameForProof(name string) bool {
	_, ok := canonicalWireLabels(name)
	return ok
}

// nameInInterval reports whether qname falls strictly between owner and next
// in canonical order — which is what an NSEC RR asserts about the names it
// covers.
//
// The wrap is the part worth reading twice. The last NSEC in a zone points
// back at the apex, so its owner sorts *after* its next name. That record
// covers everything from the owner to the end of the zone, and nothing else;
// treating it as an ordinary interval would make it cover nothing at all and
// leave the tail of every zone unprovable.
//
// An NSEC whose owner and next name are equal occurs in a zone with a single
// name. RFC 4034 §4.1.1 has the next name point back at the owner, and such
// a record covers every name other than the owner itself.
func nameInInterval(qname, owner, next string) bool {
	q := dns.CanonicalName(qname)
	o := dns.CanonicalName(owner)
	n := dns.CanonicalName(next)

	cmpON := compareCanonicalNames(o, n)
	afterOwner := compareCanonicalNames(q, o) > 0
	beforeNext := compareCanonicalNames(q, n) < 0

	switch {
	case cmpON < 0:
		// The ordinary case: a half-open interval inside the zone.
		return afterOwner && beforeNext
	case cmpON > 0:
		// The last NSEC, wrapping past the end of the zone back to the
		// apex. It covers everything after the owner, and also everything
		// before the next name — which in a correctly signed zone is only
		// the apex itself, already excluded by being equal to next.
		return afterOwner || beforeNext
	default:
		// owner == next: a single-name zone. Everything except the owner.
		return compareCanonicalNames(q, o) != 0
	}
}

// isSubDomainOf reports whether child is at or below parent.
//
// dns.IsSubDomain does the same job; this wrapper canonicalises first so that
// a case-randomised name is not read as a different one, which is the failure
// this package keeps having to defend against.
func isSubDomainOf(parent, child string) bool {
	return dns.IsSubDomain(dns.CanonicalName(parent), dns.CanonicalName(child))
}

// parentName returns the name one label shorter than name, or the root.
func parentName(name string) string {
	name = dns.CanonicalName(name)
	if name == "." {
		return "."
	}
	idx := dns.Split(name)
	if len(idx) < 2 {
		return "."
	}
	return name[idx[1]:]
}

// wildcardAt returns the wildcard name immediately below name, which is the
// name that could have synthesised an answer for anything under it.
func wildcardAt(name string) string {
	return "*." + dns.CanonicalName(name)
}

// nextCloser returns the ancestor of qname exactly one label longer than
// encloser — the "next closer" name of RFC 5155 §1.3.
//
// Proving that this name does not exist is what turns "encloser is the
// deepest ancestor that does exist" into a proof about qname itself. Returns
// false when encloser is not a proper ancestor of qname, because there is
// then no such name and a caller that proceeded would be reasoning about a
// name it invented.
func nextCloser(qname, encloser string) (string, bool) {
	q := dns.CanonicalName(qname)
	e := dns.CanonicalName(encloser)
	if q == e || !isSubDomainOf(e, q) {
		return "", false
	}

	qLabels := dns.CountLabel(q)
	eLabels := dns.CountLabel(e)
	if qLabels <= eLabels {
		return "", false
	}

	idx := dns.Split(q)
	// The label index that leaves exactly eLabels+1 labels remaining.
	drop := qLabels - (eLabels + 1)
	if drop < 0 || drop >= len(idx) {
		return "", false
	}
	return q[idx[drop]:], true
}

// ancestorsOf lists qname and each of its ancestors up to and including
// zone, longest first.
//
// Used to walk outwards looking for a closest encloser. Bounded by the label
// count of a name that has already been parsed, so it cannot be driven
// unboundedly by a response.
func ancestorsOf(qname, zone string) []string {
	q := dns.CanonicalName(qname)
	z := dns.CanonicalName(zone)
	if !isSubDomainOf(z, q) {
		return nil
	}

	out := []string{q}
	for q != z {
		q = parentName(q)
		out = append(out, q)
		if q == "." {
			break
		}
	}
	return out
}

// isWildcardName reports whether name's leftmost label is the asterisk.
func isWildcardName(name string) bool {
	return strings.HasPrefix(dns.CanonicalName(name), "*.")
}
