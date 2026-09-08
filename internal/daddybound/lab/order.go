package lab

import (
	"bytes"

	"github.com/miekg/dns"
)

// Canonical name ordering, implemented independently of the validator.
//
// The lab has to sort names to build an NSEC chain, and the validator has to
// sort names to check one. If both used the same code, a bug in it would
// cancel out: the chain would be built wrong, checked wrong, and every test
// would pass while the zone was unusable by any other implementation.
//
// So this is a second implementation of RFC 4034 §6.1, written to a
// different construction. The validator walks label arrays from the right;
// this builds a single sort key whose byte order *is* the canonical order,
// then compares keys. A cross-check test asserts the two agree over a large
// generated set of names, which is a differential test of the same rule
// against itself — the cheapest independent check available.

// canonicalLess reports whether a sorts before b in canonical DNS name order.
func canonicalLess(a, b string) bool {
	return bytes.Compare(canonicalSortKey(a), canonicalSortKey(b)) < 0
}

// canonicalSortKey builds a byte string whose ordinary lexicographic order
// matches RFC 4034 §6.1 canonical name order.
//
// Labels are emitted rightmost first, since the RFC orders names by their
// labels starting from the right. Each label is followed by a separator that
// must sort below every possible label octet — and a DNS label may contain
// any octet, including zero, so a bare 0x00 separator would be ambiguous.
//
// The escape solves it: a zero octet inside a label becomes 0x00 0x01, and
// the separator is 0x00 0x00. Every escaped octet therefore begins with
// something greater than or equal to the separator's first byte and, where
// equal, is followed by a larger second byte. A label that is a prefix of
// another hits its separator first and sorts before it, which is the RFC's
// "the absence of an octet sorts before a zero octet".
//
// The leading tag byte places orderable and unorderable names in separate
// ranges. Without it, "sorts last" has to be expressed as a key made of high
// octets, and a real name whose rightmost label begins with 0xFF then sorts
// above it — so a name the lab cannot place would slip *below* a name it
// can, disagreeing with the validator about which of the two an NSEC
// interval covers. The cross-check test found exactly that; the tag makes
// the two ranges disjoint by construction rather than by luck of the octets.
func canonicalSortKey(name string) []byte {
	labels, ok := wireLabels(name)
	if !ok {
		// Unorderable names sort after every orderable one and equal to each
		// other, matching the validator's rule so that the two
		// implementations agree even on inputs neither can place.
		return []byte{keyUnorderable}
	}

	key := []byte{keyOrderable}
	for i := len(labels) - 1; i >= 0; i-- {
		for _, b := range labels[i] {
			if b == 0x00 {
				key = append(key, 0x00, 0x01)
				continue
			}
			key = append(key, b)
		}
		key = append(key, 0x00, 0x00)
	}
	return key
}

// Sort-key range tags. See canonicalSortKey.
const (
	keyOrderable   = 0x00
	keyUnorderable = 0x01
)

// wireLabels returns a name's labels as raw octets, root omitted.
func wireLabels(name string) ([][]byte, bool) {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(dns.CanonicalName(name), buf, 0, nil, false)
	if err != nil {
		return nil, false
	}
	var out [][]byte
	for off := 0; off < n; {
		length := int(buf[off])
		if length == 0 {
			break
		}
		if length > 63 || off+1+length > n {
			return nil, false
		}
		out = append(out, buf[off+1:off+1+length])
		off += 1 + length
	}
	return out, true
}

// intervalCovers reports whether name falls strictly between owner and next,
// which is what an NSEC record asserts about the names it covers.
//
// The wrapping case is the last record in a zone, whose next name points back
// at the apex and which therefore covers everything from its owner to the end
// of the zone.
func intervalCovers(name, owner, next string) bool {
	nk := canonicalSortKey(name)
	ok := canonicalSortKey(owner)
	nx := canonicalSortKey(next)

	afterOwner := bytes.Compare(nk, ok) > 0
	beforeNext := bytes.Compare(nk, nx) < 0

	switch c := bytes.Compare(ok, nx); {
	case c < 0:
		return afterOwner && beforeNext
	case c > 0:
		return afterOwner || beforeNext
	default:
		return !bytes.Equal(nk, ok)
	}
}
