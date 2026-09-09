package lab

import "github.com/miekg/dns"

// Wildcard synthesis, and the proof a synthesised answer owes.
//
// RFC 4592 §3.3.1 gives exactly one place a wildcard may be expanded from:
// the "source of synthesis", which is the asterisk label prepended to the
// query name's closest encloser. Not any wildcard above the name — the one
// directly below the deepest ancestor that exists. A lab that expanded from
// the first wildcard it found walking upwards would answer queries a real
// server answers NXDOMAIN for, and any validator agreeing with it would be
// agreeing with the harness rather than with the DNS.
//
// The answer such an expansion produces is signed, genuinely, by the zone.
// That is what makes the accompanying denial necessary rather than
// decorative: the same signature is valid for every name under the encloser,
// so without a proof that the queried name itself did not exist, an attacker
// replays one wildcard answer over a name that has its own records.

// closestEncloser returns the deepest ancestor of qname that exists in this
// zone, which is where wildcard synthesis is anchored.
//
// Computed from the zone's actual contents. The validator derives the same
// name from a single NSEC record instead, which is the harder direction; the
// two arriving at the same answer from different information is the point.
func (z *Zone) closestEncloser(qname string) string {
	name := dns.CanonicalName(qname)
	for {
		if z.nameExists(name) {
			return name
		}
		if name == z.Name || name == "." {
			return z.Name
		}
		idx := dns.Split(name)
		if len(idx) < 2 {
			return z.Name
		}
		name = name[idx[1]:]
	}
}

// synthesise builds a wildcard-expanded answer for qname, returning the
// records and the wildcard owner name they came from.
//
// The RRSIG travels unchanged apart from its owner name. That is what a real
// server sends: the signature covers the wildcard owner, and the Labels field
// is what tells a validator to reconstruct it (RFC 4035 §5.3.2). Re-signing
// the expanded name here would produce a signature no zone ever makes, and
// the wildcard reconstruction path would never be exercised.
func (z *Zone) synthesise(qname string, rrtype uint16) ([]dns.RR, string) {
	name := dns.CanonicalName(qname)
	source := wildcardUnder(z.closestEncloser(name))

	records := z.sets[setKey{name: source, rrtype: rrtype}]
	if len(records) == 0 {
		return nil, ""
	}
	// A wildcard cannot synthesise an answer for its own owner name, and
	// cannot cover a name that exists.
	if name == source || z.nameExists(name) {
		return nil, ""
	}

	out := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		copied := dns.Copy(rr)
		copied.Header().Name = name
		out = append(out, copied)
	}
	return out, source
}

// wildcardJustification returns the signed denial that the expansion was
// legitimate: the NSEC covering the next closer name.
//
// RFC 4035 §5.3.4 requires "the non-existence of an exact match or closer
// wildcard match for the query". Denying the next closer name — the ancestor
// of qname one label below the encloser — does both at once: if it does not
// exist then neither does qname, and no wildcard deeper than the source of
// synthesis can exist either.
func (z *Zone) wildcardJustification(qname, source string) []dns.RR {
	encloser := parentOf(source)
	closer := nextCloserName(qname, encloser)
	if closer == "" {
		return nil
	}
	if z.useNSEC3 {
		return z.nsec3Covering(closer)
	}
	return z.nsecCovering(closer)
}

// parentOf strips one label.
func parentOf(name string) string {
	c := dns.CanonicalName(name)
	idx := dns.Split(c)
	if len(idx) < 2 {
		return "."
	}
	return c[idx[1]:]
}

// nextCloserName returns the ancestor of qname exactly one label longer than
// encloser, or "" when there is none.
func nextCloserName(qname, encloser string) string {
	q := dns.CanonicalName(qname)
	e := dns.CanonicalName(encloser)
	if q == e || !dns.IsSubDomain(e, q) {
		return ""
	}
	want := dns.CountLabel(e) + 1
	have := dns.CountLabel(q)
	if have < want {
		return ""
	}
	idx := dns.Split(q)
	drop := have - want
	if drop < 0 || drop >= len(idx) {
		return ""
	}
	return q[idx[drop]:]
}
