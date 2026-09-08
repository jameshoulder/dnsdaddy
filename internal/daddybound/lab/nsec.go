package lab

import (
	"sort"

	"github.com/miekg/dns"
)

// NSEC chain generation.
//
// A signed zone using NSEC publishes, for every name it is authoritative
// for, one NSEC record naming the next such name in canonical order and
// listing the types present. The chain closes: the last name points back at
// the apex. Together the records assert that nothing exists between any two
// adjacent names, which is what makes a denial provable rather than merely
// asserted.
//
// RFC 4035 §2.3: "Each owner name in the zone that has authoritative data or
// a delegation point NS RRset MUST have an NSEC resource record."
//
// The lab generates these rather than hand-writing them because a
// hand-written chain is a fixture, and a fixture teaches a validator to
// accept that fixture. A generated chain follows the rule, so a validator
// that only handles the shapes someone thought to write down fails here.

// buildNSECChain generates and signs the NSEC records for one zone.
//
// Called after every other record in the zone exists — including the DS
// records a parent publishes for its children — because the type bitmaps
// describe what is present, and a bitmap computed too early would omit them.
func (z *Zone) buildNSECChain(spec Spec) error {
	if !z.useNSEC {
		return nil
	}

	names := z.authoritativeNames()
	if len(names) == 0 {
		return nil
	}

	for i, name := range names {
		next := names[0] // the last record wraps back to the apex
		if i+1 < len(names) {
			next = names[i+1]
		}

		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600,
			},
			NextDomain: next,
			TypeBitMap: z.typesAt(name),
		}
		if err := z.addSigned(spec, []dns.RR{nsec}); err != nil {
			return err
		}
	}
	return nil
}

// authoritativeNames lists the names this zone must publish an NSEC for, in
// canonical order.
//
// A delegation point counts: the parent is not authoritative for the child's
// data, but it is authoritative for the fact of the delegation, and the NSEC
// at that name is what carries the DS bit — set for a secure delegation,
// clear for an insecure one. Omitting it would make insecure delegations
// unprovable.
func (z *Zone) authoritativeNames() []string {
	seen := map[string]bool{}
	for k := range z.sets {
		// RRSIG and NSEC are not themselves reasons for a name to exist.
		if k.rrtype == dns.TypeRRSIG || k.rrtype == dns.TypeNSEC {
			continue
		}
		seen[k.name] = true
	}

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		return canonicalLess(out[i], out[j])
	})
	return out
}

// typesAt returns the RR types present at a name, in the order NSEC requires.
//
// RRSIG and NSEC are included because the zone really does publish them
// there. A validator checking "is type X absent" against a bitmap that
// omitted them would conclude the zone is unsigned at that name.
func (z *Zone) typesAt(name string) []uint16 {
	var types []uint16
	seen := map[uint16]bool{}
	for k := range z.sets {
		if k.name != name || seen[k.rrtype] {
			continue
		}
		seen[k.rrtype] = true
		types = append(types, k.rrtype)
	}
	if !seen[dns.TypeRRSIG] {
		types = append(types, dns.TypeRRSIG)
	}
	if !seen[dns.TypeNSEC] {
		types = append(types, dns.TypeNSEC)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

// denialFor returns the signed records that prove a denial for qname in zone.
//
// Which records are needed depends on what is being denied, and the two
// cases are genuinely different proofs rather than one proof with an extra
// record:
//
//   - NODATA: the name exists, so the NSEC *matching* it proves the type is
//     absent by omitting it from the bitmap.
//   - NXDOMAIN: the name does not exist, so one NSEC must *cover* it, and a
//     second must cover the wildcard that could otherwise have synthesised
//     an answer. Without the second, a validator has been shown that the
//     exact name is missing while a wildcard quietly answers for it.
func (h *Hierarchy) denialFor(zone *Zone, qname string, rrtype uint16, rcode int) []dns.RR {
	if zone.useNSEC3 {
		return h.nsec3DenialFor(zone, qname, rrtype, rcode)
	}

	var out []dns.RR
	add := func(rr []dns.RR) {
		for _, r := range rr {
			if !containsRR(out, r) {
				out = append(out, r)
			}
		}
	}

	if rcode == dns.RcodeSuccess {
		if match := zone.nsecMatching(qname); match != nil {
			add(match)
			return out
		}
		// No NSEC at the name, and yet the name exists: an empty
		// non-terminal. RFC 4035 §2.3 requires an NSEC only at names with
		// authoritative data or a delegation NS RRset, and an empty
		// non-terminal has neither, so a correctly signed NSEC zone
		// publishes none there. RFC 7129 §5.1 puts it plainly: "An empty
		// non-terminal will get an NSEC3 record but not an NSEC record."
		//
		// What proves the NODATA is the NSEC spanning the name, whose next
		// name is a descendant of it — that descendant exists, so every
		// ancestor of it exists too, including this one.
		add(zone.nsecCovering(qname))
		return out
	}

	// NXDOMAIN. Two separate facts have to be proved, and the second is the
	// one an attacker would omit.
	add(zone.nsecCovering(qname))

	// The wildcard that could have answered sits directly below the closest
	// encloser — the deepest ancestor of qname that exists — and not below
	// the zone apex. Denying "*.<apex>" instead would prove nothing about a
	// zone whose wildcard lives deeper, and a validator checking the right
	// name would correctly reject the proof.
	add(zone.nsecCovering(wildcardUnder(zone.closestEncloser(qname))))
	return out
}

// nsecMatching returns the NSEC RRset whose owner is exactly name.
func (z *Zone) nsecMatching(name string) []dns.RR {
	return z.sets[setKey{name: dns.CanonicalName(name), rrtype: dns.TypeNSEC}]
}

// nsecCovering returns the NSEC RRset whose interval contains name.
func (z *Zone) nsecCovering(name string) []dns.RR {
	for k, records := range z.sets {
		if k.rrtype != dns.TypeNSEC {
			continue
		}
		for _, rr := range records {
			nsec, ok := rr.(*dns.NSEC)
			if !ok {
				continue
			}
			if intervalCovers(name, nsec.Hdr.Name, nsec.NextDomain) {
				return records
			}
		}
	}
	return nil
}

func wildcardUnder(zone string) string { return "*." + dns.CanonicalName(zone) }

func containsRR(haystack []dns.RR, needle dns.RR) bool {
	for _, rr := range haystack {
		if rr.String() == needle.String() {
			return true
		}
	}
	return false
}
