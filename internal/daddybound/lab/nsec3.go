package lab

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// NSEC3 chain generation, following the construction in RFC 5155 §7.1.
//
// Hashing goes through github.com/miekg/dns, deliberately, for the same
// reason signing does: the validator implements RFC 5155 §5 itself, and a lab
// that hashed with the code under test would produce a chain that agreed with
// any hashing bug the validator had. A cross-check test holds the two
// implementations against each other, and against the RFC's own published
// example hashes.
//
// The properties RFC 5155 §7.1 requires, and which this builds:
//
//	Each owner name within the zone that owns authoritative RRSets MUST have
//	a corresponding NSEC3 RR. ... Each empty non-terminal MUST have a
//	corresponding NSEC3 RR, unless the empty non-terminal is only derived
//	from an insecure delegation covered by an Opt-Out NSEC3 RR.
//
// Empty non-terminals are the visible difference from NSEC, which gives them
// no record at all. Under NSEC3 they are ordinary members of the chain, which
// is why a NODATA at one needs no special reasoning.

// buildNSEC3Chain generates and signs the NSEC3 records for one zone, plus
// the NSEC3PARAM RR that RFC 5155 §7.1 step 8 puts at the apex.
func (z *Zone) buildNSEC3Chain(spec Spec) error {
	if !z.useNSEC3 {
		return nil
	}

	included, excluded := z.nsec3Names()
	if len(included) == 0 {
		return nil
	}

	saltLen, err := nsec3SaltLength(z.n3salt)
	if err != nil {
		return fmt.Errorf("lab: %s: %w", z.Name, err)
	}

	type entry struct {
		hash  string
		name  string
		types []uint16
	}
	entries := make([]entry, 0, len(included))
	seen := map[string]bool{}
	for _, name := range included {
		h := dns.HashName(name, z.n3alg, z.n3iter, z.n3salt)
		if h == "" {
			return fmt.Errorf("lab: cannot hash %s with NSEC3 algorithm %d", name, z.n3alg)
		}
		if seen[h] {
			// RFC 5155 §7.1 step 6 combines records with identical hashes.
			// A collision in a lab zone means the salt needs changing, and
			// silently dropping a name would make the chain deny something
			// that exists.
			return fmt.Errorf("lab: NSEC3 hash collision at %s; choose a different salt", name)
		}
		seen[h] = true
		entries = append(entries, entry{hash: h, name: name, types: z.typesForNSEC3(name)})
	}

	// Step 5: sort into hash order. Base32hex ordering is byte ordering,
	// which is why RFC 5155 §1.3 can say it "is the same as the canonical
	// DNS name order" for these labels.
	sort.Slice(entries, func(i, j int) bool { return entries[i].hash < entries[j].hash })

	excludedHashes := make([]string, 0, len(excluded))
	for _, name := range excluded {
		if h := dns.HashName(name, z.n3alg, z.n3iter, z.n3salt); h != "" {
			excludedHashes = append(excludedHashes, h)
		}
	}

	for i, e := range entries {
		next := entries[0].hash // step 7: the last record wraps to the first
		if i+1 < len(entries) {
			next = entries[i+1].hash
		}

		// RFC 5155 §6: an Opt-Out record "MUST only cover hashed owner names
		// or hashed 'next closer' names of insecure delegations". The flag
		// therefore goes on the records that actually span an excluded
		// delegation and on no others, rather than on every record in the
		// zone. A validator must handle both, but a lab that set it
		// everywhere could not show which record the proof depends on.
		var flags uint8
		if spansAny(e.hash, next, excludedHashes) {
			flags = 1
		}

		rr := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   nsec3Owner(e.hash, z.Name),
				Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600,
			},
			Hash:       z.n3alg,
			Flags:      flags,
			Iterations: z.n3iter,
			Salt:       z.n3salt,
			SaltLength: saltLen,
			NextDomain: next,
			HashLength: 20, // SHA-1
			TypeBitMap: e.types,
		}
		if err := z.addSigned(spec, []dns.RR{rr}); err != nil {
			return err
		}
	}

	param := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name: z.Name, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: 3600,
		},
		Hash: z.n3alg, Flags: 0, Iterations: z.n3iter,
		Salt: z.n3salt, SaltLength: saltLen,
	}
	return z.addSigned(spec, []dns.RR{param})
}

// nsec3SaltLength converts a hexadecimal salt to the one-octet Salt Length
// field RFC 5155 §3.1.5 defines.
//
// The bound is checked rather than assumed. One octet holds at most 255, so a
// salt longer than 510 hexadecimal characters cannot be expressed at all, and
// a silently truncated length field would produce records that parse as a
// different salt — signatures that verify over bytes no validator reconstructs.
// An odd number of characters is not a byte string either.
func nsec3SaltLength(salt string) (uint8, error) {
	if len(salt)%2 != 0 {
		return 0, fmt.Errorf("NSEC3 salt %q has an odd number of hexadecimal characters", salt)
	}
	octets := len(salt) / 2
	if octets > 255 {
		return 0, fmt.Errorf("NSEC3 salt is %d octets; RFC 5155 §3.1.5 gives the Salt Length field one octet", octets)
	}
	// #nosec G115 -- octets is bounded above by 255 on the line before this
	// one, which is exactly the range of the field being filled.
	return uint8(octets), nil
}

// spansAny reports whether the interval (owner, next] in hash order contains
// any of the given hashes, with the usual wrap at the end of the chain.
func spansAny(owner, next string, hashes []string) bool {
	for _, h := range hashes {
		switch {
		case owner < next:
			if h > owner && h < next {
				return true
			}
		case owner > next:
			if h > owner || h < next {
				return true
			}
		default:
			if h != owner {
				return true
			}
		}
	}
	return false
}

// nsec3Names lists the names this zone publishes an NSEC3 for, and the names
// opt-out leaves out.
//
// Empty non-terminals are included, which is the substantive difference from
// the NSEC chain: RFC 5155 §7.1 requires a record for each of them, and their
// bitmaps are empty because they own nothing.
func (z *Zone) nsec3Names() (included, excluded []string) {
	names := map[string]bool{}
	for k := range z.sets {
		if k.rrtype == dns.TypeRRSIG || k.rrtype == dns.TypeNSEC || k.rrtype == dns.TypeNSEC3 {
			continue
		}
		names[k.name] = true
		// Every ancestor between this name and the apex exists, as an empty
		// non-terminal if it owns nothing.
		for n := parentOf(k.name); n != "" && dns.IsSubDomain(z.Name, n); n = parentOf(n) {
			names[n] = true
			if n == z.Name {
				break
			}
		}
	}

	for name := range names {
		// RFC 5155 §7.1: with Opt-Out in use, "owner names of unsigned
		// delegations MAY be excluded". Only unsigned ones: a delegation
		// with a DS is signed material and stays in the chain.
		if z.n3optOut && z.delegations[name] && !z.hasDS(name) {
			excluded = append(excluded, name)
			continue
		}
		included = append(included, name)
	}
	sort.Strings(included)
	sort.Strings(excluded)
	return included, excluded
}

func (z *Zone) hasDS(name string) bool {
	return len(z.sets[setKey{name: dns.CanonicalName(name), rrtype: dns.TypeDS}]) > 0
}

// typesForNSEC3 returns the types present at an original owner name.
//
// RFC 5155 §7.1: the bitmap "MUST indicate the presence of all types present
// at the original owner name, except for the types solely contributed by an
// NSEC3 RR itself. Note that this means that the NSEC3 type itself will never
// be present in the Type Bit Maps."
//
// So NSEC3 is excluded — it lives at the hashed name, not the original — and
// RRSIG is included wherever the zone actually signed something there. An
// empty non-terminal gets an empty bitmap, and a delegation with no DS gets
// only NS, because the parent signs nothing at that name.
func (z *Zone) typesForNSEC3(name string) []uint16 {
	var types []uint16
	seen := map[uint16]bool{}
	signed := false

	for k, records := range z.sets {
		if k.name != name || k.rrtype == dns.TypeNSEC3 || k.rrtype == dns.TypeNSEC {
			continue
		}
		if !seen[k.rrtype] {
			seen[k.rrtype] = true
			types = append(types, k.rrtype)
		}
		for _, rr := range records {
			if _, isSig := rr.(*dns.RRSIG); isSig {
				signed = true
			}
		}
	}
	if signed && !seen[dns.TypeRRSIG] {
		types = append(types, dns.TypeRRSIG)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

// nsec3Matching returns the NSEC3 RRset whose owner is the hash of name.
func (z *Zone) nsec3Matching(name string) []dns.RR {
	h := dns.HashName(name, z.n3alg, z.n3iter, z.n3salt)
	if h == "" {
		return nil
	}
	return z.sets[setKey{name: nsec3Owner(h, z.Name), rrtype: dns.TypeNSEC3}]
}

// nsec3Owner builds an NSEC3 owner name: the hash prepended as a single
// label to the zone name (RFC 5155 §7.1), in canonical form.
//
// The root needs its own arm. Concatenating a hash, a dot and "." produces
// "HASH..", which is not a name, and the failure surfaces as "bad rdata" from
// the packer — a message pointing at the record's contents rather than at its
// owner.
func nsec3Owner(hash, zone string) string {
	label := strings.ToLower(hash)
	if zone == "." || zone == "" {
		return label + "."
	}
	return label + "." + dns.CanonicalName(zone)
}

// nsec3Covering returns the NSEC3 RRset whose interval contains name's hash.
func (z *Zone) nsec3Covering(name string) []dns.RR {
	h := dns.HashName(name, z.n3alg, z.n3iter, z.n3salt)
	if h == "" {
		return nil
	}
	for k, records := range z.sets {
		if k.rrtype != dns.TypeNSEC3 {
			continue
		}
		for _, rr := range records {
			n, ok := rr.(*dns.NSEC3)
			if !ok {
				continue
			}
			owner := strings.ToUpper(strings.SplitN(k.name, ".", 2)[0])
			if spansAny(owner, strings.ToUpper(n.NextDomain), []string{h}) {
				return records
			}
		}
	}
	return nil
}

// nsec3DenialFor assembles the records that prove a denial in an NSEC3 zone.
//
// The shapes are RFC 5155 §7.2.2 through §7.2.7. They differ from NSEC's in
// one structural way: because a hash discards a name's ancestry, the closest
// encloser cannot be read off a single record and has to be shipped — a
// record matching it, and a record covering the name one label below it.
func (h *Hierarchy) nsec3DenialFor(zone *Zone, qname string, rcode int) []dns.RR {
	var out []dns.RR
	add := func(rr []dns.RR) {
		for _, r := range rr {
			if !containsRR(out, r) {
				out = append(out, r)
			}
		}
	}

	if rcode == dns.RcodeSuccess {
		// §7.2.3: a NODATA response carries the record matching the name,
		// which exists — including an empty non-terminal, which has one
		// under NSEC3 even though it has none under NSEC.
		if match := zone.nsec3Matching(qname); match != nil {
			add(match)
			return out
		}
	}

	// No record at the name. Either it does not exist, or opt-out left it
	// out of the chain, and either way the proof is §7.2.1's closest
	// encloser proof: the record matching the deepest provable ancestor, and
	// the record covering the name one label below it.
	encloser := zone.nsec3ClosestEncloser(qname)
	add(zone.nsec3Matching(encloser))
	if closer := nextCloserName(qname, encloser); closer != "" {
		add(zone.nsec3Covering(closer))
	}

	// §7.2.2 adds the wildcard denial for a name error; §7.2.5 replaces it
	// with a matching record when the wildcard exists and has no such type.
	if wc := zone.nsec3Matching(wildcardUnder(encloser)); wc != nil {
		add(wc)
	} else {
		add(zone.nsec3Covering(wildcardUnder(encloser)))
	}
	return out
}

// nsec3ClosestEncloser returns the deepest ancestor of qname that this zone
// publishes an NSEC3 record for.
//
// Deliberately not the same question as Zone.closestEncloser, which asks what
// exists. Under opt-out those two answers differ: a name can exist as an
// insecure delegation and have no record, and RFC 5155 §1.3 gives the
// difference a name — the closest *provable* encloser, which "is only
// different from the closest encloser in an Opt-Out zone". A server that
// shipped the existing-but-unprovable name would be sending a proof step it
// cannot support.
func (z *Zone) nsec3ClosestEncloser(qname string) string {
	name := dns.CanonicalName(qname)
	for {
		if z.nsec3Matching(name) != nil {
			return name
		}
		if name == z.Name || name == "." {
			return z.Name
		}
		name = parentOf(name)
	}
}
