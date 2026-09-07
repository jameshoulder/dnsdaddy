package lab

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// The mutations in this file take a correctly signed hierarchy and break it
// in one specific, named way.
//
// They are how the lab tests the negative cases, and the discipline is that
// each one breaks exactly one thing. A scenario that broke two would still
// produce a failure, and the test would still pass, and nobody would notice
// when one of the two checks stopped working.

// Records returns a copy of one RRset with its signatures, or nil.
func (h *Hierarchy) Set(zoneName, owner string, rrtype uint16) []dns.RR {
	z := h.Zone(zoneName)
	if z == nil {
		return nil
	}
	return append([]dns.RR{}, z.sets[setKey{name: dns.CanonicalName(owner), rrtype: rrtype}]...)
}

// Replace installs a new set of records for one (owner, type) in a zone.
func (h *Hierarchy) Replace(zoneName, owner string, rrtype uint16, records []dns.RR) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}
	k := setKey{name: dns.CanonicalName(owner), rrtype: rrtype}
	if len(records) == 0 {
		delete(z.sets, k)
	} else {
		z.sets[k] = records
	}
	h.reindex()
	return nil
}

// TamperData changes the data of a signed RRset while leaving its signature
// alone, which is what an on-path attacker rewriting an answer produces.
//
// This is the scenario the whole engine exists to catch, so it is worth being
// precise about what it does and does not change: the RRSIG is untouched and
// still verifies against the key, over the RRset the signer actually signed.
// Only the data moved.
func (h *Hierarchy) TamperData(zoneName, owner string, rrtype uint16, mutate func(dns.RR)) error {
	records := h.Set(zoneName, owner, rrtype)
	if len(records) == 0 {
		return fmt.Errorf("lab: no %s %s to tamper with", owner, dns.TypeToString[rrtype])
	}
	changed := false
	for i, rr := range records {
		if _, isSig := rr.(*dns.RRSIG); isSig {
			continue
		}
		c := dns.Copy(rr)
		mutate(c)
		records[i] = c
		changed = true
	}
	if !changed {
		return fmt.Errorf("lab: %s %s had no data records", owner, dns.TypeToString[rrtype])
	}
	return h.Replace(zoneName, owner, rrtype, records)
}

// CorruptSignature flips one bit in the signature octets, leaving everything
// else — algorithm, key tag, validity, signer — intact and admissible.
//
// One bit rather than a wholesale replacement, deliberately. A signature
// replaced by random bytes could fail a length check or a format check and
// never reach the cryptography, which would test the wrong thing. Flipping a
// bit in the middle produces a well-formed signature of the right length for
// the right algorithm that simply does not verify, so the failure has to come
// from the arithmetic.
func (h *Hierarchy) CorruptSignature(zoneName, owner string, rrtype uint16) error {
	return h.mapSignatures(zoneName, owner, rrtype, func(sig *dns.RRSIG) error {
		raw, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil || len(raw) == 0 {
			return fmt.Errorf("lab: signature on %s %s is not decodable", owner, dns.TypeToString[rrtype])
		}
		raw[len(raw)/2] ^= 0x01
		sig.Signature = base64.StdEncoding.EncodeToString(raw)
		return nil
	})
}

// MalformSignature empties the signature field, exercising the parsing path
// rather than the cryptographic one.
//
// An empty signature rather than a string of non-base64 rubbish, and the
// difference matters for a reason that only showed up against a real
// reference validator. Presentation text that is not base64 cannot be packed
// into a DNS message at all, so the lab's authoritative server could not
// answer, the oracle retried until it gave up, and the scenario compared
// Daddybound's verdict against a seventeen-second timeout. A scenario that
// cannot be put on the wire cannot be compared against anything that speaks
// DNS.
//
// An RRSIG with a zero-length signature field packs and parses cleanly, is
// exactly as inadmissible, and both validators can see it.
func (h *Hierarchy) MalformSignature(zoneName, owner string, rrtype uint16) error {
	return h.mapSignatures(zoneName, owner, rrtype, func(sig *dns.RRSIG) error {
		sig.Signature = ""
		return nil
	})
}

// SetSignatureAlgorithm relabels the algorithm on an RRset's signatures
// without touching the zone's keys, which is what an attacker who has
// stripped a valid signature and substituted their own can produce.
//
// The signature bytes become meaningless, which is faithful: an attacker
// cannot make a valid one either. What matters is the algorithm field, and
// whether a validator lets an unusable signature speak for the absence of a
// usable one.
func (h *Hierarchy) SetSignatureAlgorithm(zoneName, owner string, rrtype uint16, alg dnssec.Algorithm) error {
	return h.mapSignatures(zoneName, owner, rrtype, func(sig *dns.RRSIG) error {
		sig.Algorithm = uint8(alg)
		return nil
	})
}

// AddSignature appends another RRSIG over an RRset, derived from the
// existing one and then mutated.
//
// Real zones carry several signatures over one RRset routinely — during a key
// rollover, and permanently when a zone is signed with more than one
// algorithm — so a validator must handle a mixture of good and unusable ones.
// RFC 6840 §5.4 is explicit that any one valid signature suffices.
func (h *Hierarchy) AddSignature(zoneName, owner string, rrtype uint16, mutate func(*dns.RRSIG)) error {
	records := h.Set(zoneName, owner, rrtype)
	if len(records) == 0 {
		return fmt.Errorf("lab: no %s %s in %s", owner, dns.TypeToString[rrtype], zoneName)
	}
	var template *dns.RRSIG
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			template = sig
			break
		}
	}
	if template == nil {
		return fmt.Errorf("lab: %s %s carries no signature to derive from", owner, dns.TypeToString[rrtype])
	}

	extra := dns.Copy(template).(*dns.RRSIG)
	mutate(extra)
	return h.Replace(zoneName, owner, rrtype, append(records, extra))
}

// DropOriginalSignature removes the zone's own valid signature from an
// RRset, keeping any that were added afterwards.
//
// The valid one is identified by being first: addSigned writes the data
// records then the signature, and AddSignature appends after that.
func (h *Hierarchy) DropOriginalSignature(zoneName, owner string, rrtype uint16) error {
	records := h.Set(zoneName, owner, rrtype)
	kept := make([]dns.RR, 0, len(records))
	dropped := false
	for _, rr := range records {
		if _, isSig := rr.(*dns.RRSIG); isSig && !dropped {
			dropped = true
			continue
		}
		kept = append(kept, rr)
	}
	if !dropped {
		return fmt.Errorf("lab: %s %s had no signature to drop", owner, dns.TypeToString[rrtype])
	}
	return h.Replace(zoneName, owner, rrtype, kept)
}

// PermuteRRset reorders the data records of an RRset, leaving the signatures
// where they are.
//
// A DNS response may carry an RRset's members in any order, and an on-path
// attacker can reorder them without touching a byte of signed data. If that
// changes a verdict, the attacker chooses the verdict.
func (h *Hierarchy) PermuteRRset(zoneName, owner string, rrtype uint16, perm []int) error {
	records := h.Set(zoneName, owner, rrtype)
	var data, sigs []dns.RR
	for _, rr := range records {
		if _, isSig := rr.(*dns.RRSIG); isSig {
			sigs = append(sigs, rr)
			continue
		}
		data = append(data, rr)
	}
	if len(perm) != len(data) {
		return fmt.Errorf("lab: permutation of %d does not fit %d records", len(perm), len(data))
	}

	reordered := make([]dns.RR, 0, len(records))
	for _, i := range perm {
		if i < 0 || i >= len(data) {
			return fmt.Errorf("lab: permutation index %d out of range", i)
		}
		reordered = append(reordered, data[i])
	}
	return h.Replace(zoneName, owner, rrtype, append(reordered, sigs...))
}

// ShiftValidity moves a signature's inception and expiration by a number of
// seconds, so a test can place an answer outside its window without moving
// the clock — which keeps the clock available for asserting the inclusive
// boundaries separately.
func (h *Hierarchy) ShiftValidity(zoneName, owner string, rrtype uint16, seconds int64) error {
	return h.mapSignatures(zoneName, owner, rrtype, func(sig *dns.RRSIG) error {
		sig.Inception = uint32(int64(sig.Inception) + seconds)
		sig.Expiration = uint32(int64(sig.Expiration) + seconds)
		return nil
	})
}

// RemoveSignatures strips the RRSIGs from an RRset, leaving the data.
func (h *Hierarchy) RemoveSignatures(zoneName, owner string, rrtype uint16) error {
	records := h.Set(zoneName, owner, rrtype)
	kept := records[:0]
	for _, rr := range records {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			kept = append(kept, rr)
		}
	}
	return h.Replace(zoneName, owner, rrtype, kept)
}

// RemoveDNSKEYs deletes a zone's apex DNSKEY RRset entirely, so that a
// delegation points at a zone with no keys.
func (h *Hierarchy) RemoveDNSKEYs(zoneName string) error {
	return h.Replace(zoneName, zoneName, dns.TypeDNSKEY, nil)
}

// CorruptDS flips a bit in the digest of the DS the parent publishes,
// leaving the key tag and algorithm matching. This is the shape of a
// substituted key: the parent's delegation refers to exactly this key and
// disagrees about what it contains.
func (h *Hierarchy) CorruptDS(childZone string) error {
	return h.mapDS(childZone, func(ds *dns.DS) error {
		raw, err := hex.DecodeString(ds.Digest)
		if err != nil || len(raw) == 0 {
			return fmt.Errorf("lab: DS digest for %s is not hex", childZone)
		}
		raw[0] ^= 0x01
		ds.Digest = hex.EncodeToString(raw)
		return nil
	})
}

// SetDSDigestType relabels the DS as using a different digest algorithm,
// without recomputing the digest. Used to reach the unsupported and
// disallowed digest paths, which are checked before the digest is compared.
func (h *Hierarchy) SetDSDigestType(childZone string, dt dnssec.DigestType) error {
	return h.mapDS(childZone, func(ds *dns.DS) error {
		ds.DigestType = uint8(dt)
		return nil
	})
}

// SetDSRRset replaces the DS RRset a parent publishes for a child, and
// re-signs it so the change is about the DS records themselves rather than
// about a broken parent signature.
//
// Used to build mixed DS RRsets — usable and unusable digest types side by
// side — which is where ordering dependence hides.
func (h *Hierarchy) SetDSRRset(childZone string, dsRecords []*dns.DS) error {
	parent := h.parentOf(childZone)
	if parent == nil {
		return fmt.Errorf("lab: %s has no parent zone", childZone)
	}
	rrs := make([]dns.RR, 0, len(dsRecords))
	for _, ds := range dsRecords {
		rrs = append(rrs, ds)
	}
	if err := h.Replace(parent.Name, childZone, dns.TypeDS, rrs); err != nil {
		return err
	}
	return h.resignInParent(childZone, dns.TypeDS)
}

// DSFor builds a DS record for a child zone's key with a chosen digest type,
// optionally corrupting the digest.
//
// When the digest type is one this build cannot compute, the digest is filled
// with fixed bytes: the point of such a record is that a validator must not
// be able to evaluate it, so what it contains is immaterial — and generating
// it from the key would need the very algorithm that is missing.
func (h *Hierarchy) DSFor(childZone string, dt dnssec.DigestType, corrupt bool) (*dns.DS, error) {
	z := h.Zone(childZone)
	if z == nil {
		return nil, fmt.Errorf("lab: no zone %s", childZone)
	}

	ds := z.Key.ToDS(uint8(dt))
	if ds == nil {
		ds = &dns.DS{
			KeyTag:    z.Key.KeyTag(),
			Algorithm: z.Key.Algorithm,
			Digest:    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		}
	}
	ds.Hdr = dns.RR_Header{Name: z.Name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	ds.DigestType = uint8(dt)

	if corrupt {
		raw, err := hex.DecodeString(ds.Digest)
		if err != nil || len(raw) == 0 {
			return nil, fmt.Errorf("lab: DS digest for %s is not hex", childZone)
		}
		raw[0] ^= 0x01
		ds.Digest = hex.EncodeToString(raw)
	}
	return ds, nil
}

// AppendRogueKey adds an unauthenticated key to a zone's apex DNSKEY RRset
// without re-signing the RRset, and signs the answer with it.
//
// This is the attack the apex DNSKEY signature check exists to stop. The
// rogue key is a perfectly good zone key: right flags, right protocol,
// supported algorithm, and it genuinely produced the signature on the
// answer. What it is not is a key the zone vouched for — no DS refers to it,
// and the DNSKEY RRset's own signature was made before it was added, so it no
// longer covers the set.
//
// A validator that trusts every key in an apex RRset because one of them
// matched a DS accepts this. That is a false Secure, and it is the exact
// failure class this project treats as P0.
func (h *Hierarchy) AppendRogueKey(zoneName, owner string, rrtype uint16) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}

	rogueSigner, err := deriveKey(z.Algorithm, h.spec.Seed+"|rogue|"+z.Name)
	if err != nil {
		return err
	}
	rogue := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: z.Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600,
		},
		Flags: 257, Protocol: 3, Algorithm: uint8(z.Algorithm),
	}
	if err := setPublicKey(rogue, rogueSigner); err != nil {
		return err
	}

	// Added to the apex RRset, with the original signature left in place so
	// that it no longer covers what it claims to.
	keys := h.Set(zoneName, zoneName, dns.TypeDNSKEY)
	if len(keys) == 0 {
		return fmt.Errorf("lab: %s has no DNSKEY RRset", zoneName)
	}
	if err := h.Replace(zoneName, zoneName, dns.TypeDNSKEY, append(keys, rogue)); err != nil {
		return err
	}

	// And the answer is signed by the rogue key alone.
	data := h.Set(zoneName, owner, rrtype)
	kept := make([]dns.RR, 0, len(data))
	for _, rr := range data {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			kept = append(kept, rr)
		}
	}
	if len(kept) == 0 {
		return fmt.Errorf("lab: no %s %s to re-sign", owner, dns.TypeToString[rrtype])
	}

	rogueZone := &Zone{
		Name: z.Name, Key: rogue, Signer: rogueSigner,
		Algorithm: z.Algorithm, DigestType: z.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := rogueZone.addSigned(h.spec, kept); err != nil {
		return err
	}
	return h.Replace(zoneName, owner, rrtype, rogueZone.sets[setKey{name: dns.CanonicalName(owner), rrtype: rrtype}])
}

// SignWithForeignZone re-signs an RRset with a different zone's key, so the
// signature is cryptographically sound and made by the wrong authority.
//
// The signer's name then names a zone that does not contain the RRset, which
// R-SIG-02 forbids. Without that rule, any zone able to get its key into a
// chain could sign any other zone's data.
func (h *Hierarchy) SignWithForeignZone(zoneName, owner string, rrtype uint16, foreignZone string) error {
	foreign := h.Zone(foreignZone)
	if foreign == nil {
		return fmt.Errorf("lab: no zone %s", foreignZone)
	}
	data := h.Set(zoneName, owner, rrtype)
	kept := make([]dns.RR, 0, len(data))
	for _, rr := range data {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			kept = append(kept, rr)
		}
	}
	if len(kept) == 0 {
		return fmt.Errorf("lab: no %s %s to re-sign", owner, dns.TypeToString[rrtype])
	}

	scratch := &Zone{
		Name: foreign.Name, Key: foreign.Key, Signer: foreign.Signer,
		Algorithm: foreign.Algorithm, DigestType: foreign.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := scratch.addSigned(h.spec, kept); err != nil {
		return err
	}
	return h.Replace(zoneName, owner, rrtype, scratch.sets[setKey{name: dns.CanonicalName(owner), rrtype: rrtype}])
}

// RelabelAlgorithm rewrites a zone's key, its parent's DS and all of its
// signatures to claim a different algorithm number, keeping the actual key
// material and signatures as they are.
//
// The result is a zone that is internally consistent — the DS matches the key
// by tag, algorithm and digest, and the signatures name the key correctly —
// and that claims an algorithm the validator has no verifier for. That is
// exactly what a validator encountering a genuinely unsupported algorithm
// sees: it cannot tell whether the signatures are good, only that it cannot
// check them.
func (h *Hierarchy) RelabelAlgorithm(zoneName string, alg dnssec.Algorithm) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}

	keys := h.Set(zoneName, zoneName, dns.TypeDNSKEY)
	var relabelled *dns.DNSKEY
	updated := make([]dns.RR, 0, len(keys))
	for _, rr := range keys {
		switch x := dns.Copy(rr).(type) {
		case *dns.DNSKEY:
			x.Algorithm = uint8(alg)
			relabelled = x
			updated = append(updated, x)
		case *dns.RRSIG:
			x.Algorithm = uint8(alg)
			updated = append(updated, x)
		default:
			updated = append(updated, rr)
		}
	}
	if relabelled == nil {
		return fmt.Errorf("lab: %s has no DNSKEY to relabel", zoneName)
	}

	// The key tag is a checksum over the RDATA, and the algorithm is part of
	// the RDATA, so relabelling changes it. Every reference to the old tag
	// has to move with it or the zone stops being internally consistent and
	// the scenario would test key selection instead of algorithm support.
	newTag := relabelled.KeyTag()
	for _, rr := range updated {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sig.KeyTag = newTag
		}
	}
	if err := h.Replace(zoneName, zoneName, dns.TypeDNSKEY, updated); err != nil {
		return err
	}
	z.Key = relabelled
	z.Algorithm = alg

	// Every other RRset in the zone carries signatures naming the old
	// algorithm and tag.
	for k := range z.sets {
		if k.rrtype == dns.TypeDNSKEY && k.name == z.Name {
			continue
		}
		if err := h.mapSignatures(zoneName, k.name, k.rrtype, func(sig *dns.RRSIG) error {
			sig.Algorithm = uint8(alg)
			sig.KeyTag = newTag
			return nil
		}); err != nil {
			return err
		}
	}

	// And the parent's DS refers to the key by tag and algorithm, and by a
	// digest computed over RDATA that has now changed.
	if z.DS != nil {
		ds, err := makeDS(z)
		if err != nil {
			return err
		}
		if err := h.mapDS(zoneName, func(existing *dns.DS) error {
			existing.KeyTag = ds.KeyTag
			existing.Algorithm = ds.Algorithm
			existing.Digest = ds.Digest
			return nil
		}); err != nil {
			return err
		}
		z.DS = ds
		// The DS lives in the parent and is signed by the parent, whose
		// algorithm has not changed, so the parent must re-sign it.
		if err := h.resignInParent(zoneName, dns.TypeDS); err != nil {
			return err
		}
	}
	return nil
}

// mapSignatures applies f to every RRSIG covering one RRset.
func (h *Hierarchy) mapSignatures(zoneName, owner string, rrtype uint16, f func(*dns.RRSIG) error) error {
	records := h.Set(zoneName, owner, rrtype)
	if len(records) == 0 {
		return fmt.Errorf("lab: no %s %s in %s", owner, dns.TypeToString[rrtype], zoneName)
	}
	found := false
	for i, rr := range records {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		c := dns.Copy(sig).(*dns.RRSIG)
		if err := f(c); err != nil {
			return err
		}
		records[i] = c
		found = true
	}
	if !found {
		return fmt.Errorf("lab: %s %s carries no signature", owner, dns.TypeToString[rrtype])
	}
	return h.Replace(zoneName, owner, rrtype, records)
}

// mapDS applies f to the DS records a parent publishes for a child.
func (h *Hierarchy) mapDS(childZone string, f func(*dns.DS) error) error {
	parent := h.parentOf(childZone)
	if parent == nil {
		return fmt.Errorf("lab: %s has no parent zone in this hierarchy", childZone)
	}
	records := h.Set(parent.Name, childZone, dns.TypeDS)
	if len(records) == 0 {
		return fmt.Errorf("lab: %s publishes no DS for %s", parent.Name, childZone)
	}
	for i, rr := range records {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		c := dns.Copy(ds).(*dns.DS)
		if err := f(c); err != nil {
			return err
		}
		records[i] = c
	}
	if err := h.Replace(parent.Name, childZone, dns.TypeDS, records); err != nil {
		return err
	}
	// The DS RRset is data in the parent zone, so changing it invalidates
	// the parent's signature over it. Re-signing keeps the scenario about
	// the one thing it is meant to be about.
	return h.resignInParent(childZone, dns.TypeDS)
}

// resignInParent re-signs an RRset that lives in a child's parent zone.
func (h *Hierarchy) resignInParent(childZone string, rrtype uint16) error {
	parent := h.parentOf(childZone)
	if parent == nil {
		return fmt.Errorf("lab: %s has no parent zone", childZone)
	}
	records := h.Set(parent.Name, childZone, rrtype)
	kept := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if _, isSig := rr.(*dns.RRSIG); !isSig {
			kept = append(kept, rr)
		}
	}
	if len(kept) == 0 {
		return fmt.Errorf("lab: nothing to re-sign for %s %s", childZone, dns.TypeToString[rrtype])
	}
	scratch := &Zone{
		Name: parent.Name, Key: parent.Key, Signer: parent.Signer,
		Algorithm: parent.Algorithm, DigestType: parent.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := scratch.addSigned(h.spec, kept); err != nil {
		return err
	}
	return h.Replace(parent.Name, childZone, rrtype, scratch.sets[setKey{name: dns.CanonicalName(childZone), rrtype: rrtype}])
}

// parentOf returns the zone directly above name in this hierarchy.
func (h *Hierarchy) parentOf(name string) *Zone {
	name = dns.CanonicalName(name)
	for i, z := range h.Zones {
		if z.Name == name && i > 0 {
			return h.Zones[i-1]
		}
	}
	return nil
}
