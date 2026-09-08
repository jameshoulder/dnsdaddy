package lab

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

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

// CorruptSignatureAt corrupts the nth signature over an RRset, leaving any
// others intact.
//
// Needed to build the rollover shape: several signatures over one RRset where
// some are broken and at least one is good.
func (h *Hierarchy) CorruptSignatureAt(zoneName, owner string, rrtype uint16, n int) error {
	records := h.Set(zoneName, owner, rrtype)
	seen := 0
	corrupted := false
	for i, rr := range records {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if seen != n {
			seen++
			continue
		}
		c := dns.Copy(sig).(*dns.RRSIG)
		raw, err := base64.StdEncoding.DecodeString(c.Signature)
		if err != nil || len(raw) == 0 {
			return fmt.Errorf("lab: signature %d on %s %s is not decodable", n, owner, dns.TypeToString[rrtype])
		}
		raw[len(raw)/2] ^= 0x01
		c.Signature = base64.StdEncoding.EncodeToString(raw)
		records[i] = c
		corrupted = true
		break
	}
	if !corrupted {
		return fmt.Errorf("lab: %s %s has no signature %d", owner, dns.TypeToString[rrtype], n)
	}
	return h.Replace(zoneName, owner, rrtype, records)
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
		// No signature to copy — which is the interesting case, because an
		// RRset stripped of its signature and given an unusable one instead
		// is exactly the downgrade attack. The template is synthesised from
		// the zone rather than refused, so that scenario can be built.
		z := h.Zone(zoneName)
		if z == nil {
			return fmt.Errorf("lab: no zone %s", zoneName)
		}
		hdr := records[0].Header()
		template = &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name: dns.CanonicalName(hdr.Name), Rrtype: dns.TypeRRSIG,
				Class: hdr.Class, Ttl: hdr.Ttl,
			},
			TypeCovered: rrtype,
			Algorithm:   uint8(z.Algorithm),
			Labels:      uint8(dns.CountLabel(hdr.Name)), // #nosec G115 -- bounded by maxDNSLabels; see addSigned
			OrigTtl:     hdr.Ttl,
			Inception:   dnssec.DNSSECTime(h.spec.Inception),
			Expiration:  dnssec.DNSSECTime(h.spec.Expiration),
			KeyTag:      z.Key.KeyTag(),
			SignerName:  z.Name,
			// Well-formed base64 of the right length for the zone's
			// algorithm, and not a valid signature. An attacker's would not
			// be either.
			Signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		}
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
		// Shifted in the 32-bit space the fields live in, wrapping as
		// RFC 4034 §3.1.5 specifies, rather than in int64 and truncated
		// afterwards. A shift that crosses the 2106 rollover is a legal
		// signature and one worth being able to construct.
		sig.Inception = shiftSerial(sig.Inception, seconds)
		sig.Expiration = shiftSerial(sig.Expiration, seconds)
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

// parentOf returns the zone that delegates name.
//
// Read from the recorded delegations rather than from position in the zone
// list. The list is not a chain: two zones may be delegated from the same
// parent, which is exactly the shape needed to have one secure delegation and
// one insecure one in the same hierarchy. Taking "the zone before this one"
// as the parent worked only while every hierarchy was a straight line, and
// returned a sibling as soon as one was not.
func (h *Hierarchy) parentOf(name string) *Zone {
	name = dns.CanonicalName(name)
	for _, z := range h.Zones {
		if z.delegations[name] {
			return z
		}
	}
	return nil
}

// shiftSerial moves a 32-bit DNSSEC timestamp by a number of seconds,
// wrapping in the field's own arithmetic.
//
// The addition is done in uint32 so that the wrap is the specified behaviour
// rather than a truncation applied to a wider result. A negative shift is
// added as its two's-complement counterpart, which is the same operation
// modulo 2^32.
func shiftSerial(base uint32, seconds int64) uint32 {
	// #nosec G115 -- deliberate modular arithmetic on a 32-bit protocol
	// field. RFC 4034 §3.1.5 defines RRSIG inception and expiration as a
	// wrapping 32-bit seconds count compared with RFC 1982 serial
	// arithmetic, so a shift that crosses the 2106 rollover produces a legal
	// signature rather than a corrupt one. Reducing modulo 2^32 first keeps
	// the addition inside the field's own arithmetic.
	return base + uint32(seconds%(1<<32))
}

// RemoveNSEC deletes one NSEC RRset and its signature from a zone.
//
// This is how a proof is made incomplete without being made invalid:
// everything still present verifies, and what is missing is the part that
// would have completed the argument. Removing the wildcard denial from an
// NXDOMAIN is the canonical case, and a validator that stops after the first
// covering record accepts it.
func (h *Hierarchy) RemoveNSEC(zoneName, owner string) error {
	if h.Set(zoneName, owner, dns.TypeNSEC) == nil {
		return fmt.Errorf("lab: no NSEC at %s in %s to remove", owner, zoneName)
	}
	return h.Replace(zoneName, owner, dns.TypeNSEC, nil)
}

// SetNSECBitmap rewrites the type bitmap of one NSEC and re-signs it.
//
// Re-signing matters: the point of these scenarios is a *validly signed*
// record that says the wrong thing, because a record with a broken signature
// is caught by machinery that already exists and proves nothing about the
// denial logic.
func (h *Hierarchy) SetNSECBitmap(zoneName, owner string, types []uint16) error {
	return h.mutateNSEC(zoneName, owner, func(n *dns.NSEC) { n.TypeBitMap = types })
}

// SetNSECNext rewrites the Next Domain Name of one NSEC and re-signs it.
func (h *Hierarchy) SetNSECNext(zoneName, owner, next string) error {
	return h.mutateNSEC(zoneName, owner, func(n *dns.NSEC) { n.NextDomain = dns.CanonicalName(next) })
}

// mutateNSEC applies a change to an NSEC record and re-signs it with the
// zone's own key, so the result is a genuine statement by that zone.
func (h *Hierarchy) mutateNSEC(zoneName, owner string, apply func(*dns.NSEC)) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}
	records := h.Set(zoneName, owner, dns.TypeNSEC)
	if len(records) == 0 {
		return fmt.Errorf("lab: no NSEC at %s in %s", owner, zoneName)
	}

	kept := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		nsec, ok := rr.(*dns.NSEC)
		if !ok {
			continue // the old signature is discarded; a new one replaces it
		}
		clone, ok := dns.Copy(nsec).(*dns.NSEC)
		if !ok {
			return fmt.Errorf("lab: copying the NSEC at %s did not produce an NSEC", owner)
		}
		apply(clone)
		kept = append(kept, clone)
	}
	if len(kept) == 0 {
		return fmt.Errorf("lab: nothing to re-sign at %s", owner)
	}

	scratch := &Zone{
		Name: z.Name, Key: z.Key, Signer: z.Signer,
		Algorithm: z.Algorithm, DigestType: z.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := scratch.addSigned(h.spec, kept); err != nil {
		return err
	}
	return h.Replace(zoneName, owner, dns.TypeNSEC,
		scratch.sets[setKey{name: dns.CanonicalName(owner), rrtype: dns.TypeNSEC}])
}

// responseOverride replaces part of the response to one specific question.
//
// The mutations above all break the zone. This one leaves the zone perfectly
// correct and breaks the *response*, which is a different attacker and a
// different class of bug. An on-path attacker cannot forge a signature, but
// they can drop records, and they can move a genuinely signed record from the
// place it belongs to a place where it appears to prove something else. Every
// record planted this way is a real record this hierarchy really signed.
type responseOverride struct {
	rcode     *int
	authority []dns.RR
	set       bool
}

// SubstituteAuthority replaces the authority section of the answer to one
// question. An empty slice strips the section entirely, which is what an
// attacker who wants a claim to go unproved does.
func (h *Hierarchy) SubstituteAuthority(qname string, rrtype uint16, records []dns.RR) {
	h.override(qname, rrtype, func(o *responseOverride) {
		o.authority = records
		o.set = true
	})
}

// ForceRcode changes the response code for one question, leaving every record
// alone.
//
// This is the cheapest attack there is — one field of a header, no
// cryptography involved — and it is how a NODATA becomes an NXDOMAIN. The
// records that arrive alongside it are genuine and verify; the question is
// whether they prove the stronger claim the attacker substituted.
func (h *Hierarchy) ForceRcode(qname string, rrtype uint16, rcode int) {
	h.override(qname, rrtype, func(o *responseOverride) { o.rcode = &rcode })
}

func (h *Hierarchy) override(qname string, rrtype uint16, apply func(*responseOverride)) {
	if h.overrides == nil {
		h.overrides = make(map[setKey]*responseOverride)
	}
	k := setKey{name: dns.CanonicalName(qname), rrtype: rrtype}
	if h.overrides[k] == nil {
		h.overrides[k] = &responseOverride{}
	}
	apply(h.overrides[k])
}

// SetNSEC3Hash relabels the hash algorithm on a zone's NSEC3 records and
// re-signs them, without changing the hashes themselves.
//
// The records stay perfectly valid signed statements by the zone; only the
// field naming how they were computed changes. That is the point: RFC 5155
// §8.1 requires a validator to ignore such records, and ignoring them has to
// mean concluding nothing rather than falling back on the response code.
func (h *Hierarchy) SetNSEC3Hash(zoneName string, alg uint8) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}
	owners := make([]string, 0, len(z.sets))
	for k := range z.sets {
		if k.rrtype == dns.TypeNSEC3 {
			owners = append(owners, k.name)
		}
	}
	if len(owners) == 0 {
		return fmt.Errorf("lab: %s publishes no NSEC3 records", zoneName)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		if err := h.mutateNSEC3(zoneName, owner, func(n *dns.NSEC3) { n.Hash = alg }); err != nil {
			return err
		}
	}
	return nil
}

// mutateNSEC3 applies a change to an NSEC3 record and re-signs it with the
// zone's own key.
func (h *Hierarchy) mutateNSEC3(zoneName, owner string, apply func(*dns.NSEC3)) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}
	records := h.Set(zoneName, owner, dns.TypeNSEC3)
	if len(records) == 0 {
		return fmt.Errorf("lab: no NSEC3 at %s in %s", owner, zoneName)
	}

	kept := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		n, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		clone, ok := dns.Copy(n).(*dns.NSEC3)
		if !ok {
			return fmt.Errorf("lab: copying the NSEC3 at %s did not produce an NSEC3", owner)
		}
		apply(clone)
		kept = append(kept, clone)
	}
	if len(kept) == 0 {
		return fmt.Errorf("lab: nothing to re-sign at %s", owner)
	}

	scratch := &Zone{
		Name: z.Name, Key: z.Key, Signer: z.Signer,
		Algorithm: z.Algorithm, DigestType: z.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := scratch.addSigned(h.spec, kept); err != nil {
		return err
	}
	return h.Replace(zoneName, owner, dns.TypeNSEC3,
		scratch.sets[setKey{name: dns.CanonicalName(owner), rrtype: dns.TypeNSEC3}])
}

// ReownNSEC3 moves one NSEC3 record to a different zone suffix, keeping its
// hashed-owner label, and re-signs it with the same zone's key.
//
// The result is a record the zone genuinely signed, whose hash label still
// matches the name it always matched, sitting at an owner name that places it
// in a different zone. RFC 5155 §7.1 says an NSEC3 owner is "the hash of the
// original owner name, prepended as a single label to the zone name", so a
// validator that compares only the label will accept a statement about a zone
// the signer has no authority over.
func (h *Hierarchy) ReownNSEC3(zoneName, owner, newSuffix string) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}
	records := h.Set(zoneName, owner, dns.TypeNSEC3)
	if len(records) == 0 {
		return fmt.Errorf("lab: no NSEC3 at %s in %s", owner, zoneName)
	}

	label := strings.SplitN(dns.CanonicalName(owner), ".", 2)[0]
	moved := label + "." + dns.CanonicalName(newSuffix)

	kept := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		n, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		clone, ok := dns.Copy(n).(*dns.NSEC3)
		if !ok {
			return fmt.Errorf("lab: copying the NSEC3 at %s did not produce an NSEC3", owner)
		}
		clone.Hdr.Name = moved
		kept = append(kept, clone)
	}
	if len(kept) == 0 {
		return fmt.Errorf("lab: nothing to move at %s", owner)
	}

	scratch := &Zone{
		Name: z.Name, Key: z.Key, Signer: z.Signer,
		Algorithm: z.Algorithm, DigestType: z.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := scratch.addSigned(h.spec, kept); err != nil {
		return err
	}
	if err := h.Replace(zoneName, owner, dns.TypeNSEC3, nil); err != nil {
		return err
	}
	return h.Replace(zoneName, moved, dns.TypeNSEC3,
		scratch.sets[setKey{name: moved, rrtype: dns.TypeNSEC3}])
}

// SetNSEC3Flags rewrites the Flags field of one NSEC3 record and re-signs it.
//
// The field carries the Opt-Out bit, which is the difference between "no
// record here means nothing" and "no record here means this is an insecure
// delegation". Clearing it on a record a proof depends on leaves the proof
// resting on an omission, which RFC 5155 §8.6 and §8.9 both refuse.
func (h *Hierarchy) SetNSEC3Flags(zoneName, owner string, flags uint8) error {
	return h.mutateNSEC3(zoneName, owner, func(n *dns.NSEC3) { n.Flags = flags })
}

// AddSecondNSEC publishes a second NSEC record at an owner name that already
// has one, and signs the pair as a single RRset.
//
// This is a broken zone rather than a forged response: RFC 4034 §4.1 describes
// one NSEC per name and RFC 5155 §7.1 step 6 tells a signer to combine records
// with identical hashed owner names into one. But nothing stops a signer
// emitting two, both are then genuinely signed, and a validator that reads
// "the" record at a name has to decide which. An attacker on the path chooses
// the order they arrive in, so if that decides the verdict, it is the
// attacker's verdict.
func (h *Hierarchy) AddSecondNSEC(zoneName, owner string, apply func(*dns.NSEC)) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}
	records := h.Set(zoneName, owner, dns.TypeNSEC)
	if len(records) == 0 {
		return fmt.Errorf("lab: no NSEC at %s in %s", owner, zoneName)
	}

	var pair []dns.RR
	for _, rr := range records {
		n, ok := rr.(*dns.NSEC)
		if !ok {
			continue
		}
		pair = append(pair, dns.Copy(n))
		second, ok := dns.Copy(n).(*dns.NSEC)
		if !ok {
			return fmt.Errorf("lab: copying the NSEC at %s did not produce an NSEC", owner)
		}
		apply(second)
		pair = append(pair, second)
		break
	}
	if len(pair) != 2 {
		return fmt.Errorf("lab: could not build a second NSEC at %s", owner)
	}

	scratch := &Zone{
		Name: z.Name, Key: z.Key, Signer: z.Signer,
		Algorithm: z.Algorithm, DigestType: z.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := scratch.addSigned(h.spec, pair); err != nil {
		return err
	}
	return h.Replace(zoneName, owner, dns.TypeNSEC,
		scratch.sets[setKey{name: dns.CanonicalName(owner), rrtype: dns.TypeNSEC}])
}

// NSEC3OwnerFor returns the NSEC3 owner name that matches a name in this zone,
// or "" if the zone publishes none there.
func (z *Zone) NSEC3OwnerFor(name string) string {
	h := dns.HashName(name, z.n3alg, z.n3iter, z.n3salt)
	if h == "" {
		return ""
	}
	owner := nsec3Owner(h, z.Name)
	if len(z.sets[setKey{name: owner, rrtype: dns.TypeNSEC3}]) == 0 {
		return ""
	}
	return owner
}

// AddSecondNSEC3 publishes a second NSEC3 at an owner that already has one and
// signs the pair as one RRset. The NSEC3 counterpart of AddSecondNSEC, and the
// case RFC 5155 §7.1 step 6 tells signers to avoid by taking the union.
func (h *Hierarchy) AddSecondNSEC3(zoneName, owner string, apply func(*dns.NSEC3)) error {
	z := h.Zone(zoneName)
	if z == nil {
		return fmt.Errorf("lab: no zone %s", zoneName)
	}
	records := h.Set(zoneName, owner, dns.TypeNSEC3)
	if len(records) == 0 {
		return fmt.Errorf("lab: no NSEC3 at %s in %s", owner, zoneName)
	}

	var pair []dns.RR
	for _, rr := range records {
		n, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		pair = append(pair, dns.Copy(n))
		second, ok := dns.Copy(n).(*dns.NSEC3)
		if !ok {
			return fmt.Errorf("lab: copying the NSEC3 at %s did not produce an NSEC3", owner)
		}
		apply(second)
		pair = append(pair, second)
		break
	}
	if len(pair) != 2 {
		return fmt.Errorf("lab: could not build a second NSEC3 at %s", owner)
	}

	scratch := &Zone{
		Name: z.Name, Key: z.Key, Signer: z.Signer,
		Algorithm: z.Algorithm, DigestType: z.DigestType,
		sets: make(map[setKey][]dns.RR),
	}
	if err := scratch.addSigned(h.spec, pair); err != nil {
		return err
	}
	return h.Replace(zoneName, owner, dns.TypeNSEC3,
		scratch.sets[setKey{name: dns.CanonicalName(owner), rrtype: dns.TypeNSEC3}])
}
