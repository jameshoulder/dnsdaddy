package dnssec

import (
	"encoding/hex"

	"github.com/miekg/dns"
)

// Turning received NSEC3 records into a set that can be reasoned with.
//
// Three filters run before anything is concluded, and each one is a MUST in
// RFC 5155 §8:
//
//   - §8.1, unknown hash algorithms are ignored;
//   - §8.2, records whose Flags field is neither 0 nor 1 are ignored;
//   - and this validator's own iteration ceiling, which is a refusal to spend
//     attacker-chosen CPU rather than a statement about the data.
//
// What survives is then reduced to a single parameter set, because a proof
// assembled from records hashed with different salts is not a proof of
// anything: their intervals are in different spaces.

// collectNSEC3 authenticates the NSEC3 records in an authority section and
// reduces them to one usable parameter set.
//
// The second return value says that a record was set aside because of *this
// validator's* limits — the iteration ceiling — and not for any reason the
// standard imposes on every validator.
//
// That distinction decides a verdict, and getting it wrong in the direction
// this code originally had it was a real bug, caught by both reference
// oracles at once. RFC 5155 §8.1 requires ignoring records with unknown hash
// types and states the consequence itself: "The practical result of this is
// that responses containing only such NSEC3 RRs will generally be considered
// bogus." Ignoring a record the standard says to ignore is not a limitation
// of Daddybound, so a response left unproved by it has failed to prove its
// claim. Only the iteration ceiling is Daddybound's own choice, and only that
// may reach Indeterminate.
func (w *walk) collectNSEC3(zone *zoneState, authority []dns.RR, budget int) (set *nsec3Set, refused, truncated bool) {
	var candidates []authenticNSEC3
	refusedForBudget := false

	for _, group := range groupByOwner(authority, dns.TypeNSEC3) {
		if budget <= 0 {
			truncated = true
			break
		}
		budget--
		set, reason := NewRRset(group.data)
		if reason != ReasonNone {
			w.rec.skip(ValidationStep{
				Kind: StepDenial, Zone: zone.name, Name: group.owner, RRType: dns.TypeNSEC3,
			}, reason)
			continue
		}
		if reason := w.authenticate(set, group.sigs, zone.name, zone.keys); reason != ReasonNone {
			w.rec.skip(ValidationStep{
				Kind: StepDenial, Zone: zone.name, Name: group.owner, RRType: dns.TypeNSEC3,
				Note: "not authenticated by this zone's keys, so it proves nothing",
			}, reason)
			continue
		}

		for _, rr := range group.data {
			n, ok := rr.(*dns.NSEC3)
			if !ok {
				continue
			}
			if reason := w.nsec3Usable(zone.name, n); reason != ReasonNone {
				if reason == ReasonResourceLimit {
					refusedForBudget = true
				}
				continue
			}
			hash, owner, ok := nsec3OwnerHash(n.Hdr.Name)
			if !ok {
				w.rec.skip(ValidationStep{
					Kind: StepDenial, Zone: zone.name, Name: n.Hdr.Name, RRType: dns.TypeNSEC3,
					Note: "the owner name is not a hash prepended to a zone name",
				}, ReasonMalformedRecord)
				continue
			}
			// RFC 5155 §7.1: the owner is "the hash of the original owner
			// name, prepended as a single label to the zone name". A record
			// whose remaining labels name a different zone is a record about
			// a different zone, however well its hash matches.
			if owner != zone.name {
				w.rec.skip(ValidationStep{
					Kind: StepDenial, Zone: zone.name, Name: n.Hdr.Name, RRType: dns.TypeNSEC3,
					Note: "the owner name places this record in a different zone",
				}, ReasonDenialWrongZone)
				continue
			}
			candidates = append(candidates, authenticNSEC3{
				rr: n, signer: zone.name, hash: hash, zone: owner,
			})
		}
		w.rec.ok(ValidationStep{
			Kind: StepDenial, Zone: zone.name, Name: group.owner, RRType: dns.TypeNSEC3,
		})
	}

	if len(candidates) == 0 {
		return nil, refusedForBudget, truncated
	}

	chosen := chooseNSEC3Parameters(candidates)
	kept := make([]authenticNSEC3, 0, len(candidates))
	for _, c := range candidates {
		if sameNSEC3Parameters(c.rr, chosen) {
			kept = append(kept, c)
			continue
		}
		w.rec.skip(ValidationStep{
			Kind: StepDenial, Zone: zone.name, Name: c.rr.Hdr.Name, RRType: dns.TypeNSEC3,
			Note: "different hash parameters from the set this proof is being read in",
		}, ReasonDenialIncomplete)
	}

	// Merged only after the parameter filter. Two records can share a hashed
	// owner label while having been hashed with different salts, and
	// combining those would produce a record describing a name that exists
	// in neither chain.
	kept = mergeNSEC3ByHash(kept)

	salt, err := hexSalt(chosen.Salt)
	if err != nil {
		// A salt that is not hexadecimal cannot have been produced by any
		// signer, so this is malformed data rather than a Daddybound limit.
		w.rec.skip(ValidationStep{
			Kind: StepDenial, Zone: zone.name, RRType: dns.TypeNSEC3,
			Note: "the NSEC3 salt is not hexadecimal",
		}, ReasonMalformedRecord)
		return nil, false, truncated
	}
	return &nsec3Set{
		records: kept,
		zone:    zone.name,
		alg:     chosen.Hash,
		iter:    chosen.Iterations,
		salt:    salt,
		// The walk's budget, not a fresh one. See walk.hashes.
		budget: w.hashes,
	}, refusedForBudget, truncated
}

// nsec3Usable applies the two RFC 5155 §8 filters and this validator's
// iteration ceiling, recording why a record was set aside.
func (w *walk) nsec3Usable(zone string, n *dns.NSEC3) Reason {
	step := ValidationStep{Kind: StepDenial, Zone: zone, Name: n.Hdr.Name, RRType: dns.TypeNSEC3}

	// R-N3-01, RFC 5155 §8.1: "A validator MUST ignore NSEC3 RRs with unknown
	// hash types." SHA-1 is the only value IANA has assigned.
	if n.Hash != NSEC3HashSHA1 {
		step.Note = "unassigned NSEC3 hash algorithm"
		return w.rec.skip(step, ReasonUnsupportedDigest)
	}

	// R-N3-02, RFC 5155 §8.2: "A validator MUST ignore NSEC3 RRs with a Flag
	// fields value other than zero or one." Bit 0 is Opt-Out; the rest are
	// reserved, and a record setting one is asking to be interpreted under
	// rules that do not exist.
	if n.Flags != 0 && n.Flags != 1 {
		step.Note = "reserved NSEC3 flag bits are set"
		return w.rec.skip(step, ReasonMalformedRecord)
	}

	// R-N3-11. The iteration count is a loop the response chooses the length
	// of, and each turn is a hash this validator performs. RFC 9276 §3.1 says
	// a zone "MUST" publish 0; Appendix A reports 100 as the point beyond
	// which treating a zone as insecure stops being interoperable.
	//
	// Refusing is deliberate, and it is the opposite of the other permission
	// RFC 9276 §3.2 grants. Reporting an expensive proof as Insecure would
	// let an attacker downgrade a signed zone by publishing an expensive
	// NSEC3, so the outcome here is Indeterminate: a statement about this
	// validator's budget, never about the zone.
	if int(n.Iterations) > w.v.cfg.Limits.MaxNSEC3Iterations {
		step.Note = "iteration count above the configured ceiling; refused rather than computed"
		return w.rec.skip(step, ReasonResourceLimit)
	}
	return ReasonNone
}

// chooseNSEC3Parameters picks the parameter set a proof will be read in.
//
// A response may legitimately carry two chains at once — a zone changing its
// salt or hash algorithm publishes both — and may hostilely carry a chain an
// attacker added. The choice can only affect availability, never
// authenticity: every record here is already signed by the zone, and an
// attacker cannot produce one. So the rule optimises for the thing they could
// otherwise control, which is cost: fewest iterations first, then the
// shortest salt, then the smallest, so the outcome is a function of the set
// and not of the order it arrived in.
func chooseNSEC3Parameters(candidates []authenticNSEC3) *dns.NSEC3 {
	best := candidates[0].rr
	for _, c := range candidates[1:] {
		if cheaperNSEC3(c.rr, best) {
			best = c.rr
		}
	}
	return best
}

func cheaperNSEC3(a, b *dns.NSEC3) bool {
	if a.Iterations != b.Iterations {
		return a.Iterations < b.Iterations
	}
	if len(a.Salt) != len(b.Salt) {
		return len(a.Salt) < len(b.Salt)
	}
	if a.Salt != b.Salt {
		return a.Salt < b.Salt
	}
	return a.Hash < b.Hash
}

func sameNSEC3Parameters(a, b *dns.NSEC3) bool {
	return a.Hash == b.Hash && a.Iterations == b.Iterations && a.Salt == b.Salt
}

// hexSalt decodes the salt from its presentation form.
//
// github.com/miekg/dns carries the salt as hexadecimal text, with "-" meaning
// the empty salt, which is what RFC 9276 §3.1 recommends every zone use.
func hexSalt(salt string) ([]byte, error) {
	if salt == "" || salt == "-" {
		return nil, nil
	}
	return hex.DecodeString(salt)
}
