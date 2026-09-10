package trustanchors

import (
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
)

// advance applies RFC 5011 §4's state machine to a DNSKEY RRset that has
// already been authenticated against a currently trusted key.
//
// The precondition is the whole of the security. Every transition below reads
// as "the zone said so", and that sentence is only worth anything because
// Refresh established that the zone — and not somebody on the path — is what
// said it. Calling this with an unauthenticated RRset would hand the state
// machine to whoever answered.
//
// The RFC's table, with the events it names:
//
//	Start   --NewKey-->  AddPend
//	AddPend --KeyRem-->  Start      (the hold-down restarts from scratch)
//	AddPend --AddTime--> Valid
//	Valid   --KeyRem-->  Missing
//	Valid   --RevBit-->  Revoked
//	Missing --KeyPres--> Valid
//	Missing --RevBit-->  Revoked
//	Revoked --RemTime--> Removed
//
// Two of those are worth pointing at, because they are the ones an
// implementation gets wrong in the unsafe direction:
//
//   - AddPend --KeyRem--> Start discards the hold-down progress entirely. A
//     key that appears, vanishes and reappears has not been present for
//     thirty continuous days, and crediting it for the time it spent absent
//     would let an attacker with intermittent control of the answer
//     accumulate a hold-down they never actually served.
//   - Valid --KeyRem--> Missing keeps the key trusted. Absence is not
//     revocation. Only the REVOKE bit, self-signed, withdraws a key.
//
// Returns a description of each change, for the log and the status surface.
// The list is empty on the ordinary refresh where nothing has moved.
func (m *Manager) advance(
	records []dns.RR, selfRevoked map[string]bool, now time.Time, origTTL time.Duration,
) []string {
	var changes []string
	note := func(format string, args ...any) {
		changes = append(changes, fmt.Sprintf(format, args...))
	}

	// Index the arriving keys. Revoked ones are held separately: RFC 5011
	// §2.2 makes a revoked key untrusted, so it must not be matched against a
	// stored key as though it were the same live key.
	present := map[string]*dns.DNSKEY{}
	revoked := map[string]*dns.DNSKEY{}
	for _, rr := range records {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		// Only SEP keys become trust anchors. RFC 5011 §2.1 is about the keys
		// a trust point is made of, and a zone-signing key is not one — it is
		// vouched for by the key-signing key, which is what the anchor points
		// at. Managing ZSKs here would fill the state file with keys that roll
		// every few weeks and mean nothing to a validator.
		if key.Flags&dns.SEP == 0 {
			continue
		}
		if key.Flags&dns.REVOKE != 0 {
			// Only a revocation the key signed itself counts. Refresh has
			// already established which of these carry a signature made by
			// the key being withdrawn; a REVOKE bit on any other key is a
			// claim by whoever wrote the packet, and acting on it would let
			// one stolen key retire every other key at this trust point.
			//
			// A revoked key that fails that test is simply not in `present`
			// either, so it reads as absent — Valid becomes Missing, which
			// keeps it trusted and costs nothing.
			if selfRevoked[material(key)] {
				// Indexed by the material with the REVOKE bit cleared, so it
				// matches the stored, unrevoked form of the same key.
				revoked[material(key)] = key
			}
			continue
		}
		present[material(key)] = key
	}

	// Existing keys first: revocation, presence, absence, and the timers.
	for i := range m.tp.Keys {
		k := &m.tp.Keys[i]
		stored, err := k.DNSKEY()
		if err != nil {
			continue
		}
		id := material(stored)

		// RevBit. Applies from Valid, Missing and AddPend alike: a key the
		// zone is withdrawing must not be waiting out a hold-down towards
		// being trusted.
		//
		// The self-signature was established in Refresh, per key, and only
		// keys that passed it reach the `revoked` map. See selfRevokedKeys
		// for why "signed by some trusted key" is not good enough.
		if _, isRevoked := revoked[id]; isRevoked && k.State != StateRevoked && k.State != StateRemoved {
			was := k.State
			k.State = StateRevoked
			k.RevokedAt = now
			k.RemoveHoldDownUntil = now.Add(m.cfg.RemoveHoldDown)
			k.LastSeen = now
			note("key %d moved from %s to revoked; it is no longer a trust anchor", k.KeyTag, was)
			continue
		}

		if _, here := present[id]; here {
			k.LastSeen = now
			switch k.State {
			case StateMissing:
				// KeyPres.
				k.State = StateValid
				note("key %d returned to the RRset and is a trust anchor again", k.KeyTag)
			case StateAddPend:
				// AddTime, but only once the hold-down has genuinely passed.
				if !now.Before(k.AddHoldDownUntil) {
					k.State = StateValid
					note("key %d completed its %s hold-down and is now a trust anchor",
						k.KeyTag, m.cfg.AddHoldDown)
				}
			}
			continue
		}

		// KeyRem: absent from an RRset that did authenticate.
		switch k.State {
		case StateValid:
			k.State = StateMissing
			note("key %d is absent from the RRset; it remains a trust anchor while missing", k.KeyTag)
		case StateAddPend:
			// Back to Start, which for us means forgetting the key: the
			// hold-down has to be served continuously, and a fresh sighting
			// starts a fresh thirty days.
			k.State = ""
			note("key %d disappeared before its hold-down completed; its hold-down is discarded", k.KeyTag)
		case StateRevoked:
			// RemTime. The key is only forgotten once the remove hold-down
			// has passed *and* it has stopped being published, so that a
			// resolver that was offline for the revocation still sees it.
			if !now.Before(k.RemoveHoldDownUntil) {
				k.State = StateRemoved
				note("key %d passed its remove hold-down and is no longer tracked", k.KeyTag)
			}
		}
	}

	// Then keys that are new to this trust point.
	for id, key := range present {
		if m.known(id) {
			continue
		}
		// NewKey. The hold-down is thirty days or the RRset's original TTL,
		// whichever is greater — RFC 5011 §2.4.1 — because a zone publishing a
		// very long TTL has told resolvers they may not look again for that
		// long, and a hold-down shorter than that could be served by an
		// answer nobody re-fetches.
		hold := m.cfg.AddHoldDown
		if origTTL > hold {
			hold = origTTL
		}
		m.tp.Keys = append(m.tp.Keys, ManagedKey{
			Key:              key.String(),
			KeyTag:           key.KeyTag(),
			Algorithm:        key.Algorithm,
			Flags:            key.Flags,
			State:            StateAddPend,
			FirstSeen:        now,
			LastSeen:         now,
			AddHoldDownUntil: now.Add(hold),
		})
		note("key %d is new; it becomes a trust anchor after %s if it stays published",
			key.KeyTag(), hold)
	}

	m.seed(present, now, &changes)
	m.forget()
	m.tp.sortKeys()

	// The anchor set is rebuilt here rather than by the caller, because
	// viability is a question about the rebuilt set: "has everything been
	// revoked" is answered by looking at what is left, not by counting states.
	m.recompute()
	m.checkViability(&changes)
	return changes
}

// seed promotes keys that match a configured anchor straight to Valid.
//
// The bootstrap. RFC 5011 manages keys once a trust point exists, and says
// nothing about how the first one gets there; this resolver ships the digests
// IANA publishes, so a key whose digest matches one of them is a key the
// operator already trusts and there is nothing to hold down. It is the
// "initial-ds" arrangement BIND and unbound both offer, and it is why no
// DNSKEY blob is compiled into this binary — only a digest, which is the form
// IANA publishes and an operator can check by eye.
//
// It runs on every refresh rather than only the first, so that an operator who
// adds an anchor to their configuration gets it recognised at the next refresh
// instead of at the next restart.
func (m *Manager) seed(present map[string]*dns.DNSKEY, now time.Time, changes *[]string) {
	for id, key := range present {
		matched := false
		for _, a := range m.cfg.Configured.Anchors() {
			if a.MatchesKey(m.cfg.Policy, key) == dnssec.ReasonNone {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for i := range m.tp.Keys {
			k := &m.tp.Keys[i]
			stored, err := k.DNSKEY()
			if err != nil || material(stored) != id {
				continue
			}
			// A revoked key is never promoted back, however it matches a
			// configured digest. The zone has withdrawn it, and a
			// configuration file that still names it is out of date rather
			// than authoritative about the zone's current keys.
			if k.State == StateRevoked || k.State == StateRemoved {
				break
			}
			if k.State != StateValid {
				was := k.State
				k.State = StateValid
				k.Seeded = true
				k.LastSeen = now
				if was != "" {
					*changes = append(*changes, fmt.Sprintf(
						"key %d matches a configured anchor and is trusted without a hold-down", k.KeyTag))
				}
			} else {
				k.Seeded = true
			}
			break
		}
	}
}

// known reports whether the trust point already tracks this key material in a
// state that is not "forgotten".
func (m *Manager) known(id string) bool {
	for _, k := range m.tp.Keys {
		if k.State == "" {
			continue
		}
		stored, err := k.DNSKEY()
		if err != nil {
			continue
		}
		if material(stored) == id {
			return true
		}
	}
	return false
}

// forget drops the keys the machine has finished with.
//
// Only the empty state — a hold-down abandoned — is dropped. Removed keys are
// kept, deliberately and for ever: they are the record of what has been
// revoked, and forgetting one would let an attacker who can replay an old
// DNSKEY RRset reintroduce it as a NewKey and start its hold-down again.
func (m *Manager) forget() {
	kept := m.tp.Keys[:0]
	for _, k := range m.tp.Keys {
		if k.State == "" {
			continue
		}
		kept = append(kept, k)
	}
	m.tp.Keys = kept
}

// checkViability notices a trust point that can no longer be maintained.
//
// RFC 5011 §5 deletes a trust point whose anchors have all been revoked, after
// which the data below it is evaluated as though nothing were configured —
// which means Insecure. This implementation does not do that, and the
// difference is deliberate.
//
// Live mode's premise is that the answers it returns were validated. A
// resolver that silently stopped validating the root and carried on serving
// would be making a claim it could no longer support, and an operator would
// have no way to tell from the answers. So the trust point stays, marked, with
// no trusted keys — and a validator with no anchors reports Indeterminate,
// which says "this validator cannot tell" rather than "this data is provably
// unsigned". RFC 5011 §8.2 agrees about what happens next: "A manual or other
// out-of-band update of all resolvers will be required."
//
// In practice the configured anchors have to be revoked too before this can
// fire, since they are in the set unconditionally — so reaching it means the
// root's published keys have all been withdrawn, which is an emergency by any
// reading.
func (m *Manager) checkViability(changes *[]string) {
	if len(m.anchors.Anchors()) > 0 {
		if m.tp.NeedsIntervention {
			m.tp.NeedsIntervention = false
			m.tp.InterventionNote = ""
			*changes = append(*changes, "the trust point has a usable key again")
		}
		return
	}
	if m.tp.NeedsIntervention {
		return
	}
	m.tp.NeedsIntervention = true
	m.tp.InterventionNote = "every key at this trust point has been revoked; " +
		"an operator must supply a new anchor out of band. Until then this resolver " +
		"cannot authenticate anything under it and will report indeterminate rather " +
		"than treating the zone as unsigned."
	*changes = append(*changes, m.tp.InterventionNote)
	m.cfg.Log.Error("every DNSSEC trust anchor at this trust point has been revoked",
		"zone", m.tp.Zone, "action", "an operator must configure a new anchor")
}

// material identifies a key by everything a signature depends on, ignoring the
// REVOKE bit so that a key and its revoked form are recognisably the same key.
//
// The public key is part of it. A key tag is a 16-bit checksum over the RDATA
// (RFC 4034 Appendix B), not an identifier, and two different keys can share
// one — so matching on the tag would let a collision be mistaken for the key
// this resolver already trusts.
func material(k *dns.DNSKEY) string {
	flags := k.Flags &^ dns.REVOKE
	return fmt.Sprintf("%d|%d|%d|%s", flags, k.Protocol, k.Algorithm, k.PublicKey)
}
