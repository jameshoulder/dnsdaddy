package dnssec_test

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// RFC 6840 §4.1's ancestor-delegation restriction, on the NSEC3 side.
//
// A delegation point has two records at one name: the parent's, carrying NS
// with SOA clear, and the child's apex, carrying SOA. The parent's is
// genuinely signed by a zone inside the chain of trust and says only what a
// parent is entitled to say — that a delegation exists and whether it carries
// a DS. Reused as a NODATA proof for the child's own data it hides an entire
// signed zone, and every signature still verifies.
//
// RFC 5155 §8.3 states the NSEC3 form of the rule:
//
//	The DNAME type bit must not be set and the NS type bit may only be set
//	if the SOA type bit is set. If this is not the case, it would be an
//	indication that an attacker is using them to falsely deny the existence
//	of RRs for which the server is not authoritative.
//
// The engine applied that to the record matching the *closest encloser* and
// not to a record matching the queried name directly, which is the case a
// NODATA proof uses. The NSEC path had the check at every use; NSEC3 had it
// at one. An asymmetry between two implementations of one rule is where this
// class of defect lives, and it was found by a review bot rather than by the
// suite.
//
// The attack needs no forgery. Strip the DS response so the walk stays in the
// parent — the documented zone-cut assumption, which is meant to cost only a
// false Bogus — then answer any type at the delegation name with NOERROR and
// the parent's own signed NSEC3. That bitmap lists NS, DS, RRSIG and NSEC3;
// it does not list the queried type or CNAME, so a validator checking only
// those two reports Secure for data the parent has no authority over.
func TestAParentSideNSEC3CannotDenyTheChildsData(t *testing.T) {
	h, err := lab.NSEC3()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// The parent's own signed NSEC3 for the delegation point, taken from the
	// zone rather than constructed: NS and DS set, SOA clear, which is what
	// a delegation record looks like and what makes it the parent's.
	proof := parentDelegationNSEC3(t, h)

	src := &delegationAttack{inner: h, delegation: lab.LeafZone, proof: proof}
	got := dnssec.New(src, cfg).Validate(context.Background(), lab.LeafZone, dns.TypeTXT)

	if got.Status == dnssec.StatusSecure {
		t.Fatalf("a parent-side delegation NSEC3 was accepted as proof that the child "+
			"has no TXT records\n%s", got.Trace())
	}
	// And the reason must point at the record's entitlement rather than at
	// something incidental, or the fix is somewhere else and this passes by
	// accident.
	if got.Reason != dnssec.ReasonDenialWrongZone {
		t.Errorf("reason = %s, want %s", got.Reason, dnssec.ReasonDenialWrongZone)
	}
}

// delegationAttack strips a DS response so the walk keeps its zone-cut
// assumption, and then answers the queried type with the parent's own signed
// delegation proof.
type delegationAttack struct {
	inner      dnssec.Source
	delegation string
	proof      []dns.RR
}

func (s *delegationAttack) Lookup(ctx context.Context, name string, rrtype uint16) (dnssec.Response, error) {
	resp, err := s.inner.Lookup(ctx, name, rrtype)
	if err != nil || dns.CanonicalName(name) != dns.CanonicalName(s.delegation) {
		return resp, err
	}
	switch rrtype {
	case dns.TypeDS:
		// Nothing at all: no DS, no proof either way. The walk assumes the
		// name is not a zone cut and stays in the parent.
		return dnssec.Response{Rcode: dns.RcodeSuccess}, nil
	default:
		// NOERROR with no answer, justified by the parent's genuine proof.
		return dnssec.Response{Rcode: dns.RcodeSuccess, Authority: s.proof}, nil
	}
}

// parentDelegationNSEC3 returns the middle zone's NSEC3 for the leaf
// delegation, with its signature.
//
// Pulled out of the built hierarchy rather than written here, so the record is
// one the lab's signer actually produced and one a real referral would carry.
// A hand-built record would test the bitmap check against a record no signer
// made.
func parentDelegationNSEC3(t *testing.T, h *lab.Hierarchy) []dns.RR {
	t.Helper()

	var out []dns.RR
	for _, rr := range h.Records() {
		n3, ok := rr.(*dns.NSEC3)
		if !ok || !dns.IsSubDomain(lab.MiddleZone, n3.Hdr.Name) {
			continue
		}
		var hasNS, hasDS, hasSOA bool
		for _, t := range n3.TypeBitMap {
			switch t {
			case dns.TypeNS:
				hasNS = true
			case dns.TypeDS:
				hasDS = true
			case dns.TypeSOA:
				hasSOA = true
			}
		}
		if !hasNS || !hasDS || hasSOA {
			continue
		}
		// Only the record whose hash is the delegation name's, so the proof
		// matches rather than merely covers.
		if !strings.EqualFold(n3.Hdr.Name, nsec3OwnerFor(lab.LeafZone, n3, lab.MiddleZone)) {
			continue
		}
		out = append(out, rr)
		for _, sig := range h.Set(lab.MiddleZone, n3.Hdr.Name, dns.TypeNSEC3) {
			if _, isSig := sig.(*dns.RRSIG); isSig {
				out = append(out, sig)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("the middle zone publishes no delegation NSEC3 for the leaf; the fixture has changed")
	}
	return out
}

// nsec3OwnerFor recomputes the NSEC3 owner a name hashes to under one
// record's parameters, so the test selects the *matching* record rather than
// whichever delegation record happens to come first.
func nsec3OwnerFor(name string, like *dns.NSEC3, zone string) string {
	salt := like.Salt
	return dns.HashName(dns.CanonicalName(name), like.Hash, like.Iterations, salt) + "." + dns.CanonicalName(zone)
}

// A response cannot both carry data and deny that the name exists.
//
// The rcode is one unsigned field of the header, which makes changing it the
// cheapest edit an on-path attacker can make. Daddybound validates the RRset
// and is right about it — the records are genuine and the signature verifies —
// but the *response* is self-contradictory, and a consumer that honours the
// header would cache the name, and potentially its whole subtree, as absent
// while the validator endorsed the message.
//
// So the contradiction is refused rather than resolved in the data's favour.
// Refusing is safe in the direction that matters: the worst it can cost is a
// verdict on a response no honest server sends.
//
// Reported by a review bot, not by this suite. The engine had a rule for the
// converse — an NXDOMAIN whose covering NSEC proves the name exists is
// ReasonDenialContradicted — and none for this direction, which is the
// asymmetry that let it through.
func TestDataCannotArriveWithANameError(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	// Every record untouched; only the header changed.
	h.ForceRcode(lab.AnswerName, dns.TypeA, dns.RcodeNameError)

	got := dnssec.New(h, cfg).Validate(context.Background(), lab.AnswerName, dns.TypeA)
	if got.Status == dnssec.StatusSecure {
		t.Fatalf("a signed RRset delivered under NXDOMAIN was reported Secure; a consumer "+
			"honouring the header would cache the name as absent\n%s", got.Trace())
	}
	if got.Reason != dnssec.ReasonDenialContradicted {
		t.Errorf("reason = %s, want %s", got.Reason, dnssec.ReasonDenialContradicted)
	}
}
