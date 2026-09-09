package dnssec_test

import (
	"context"
	"sort"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Two denial records at one owner name, and who gets to choose between them.
//
// A correct zone publishes one NSEC per name (RFC 4034 §4.1), and RFC 5155
// §7.1 step 6 tells an NSEC3 signer to combine records sharing a hashed owner
// name "with the Type Bit Maps field consisting of the union of the types
// represented by the set". Nothing enforces either on the wire. A signer can
// emit two; both are then genuinely signed as one RRset, both authenticate,
// and a validator that reads "the" record at a name has to pick one.
//
// Picking the first was a real defect in this package, found by reviewing the
// diff rather than by any test. The records arrive in whatever order an
// on-path attacker chooses, so where one bitmap lists the queried type and the
// other does not, the attacker chooses between "the zone says this type
// exists, so this NODATA is a lie" and "proved". They would choose the second,
// and did: reversing the authority section moved the verdict from Bogus to
// Secure.
//
// The union is order-independent and fails in the right direction — a type
// present in any record counts as present, which produces refusals rather than
// proofs.

// duplicateCase runs one shape both ways round and returns the two verdicts.
func duplicateCase(t *testing.T, nsec3 bool) (forward, reverse dnssec.ValidationResult) {
	t.Helper()

	run := func(reversed bool) dnssec.ValidationResult {
		spec := lab.StandardSpec
		if nsec3 {
			spec = lab.NSEC3Spec
		}
		h, err := lab.Build(spec())
		if err != nil {
			t.Fatalf("build: %v", err)
		}

		// The second record claims a TXT RRset exists at the name. The
		// genuine one does not list it, and the query is for TXT.
		addTXT := func(bits []uint16) []uint16 {
			out := append(append([]uint16{}, bits...), dns.TypeTXT)
			sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
			return out
		}
		if nsec3 {
			owner := h.Zone(lab.LeafZone).NSEC3OwnerFor(lab.AnswerName)
			if owner == "" {
				t.Fatalf("the NSEC3 zone publishes no record at %s", lab.AnswerName)
			}
			err = h.AddSecondNSEC3(lab.LeafZone, owner, func(n *dns.NSEC3) {
				n.TypeBitMap = addTXT(n.TypeBitMap)
			})
		} else {
			err = h.AddSecondNSEC(lab.LeafZone, lab.AnswerName, func(n *dns.NSEC) {
				n.TypeBitMap = addTXT(n.TypeBitMap)
			})
		}
		if err != nil {
			t.Fatalf("adding the second record: %v", err)
		}

		resp, err := h.Lookup(context.Background(), lab.AnswerName, dns.TypeTXT)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		authority := append([]dns.RR(nil), resp.Authority...)
		if reversed {
			for i, j := 0, len(authority)-1; i < j; i, j = i+1, j-1 {
				authority[i], authority[j] = authority[j], authority[i]
			}
		}
		h.SubstituteAuthority(lab.AnswerName, dns.TypeTXT, authority)

		v, err := h.Validator(lab.Now())
		if err != nil {
			t.Fatalf("validator: %v", err)
		}
		return v.Validate(context.Background(), lab.AnswerName, dns.TypeTXT)
	}
	return run(false), run(true)
}

func TestDuplicateDenialRecordsGiveTheSameVerdictEitherWayRound(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nsec3 bool
	}{{"nsec", false}, {"nsec3", true}} {
		t.Run(tc.name, func(t *testing.T) {
			forward, reverse := duplicateCase(t, tc.nsec3)

			if forward.Status != reverse.Status {
				t.Fatalf("the record order chose the verdict: %s one way, %s the other\n--- forward ---\n%s\n--- reversed ---\n%s",
					forward.Status, reverse.Status, forward.Trace(), reverse.Trace())
			}
			// The direction matters as much as the agreement. One of the two
			// signed records says the queried type exists, so no ordering may
			// prove it absent.
			if forward.Status == dnssec.StatusSecure {
				t.Fatalf("a NODATA was proved although one of the zone's own signed records lists the type\n%s",
					forward.Trace())
			}
			if forward.Reason != dnssec.ReasonDenialContradicted {
				t.Errorf("reason = %s, want %s: the union of the bitmaps contains the queried type",
					forward.Reason, dnssec.ReasonDenialContradicted)
			}
		})
	}
}
