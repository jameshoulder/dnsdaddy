package dnssec_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// Resource safety for the denial paths, aimed at the one machine this has to
// survive on: roughly one vCPU and a gigabyte of memory.
//
// Every quantity these tests vary is one an attacker chooses — the iteration
// count, the number of records, the depth of a name — and the property under
// test is always the same shape. Work must stay bounded, and hitting a bound
// must produce Indeterminate rather than a verdict. "We stopped early" is not
// evidence about the data, and an implementation that answers Secure after
// giving up has turned a denial of service into a forgery.

// adversarialNSEC3Spec builds a zone whose NSEC3 parameters are as expensive
// as the validator's own ceiling allows, with plenty of records to hash
// against.
func adversarialNSEC3Spec(t *testing.T, iterations uint16, extraNames int) lab.Spec {
	t.Helper()
	spec := lab.NSEC3Spec()
	for i := range spec.Zones {
		spec.Zones[i].NSEC3Iterations = iterations
		if dns.CanonicalName(spec.Zones[i].Name) != lab.LeafZone {
			continue
		}
		for n := 0; n < extraNames; n++ {
			spec.Zones[i].Records = append(spec.Zones[i].Records, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   labelFor(n) + "." + lab.LeafZone,
					Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600,
				},
				Txt: []string{"filler"},
			})
		}
	}
	return spec
}

func labelFor(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	out := ""
	for {
		out = string(alphabet[n%len(alphabet)]) + out
		n /= len(alphabet)
		if n == 0 {
			return "n" + out
		}
	}
}

// TestExpensiveNSEC3IsRefusedRatherThanComputed checks the iteration ceiling
// from the outside: a zone above it must produce Indeterminate, and must do so
// quickly, because the whole point is not to perform the work.
//
// RFC 9276 §3.2 permits reporting such a zone insecure instead. Daddybound
// does not take that permission, and the RFC gives the reason in the same
// paragraph: "treating a high iterations count as insecure leaves zones
// subject to attack". An attacker who can raise a zone's iteration count could
// otherwise strip its protection by making validation expensive.
func TestExpensiveNSEC3IsRefusedRatherThanComputed(t *testing.T) {
	h, err := lab.Build(adversarialNSEC3Spec(t, 4000, 40))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	start := time.Now()
	got := v.Validate(context.Background(), lab.MissingName, dns.TypeA)
	elapsed := time.Since(start)

	if got.Status != dnssec.StatusIndeterminate {
		t.Fatalf("status = %s, want indeterminate\n%s", got.Status, got.Trace())
	}
	if got.Reason != dnssec.ReasonDenialNotImplemented {
		t.Errorf("reason = %s, want %s (a statement about this validator's budget, not about the zone)",
			got.Reason, dnssec.ReasonDenialNotImplemented)
	}
	// Generous, because a shared CI machine is not a benchmark rig. The
	// assertion is "it refused instead of grinding", and grinding 40 records
	// at 4000 iterations would be visible against any bound of this order.
	if elapsed > 2*time.Second {
		t.Errorf("refusing an over-budget zone took %s; the records were being hashed rather than skipped", elapsed)
	}
}

// TestNSEC3HashBudgetBoundsTotalWork exercises the other half of the pair.
//
// The iteration ceiling alone bounds the cost of one record. An attacker who
// respects it can still send many records, or force a walk up a deep name, and
// the cost is the product. This drives the total-hash budget to zero and
// checks that the outcome is a refusal rather than a wrong answer.
func TestNSEC3HashBudgetBoundsTotalWork(t *testing.T) {
	h, err := lab.Build(adversarialNSEC3Spec(t, 100, 60))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	cfg, err := h.Config(lab.Now())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	// A budget far below what any proof needs. The validator must notice it
	// ran out rather than conclude from what it managed to hash.
	cfg.Limits.MaxNSEC3Hashes = 3
	v := dnssec.New(h, cfg)

	got := v.Validate(context.Background(), lab.MissingName, dns.TypeA)
	if got.Status == dnssec.StatusSecure {
		t.Fatalf("a proof was accepted after the hash budget ran out\n%s", got.Trace())
	}
	if got.Status == dnssec.StatusInsecure {
		t.Fatalf("running out of budget was reported as Insecure, which is a claim about the zone\n%s", got.Trace())
	}
}

// TestADeepNameDoesNotUnboundTheEncloserWalk checks the loop RFC 5155 §8.3
// describes, which walks one label at a time towards the apex.
//
// The number of turns is the label count of the queried name, which the
// caller supplies. It is bounded by the wire format at 127, and each turn
// costs hashes, so the guard is the hash budget rather than a separate depth
// limit. What must not happen is a verdict.
func TestADeepNameDoesNotUnboundTheEncloserWalk(t *testing.T) {
	h, err := lab.NSEC3()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	deep := ""
	for i := 0; i < 100; i++ {
		deep += "d."
	}
	deep += lab.LeafZone

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := v.Validate(ctx, deep, dns.TypeA)
	if got.Status == dnssec.StatusSecure {
		t.Fatalf("a 100-label name below the zone validated as secure\n%s", got.Trace())
	}
}

// TestAnEmptyAuthoritySectionIsNeverAProof is the degenerate case, kept
// because it is the one an implementation is most likely to get wrong by
// accident: a loop over no records finds no contradiction, and a validator
// that treats "found nothing wrong" as "verified" says Secure.
func TestAnEmptyAuthoritySectionIsNeverAProof(t *testing.T) {
	for _, spec := range []func() lab.Spec{lab.StandardSpec, lab.NSEC3Spec} {
		h, err := lab.Build(spec())
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		h.SubstituteAuthority(lab.MissingName, dns.TypeA, nil)
		v, err := h.Validator(lab.Now())
		if err != nil {
			t.Fatalf("validator: %v", err)
		}
		got := v.Validate(context.Background(), lab.MissingName, dns.TypeA)
		if got.Status == dnssec.StatusSecure {
			t.Fatalf("an empty authority section proved a name error\n%s", got.Trace())
		}
	}
}

// TestPaddingADenialProofIsNotAnAccusation covers the bound on how many denial
// RRsets one response may have authenticated.
//
// Each one costs a canonicalisation and usually a public-key operation, and
// the count is chosen by whoever sent the response. Two things must hold. The
// work has to stop, and — less obviously — stopping must not be reported as a
// fault in the zone. A response padded until the real proof falls off the end
// would otherwise come back Bogus, which blames the zone for the padding and
// gives an attacker a way to turn any name into a validation failure.
func TestPaddingADenialProofIsNotAnAccusation(t *testing.T) {
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	genuine, err := h.Lookup(context.Background(), lab.MissingName, dns.TypeA)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	// Real, correctly signed NSEC records from the zone, repeated under
	// fresh owner names so each one is a separate RRset to authenticate.
	// They will not verify at their new owners, which is the point: the cost
	// is paid before that is discovered.
	padded := make([]dns.RR, 0, 256)
	for i := 0; i < 200; i++ {
		for _, rr := range genuine.Authority {
			clone := dns.Copy(rr)
			clone.Header().Name = fmt.Sprintf("pad%d.%s", i, lab.LeafZone)
			if sig, ok := clone.(*dns.RRSIG); ok {
				sig.Hdr.Name = fmt.Sprintf("pad%d.%s", i, lab.LeafZone)
			}
			padded = append(padded, clone)
		}
	}
	padded = append(padded, genuine.Authority...)

	h.SubstituteAuthority(lab.MissingName, dns.TypeA, padded)
	v, err := h.Validator(lab.Now())
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	start := time.Now()
	got := v.Validate(context.Background(), lab.MissingName, dns.TypeA)
	elapsed := time.Since(start)

	if got.Status == dnssec.StatusSecure {
		t.Fatalf("padding was read as a proof\n%s", got.Trace())
	}
	if got.Status == dnssec.StatusBogus {
		t.Errorf("a truncated read was reported as a fault in the zone (%s); "+
			"padding must not be a way to make any name fail validation\n%s", got.Reason, got.Trace())
	}
	if got.Reason != dnssec.ReasonResourceLimit {
		t.Errorf("reason = %s, want %s: the verdict should say this validator stopped reading",
			got.Reason, dnssec.ReasonResourceLimit)
	}
	if elapsed > 2*time.Second {
		t.Errorf("validating a padded response took %s; the records were being verified rather than skipped", elapsed)
	}
}
