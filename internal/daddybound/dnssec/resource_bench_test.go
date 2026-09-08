package dnssec_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// What one validation costs, for the six shapes an attacker can ask for.
//
// The target this is measured against is a small self-hosted box — roughly
// one vCPU and a gigabyte — because that is what DNS Daddy runs on, and
// because a resolver that can be made to spend a second on a query is a
// resolver that can be turned off by sending queries.
//
// These are not micro-optimisation benchmarks and the numbers are not
// targets. They exist to answer one question: can a structure the sender
// chooses make the work grow without bound? Every shape below is one where
// the sender picks the size — the number of denial records, the NSEC3
// iteration count, the length of a CNAME chain, the amount of padding in an
// authority section — so each is measured with the *configured limit* in
// mind rather than against a stopwatch.
//
// The Source is in memory, so what is measured is validation rather than the
// network. That is deliberate: the network is not the attacker's lever here,
// the shape of the response is.

func benchValidate(b *testing.B, h *lab.Hierarchy, name string, rrtype uint16, want dnssec.ValidationStatus) {
	b.Helper()
	v, err := h.Validator(lab.Now())
	if err != nil {
		b.Fatalf("validator: %v", err)
	}
	ctx := context.Background()

	// One validation outside the timer, both to warm nothing in particular
	// and to assert the benchmark is measuring the case it claims to. A
	// benchmark of a Bogus path that was meant to be the Secure path is a
	// benchmark of the wrong thing, and nothing about the timing would say
	// so.
	if got := v.Validate(ctx, name, rrtype); got.Status != want {
		b.Fatalf("%s %s: %s, want %s\n%s", name, dns.TypeToString[rrtype], got.Status, want, got.Trace())
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := v.Validate(ctx, name, rrtype); got.Status != want {
			b.Fatalf("verdict changed between runs: %s", got.Status)
		}
	}
}

func BenchmarkSignedPositiveAnswer(b *testing.B) {
	h, err := lab.Standard()
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	benchValidate(b, h, lab.AnswerName, dns.TypeA, dnssec.StatusSecure)
}

func BenchmarkNSECNameError(b *testing.B) {
	h, err := lab.Standard()
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	benchValidate(b, h, lab.MissingName, dns.TypeA, dnssec.StatusSecure)
}

func BenchmarkNSEC3NameError(b *testing.B) {
	h, err := lab.NSEC3()
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	benchValidate(b, h, lab.MissingName, dns.TypeA, dnssec.StatusSecure)
}

func BenchmarkCNAMEChain(b *testing.B) {
	h, err := lab.Standard()
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	benchValidate(b, h, lab.AliasHop1, dns.TypeA, dnssec.StatusSecure)
}

func BenchmarkDNAMERedirection(b *testing.B) {
	h, err := lab.Standard()
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	benchValidate(b, h, lab.DnameMatch, dns.TypeA, dnssec.StatusSecure)
}

// NSEC3 at the highest iteration count this validator will compute.
//
// RFC 9276 §3.1 tells zones to publish 0 and this is 100, the ceiling
// DefaultLimits sets from RFC 9276 Appendix A's measured interoperability
// point. A zone publishing it is pathological but valid, so the work is real
// work rather than refused work — and it is the most expensive *accepted*
// denial proof anyone can construct, because a record above the ceiling is
// set aside rather than hashed.
func BenchmarkNSEC3AtTheIterationCeiling(b *testing.B) {
	spec := lab.NSEC3Spec()
	for i := range spec.Zones {
		spec.Zones[i].NSEC3Iterations = uint16(dnssec.DefaultLimits().MaxNSEC3Iterations)
	}
	h, err := lab.Build(spec)
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	benchValidate(b, h, lab.MissingName, dns.TypeA, dnssec.StatusSecure)
}

// An authority section padded to the record budget with junk.
//
// The sender chooses how many records to put in an authority section, and
// every one of them is a candidate the validator must at least look at. The
// budget (Limits.MaxDenialRecords) is what turns "as many as fit in a
// message" into a constant, and this measures the cost of reaching it.
//
// The verdict is Indeterminate rather than Bogus, and deliberately: a
// validator that stopped reading has no business accusing the zone of
// anything. See denialProof.unreadOverReported.
func BenchmarkPaddedAuthoritySection(b *testing.B) {
	h, err := lab.Standard()
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	resp, err := h.Lookup(context.Background(), lab.MissingName, dns.TypeA)
	if err != nil {
		b.Fatalf("lookup: %v", err)
	}

	// A template taken from a genuine signature, so the padding is
	// *admissible*: right algorithm, right key tag, right signer, inside its
	// validity window. That is what makes this the worst case rather than a
	// cheap one — each padded record reaches the verifier and costs a
	// canonicalisation and a public-key operation before it fails, which is
	// exactly the bill an attacker is trying to run up. Padding with records
	// that fail a format check would measure the format check.
	var template *dns.RRSIG
	for _, rr := range resp.Authority {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeNSEC {
			template = sig
			break
		}
	}
	if template == nil {
		b.Fatal("the genuine proof carries no NSEC signature to model the padding on")
	}

	// Four times the budget, and placed *before* the genuine records, so the
	// budget is spent before the real proof is reached. That is the
	// attacker's move: not to break the proof but to bury it, and the
	// measured verdict is Indeterminate with ReasonResourceLimit rather than
	// Bogus — a validator that stopped reading has no business accusing the
	// zone of anything.
	var padded []dns.RR
	for i := 0; i < 4*dnssec.DefaultLimits().MaxDenialRecords; i++ {
		owner := fmt.Sprintf("pad%04d.example.dnsdaddylab.", i)
		sig := dns.Copy(template).(*dns.RRSIG)
		sig.Hdr.Name = owner
		padded = append(padded, &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
			NextDomain: fmt.Sprintf("pad%04d.example.dnsdaddylab.", i+1),
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		}, sig)
	}
	h.SubstituteAuthority(lab.MissingName, dns.TypeA, append(padded, resp.Authority...))

	benchValidate(b, h, lab.MissingName, dns.TypeA, dnssec.StatusIndeterminate)
}

// The same padding, with the genuine records first.
//
// The pair is the point. Burying a proof under junk costs the verdict;
// following it with junk does not, because the budget is spent on records
// that were already enough. A validator that refused this one would be
// letting an attacker deny an answer by appending to it, which is a cheaper
// attack than the one above.
func BenchmarkPaddedAuthoritySectionAfterAValidProof(b *testing.B) {
	h, err := lab.Standard()
	if err != nil {
		b.Fatalf("build: %v", err)
	}
	resp, err := h.Lookup(context.Background(), lab.MissingName, dns.TypeA)
	if err != nil {
		b.Fatalf("lookup: %v", err)
	}

	padded := append([]dns.RR(nil), resp.Authority...)
	for i := 0; i < 4*dnssec.DefaultLimits().MaxDenialRecords; i++ {
		owner := fmt.Sprintf("pad%04d.example.dnsdaddylab.", i)
		padded = append(padded, &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
			NextDomain: fmt.Sprintf("pad%04d.example.dnsdaddylab.", i+1),
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		})
	}
	h.SubstituteAuthority(lab.MissingName, dns.TypeA, padded)

	benchValidate(b, h, lab.MissingName, dns.TypeA, dnssec.StatusSecure)
}
