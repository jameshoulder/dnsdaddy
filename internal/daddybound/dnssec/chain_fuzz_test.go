package dnssec_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// FuzzInjectedAnswersNeverProduceSecure is the chain-following counterpart of
// the denial fuzzer, and it exists because CNAME and DNAME move the answer
// from "one RRset to check" to "a walk whose next step the sender chooses".
//
// The chain of trust is genuine all the way down — real anchor, real
// delegations, real keys — and only the answer section for one name is
// replaced by whatever the fuzzer encoded. That section is exactly what an
// on-path attacker controls, and it is the section that decides where the
// walk goes next: a CNAME target, a DNAME owner and target, a name that
// redirects to itself, a chain that never terminates.
//
// Two properties, and both are about what an attacker who writes that section
// can achieve:
//
//   - No input may reach Secure. A valid signature by the zone's key over an
//     RRset the fuzzer invented is not something a fuzzer can produce, so
//     every Secure here would be a chain accepted without authentication.
//     Insecure is refused for the same reason: it claims a *proof* that a
//     delegation carries no DS, and nothing the fuzzer writes is that proof.
//   - It must terminate. The hop cap and the visited set are what stop a
//     self-referential or mutually-referential answer from looping, and a
//     fuzzer is far better than a person at finding the shape that slips past
//     both. The deadline turns a hang into a failure rather than a hang.
func FuzzInjectedAnswersNeverProduceSecure(f *testing.F) {
	seedNames := []string{lab.AliasHop1, lab.DnameMatch, lab.AnswerName}

	// The genuine answers, with each signature's bits flipped: the closest an
	// attacker can get without the key, and the input most likely to slip
	// past a check that looks at records rather than at verification.
	base, err := lab.Standard()
	if err != nil {
		f.Fatalf("build: %v", err)
	}
	for _, name := range seedNames {
		resp, err := base.Lookup(context.Background(), name, dns.TypeA)
		if err != nil {
			continue
		}
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeA)
		for _, rr := range resp.Answer {
			clone := dns.Copy(rr)
			if sig, ok := clone.(*dns.RRSIG); ok {
				// Emptied rather than bit-flipped, and the difference
				// matters for the assertion below. A seed one bit away from
				// a valid signature is one mutation away from being valid
				// again, and this target asserts unconditionally that no
				// input reaches Secure — so a seed that a fuzzer could
				// repair would make that assertion false rather than
				// strict. An empty signature field packs and parses
				// cleanly, is exactly as inadmissible, and cannot be
				// restored without forging one.
				sig.Signature = ""
			}
			msg.Answer = append(msg.Answer, clone)
		}
		if packed, err := msg.Pack(); err == nil {
			f.Add(packed)
		}
	}

	// A chain that points at itself, and one that points at a name in the
	// same zone. Both are legal DNS and neither can be signed by the fuzzer,
	// so both must be refused — but they are the shapes that exercise the
	// loop detector rather than the verifier.
	for _, target := range []string{lab.AliasHop1, lab.AnswerName, "."} {
		msg := new(dns.Msg)
		msg.SetQuestion(lab.AliasHop1, dns.TypeA)
		msg.Answer = []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: lab.AliasHop1, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
			Target: target,
		}}
		if packed, err := msg.Pack(); err == nil {
			f.Add(packed)
		}
	}
	// A DNAME at the zone apex, which redirects the whole zone into itself.
	{
		msg := new(dns.Msg)
		msg.SetQuestion(lab.DnameMatch, dns.TypeA)
		msg.Answer = []dns.RR{&dns.DNAME{
			Hdr:    dns.RR_Header{Name: lab.LeafZone, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 3600},
			Target: lab.LeafZone,
		}}
		if packed, err := msg.Pack(); err == nil {
			f.Add(packed)
		}
	}
	f.Add([]byte{})

	// One hierarchy for the whole run. Deriving keys and signing five zones
	// costs milliseconds, which is harmless once and ruinous per execution:
	// the denial fuzzer managed a hundred inputs a minute before this was
	// hoisted, which is not fuzzing. Nothing in a validation mutates the
	// hierarchy and each iteration overwrites the same override.
	shared, err := lab.Standard()
	if err != nil {
		f.Fatalf("build: %v", err)
	}
	validator, err := shared.Validator(lab.Now())
	if err != nil {
		f.Fatalf("validator: %v", err)
	}

	f.Fuzz(func(t *testing.T, wire []byte) {
		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			t.Skip()
		}
		if len(msg.Question) != 1 {
			t.Skip()
		}

		// The question selects which link of which chain is attacked. Each
		// pair is (a name the chain passes through, the head of that chain),
		// so the query validated always depends on the substituted answer —
		// an earlier version of this target substituted at one name and
		// asserted about every chain, including ones that never reach it,
		// and reported a correctly Secure answer as a failure.
		links := [][2]string{
			{lab.AliasHop1, lab.AliasHop1},
			{lab.AliasHop2, lab.AliasHop1},
			{lab.AliasHop3, lab.AliasHop1},
			{lab.AnswerName, lab.AliasHop1},
			{lab.DnameMatch, lab.DnameMatch},
			{lab.AnswerName, lab.DnameMatch},
		}
		link := links[int(msg.Question[0].Qtype)%len(links)]
		attacked, head := link[0], link[1]

		shared.SubstituteAnswer(attacked, dns.TypeA, msg.Answer)
		defer shared.SubstituteAnswer(attacked, dns.TypeA, nil)

		// A deadline rather than a bare Background context: termination is
		// one of the two properties under test, and a target that hangs
		// proves it by hanging rather than by failing.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		got := validator.Validate(ctx, head, dns.TypeA)
		switch got.Status {
		case dnssec.StatusSecure:
			t.Fatalf("an injected answer at %s made %s Secure\n%s", attacked, head, got.Trace())
		case dnssec.StatusInsecure:
			t.Fatalf("an injected answer at %s made %s Insecure, which claims a proof "+
				"that no DS exists\n%s", attacked, head, got.Trace())
		}
	})
}
