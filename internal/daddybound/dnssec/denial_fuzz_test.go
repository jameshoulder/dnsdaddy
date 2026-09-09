package dnssec_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
)

// FuzzInjectedDenialRecordsNeverProveANameError is the end-to-end statement of
// the rule the whole of RFC 4035 §5.4 rests on: receiving an NSEC record
// proves nothing.
//
// The chain of trust here is genuine all the way down — real anchor, real
// delegations, real keys — and only the authority section of the final answer
// is replaced by whatever the fuzzer encoded. Since a valid signature over the
// right RRset by the zone's key is not something a fuzzer can produce, no
// input may reach Secure. Any that does is a forged denial, which is the P0
// failure class this project measures itself against.
//
// The seed corpus is the genuine proof with one bit flipped in each of its
// signatures: the closest an attacker can realistically get, and the input
// most likely to slip past a check that looks at records rather than at
// verification.
func FuzzInjectedDenialRecordsNeverProveANameError(f *testing.F) {
	for _, spec := range []func() lab.Spec{lab.StandardSpec, lab.NSEC3Spec} {
		h, err := lab.Build(spec())
		if err != nil {
			f.Fatalf("build: %v", err)
		}
		resp, err := h.Lookup(context.Background(), lab.MissingName, dns.TypeA)
		if err != nil {
			f.Fatalf("lookup: %v", err)
		}

		msg := new(dns.Msg)
		msg.SetQuestion(lab.MissingName, dns.TypeA)
		msg.Rcode = dns.RcodeNameError
		for _, rr := range resp.Authority {
			clone := dns.Copy(rr)
			if sig, ok := clone.(*dns.RRSIG); ok {
				if flipped, err := flipOneBit(sig.Signature); err == nil {
					sig.Signature = flipped
				}
			}
			msg.Ns = append(msg.Ns, clone)
		}
		if packed, err := msg.Pack(); err == nil {
			f.Add(packed)
		}
	}
	f.Add([]byte{})

	// Built once, outside the loop. Deriving keys and signing three zones
	// costs milliseconds, which sounds harmless until it is paid on every
	// execution: with the hierarchy inside the loop this target managed a
	// hundred inputs a minute, which is not fuzzing. Nothing in a validation
	// mutates the hierarchy, and each iteration overwrites the same override,
	// so reuse is safe as well as necessary.
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

		shared.SubstituteAuthority(lab.MissingName, dns.TypeA, msg.Ns)
		v := validator

		// A deadline rather than a bare Background context: termination is
		// one of the properties under test, and a target that hangs proves
		// it by hanging rather than by failing.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		got := v.Validate(ctx, lab.MissingName, dns.TypeA)
		if got.Status == dnssec.StatusSecure {
			t.Fatalf("injected denial records proved a name error\n%s", got.Trace())
		}
		if got.Status == dnssec.StatusInsecure {
			t.Fatalf("injected denial records produced Insecure, which claims a proof of no DS\n%s", got.Trace())
		}
	})
}
