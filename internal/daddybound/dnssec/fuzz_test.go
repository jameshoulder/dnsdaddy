package dnssec

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A validator's entire input arrives from the network, so the interesting
// question is not whether it verifies correct signatures — the lab settles
// that — but whether hostile input can make it panic, hang, or return Secure.
//
// The invariants below are asserted on every input the fuzzer finds:
//
//  1. it does not panic;
//  2. it terminates;
//  3. it never returns Secure, because none of these inputs carries a
//     signature anyone could have made.
//
// The third is the one worth having. A fuzz target that only checked for
// panics would pass against a validator that returned Secure for everything.

// FuzzCanonicalSignedData drives the trusted computing base directly.
//
// Signed-data construction runs before any check, on records that have been
// parsed but not otherwise examined, which makes it the first thing an
// attacker's bytes reach.
func FuzzCanonicalSignedData(f *testing.F) {
	f.Add("www.example.test.", uint8(3), uint32(3600), "192.0.2.1")
	f.Add(".", uint8(0), uint32(0), "0.0.0.0")
	f.Add("*.example.test.", uint8(2), uint32(4294967295), "255.255.255.255")
	// A Labels field larger than the owner name has labels: the input that
	// would drive a negative slice index if the guard in canonicalRR were
	// removed.
	f.Add("a.", uint8(200), uint32(1), "1.2.3.4")

	f.Fuzz(func(t *testing.T, owner string, labels uint8, ttl uint32, addr string) {
		rr, err := dns.NewRR(dns.Fqdn(sanitiseName(owner)) + " 3600 IN A " + addr)
		if err != nil || rr == nil {
			t.Skip()
		}
		sig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name: dns.Fqdn(sanitiseName(owner)), Rrtype: dns.TypeRRSIG,
				Class: dns.ClassINET, Ttl: ttl,
			},
			TypeCovered: dns.TypeA,
			Algorithm:   uint8(AlgED25519),
			Labels:      labels,
			OrigTtl:     ttl,
			SignerName:  "example.test.",
			Signature:   "AAAA",
		}

		// The contract is "returns bytes or an error", never a panic. An
		// error here is a perfectly good outcome: refusing to construct
		// signed data is safe, and constructing the wrong bytes is not.
		_, _ = canonicalSignedData(sig, []dns.RR{rr})
	})
}

// FuzzParseRSAPublicKey drives the RFC 3110 length-prefixed decoder, which is
// the only hand-written length parsing in the package and therefore the most
// likely place for an out-of-range read.
func FuzzParseRSAPublicKey(f *testing.F) {
	f.Add([]byte{3, 1, 0, 1, 0xC0, 0xFF, 0xEE})
	f.Add([]byte{0, 1, 0, 1})          // three-octet form
	f.Add([]byte{0})                   // truncated
	f.Add([]byte{255})                 // exponent length with no exponent
	f.Add([]byte{0, 0xFF, 0xFF, 0x01}) // 65535-octet exponent, four octets of data

	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := parseRSAPublicKey(data)
		if err != nil {
			return
		}
		// A key that parsed must be usable without panicking downstream.
		if key.N == nil || key.N.BitLen() == 0 {
			t.Fatalf("parseRSAPublicKey accepted a key with no modulus: %x", data)
		}
		if key.E < 3 {
			t.Fatalf("parseRSAPublicKey accepted exponent %d: %x", key.E, data)
		}
	})
}

// FuzzValidateWireResponse feeds arbitrary bytes in as a DNS message and
// validates whatever parses out of it.
//
// This is the closest thing to the real threat: an attacker who controls the
// response and can put anything in it that the wire format permits.
func FuzzValidateWireResponse(f *testing.F) {
	seed := new(dns.Msg)
	seed.SetQuestion("www.example.test.", dns.TypeA)
	if packed, err := seed.Pack(); err == nil {
		f.Add(packed)
	}
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	anchors, err := NewTrustAnchors(TrustAnchor{
		Name: "example.test.", KeyTag: 1234,
		Algorithm: AlgED25519, DigestType: DigestSHA256,
		Digest: make([]byte, 32),
	})
	if err != nil {
		f.Fatalf("anchors: %v", err)
	}

	f.Fuzz(func(t *testing.T, wire []byte) {
		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			t.Skip()
		}

		v := New(&fuzzSource{msg: msg}, Config{
			Anchors: anchors,
			Policy:  DefaultPolicy(),
			Clock:   FixedClock{Instant: time.Unix(1767225600, 0)},
			Limits:  DefaultLimits(),
		})

		// A deadline rather than a bare Background context: "it terminates"
		// is one of the invariants, and a test that hangs proves it by
		// hanging forever rather than by failing.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		got := v.Validate(ctx, "www.example.test.", dns.TypeA)

		// The invariant that makes this target worth running. Nothing the
		// fuzzer can produce is signed by the anchor's key, because the
		// anchor's digest is thirty-two zero octets and no DNSKEY digests to
		// that. Any Secure verdict here is a forged chain of trust.
		if got.Status == StatusSecure {
			t.Fatalf("fuzzed input validated as SECURE\n%s", got.Trace())
		}
	})
}

// fuzzSource answers every lookup from one arbitrary message, so the
// validator sees whatever records the fuzzer managed to encode.
type fuzzSource struct{ msg *dns.Msg }

func (s *fuzzSource) Lookup(ctx context.Context, name string, rrtype uint16) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	var out []dns.RR
	for _, section := range [][]dns.RR{s.msg.Answer, s.msg.Ns, s.msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if dns.CanonicalName(h.Name) != dns.CanonicalName(name) {
				continue
			}
			if h.Rrtype == rrtype || h.Rrtype == dns.TypeRRSIG {
				out = append(out, rr)
			}
		}
	}
	// Everything the fuzzer produced goes into both sections, so denial
	// reasoning sees arbitrary records too rather than only positive
	// validation.
	return Response{Answer: out, Authority: out}, nil
}

// sanitiseName keeps the fuzzer's names inside what the wire format can
// express, so the target spends its time on validation logic rather than on
// rediscovering that a 300-octet label does not pack.
func sanitiseName(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '*':
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "example.test."
	}
	return string(out)
}
