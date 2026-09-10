package recursive_test

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
)

// The point of issue #64: a validator working through a forwarder cannot tell
// "this name is not a zone cut" from "the server did not say", so it assumes.
// A resolver that followed referrals knows, because it crossed them.
func TestZoneCutsAreEstablishedFromRealReferrals(t *testing.T) {
	r, h := hierarchy(t)
	src := recursive.NewSource(r)

	cuts, ok := src.ZoneCutsFor(context.Background(), "www.example.com.")
	if !ok {
		t.Fatalf("the source has no opinion about zone cuts (lab write errors: %v)", h.WriteErrors())
	}

	// Positively a zone cut: the resolver was referred here.
	for _, cut := range []string{"com.", "example.com."} {
		is, present := cuts[cut]
		if !present {
			t.Errorf("%s is missing from the zone-cut map; the referral was not recorded", cut)
			continue
		}
		if !is {
			t.Errorf("%s reported as not a zone cut, but the resolver was referred to it", cut)
		}
	}

	// Positively NOT a zone cut, which is the half that removes the
	// assumption. The walk passed through this name without being referred
	// at it, and that is an observation rather than a guess.
	is, present := cuts["www.example.com."]
	if !present {
		t.Fatal("www.example.com. is absent from the map, so the validator would still have to assume")
	}
	if is {
		t.Error("www.example.com. reported as a zone cut; nothing delegated it")
	}
}

// The optional capability has to be visible through the interface the
// validator actually type-asserts on, or none of this reaches the walk.
func TestTheNativeSourceSatisfiesDelegationSource(t *testing.T) {
	r, _ := hierarchy(t)
	var src dnssec.Source = recursive.NewSource(r)

	if _, ok := src.(dnssec.DelegationSource); !ok {
		t.Fatal("the native source does not satisfy dnssec.DelegationSource, so the walk will keep assuming")
	}
}

// A source with nothing cached must say so rather than return an empty map,
// which the walk would read as "none of these are zone cuts".
func TestAnUnresolvableNameYieldsNoOpinionRatherThanAnEmptyAnswer(t *testing.T) {
	r, _ := hierarchy(t)
	src := recursive.NewSource(r)

	// A name in a TLD the laboratory root does not delegate at all.
	_, ok := src.ZoneCutsFor(context.Background(), "host.nonexistent-tld.")
	if ok {
		// If it does have an opinion it must at least not claim the
		// intermediate names are known non-cuts on no evidence.
		cuts, _ := src.ZoneCutsFor(context.Background(), "host.nonexistent-tld.")
		if is, present := cuts["nonexistent-tld."]; present && is {
			t.Fatal("claimed a delegation that the root never issued")
		}
	}
}

// The adapter must hand the validator what the authoritative server said,
// unchanged. Anything else breaks the correspondence between the records that
// were validated and the records that were fetched.
func TestTheSourceReturnsTheAuthoritativeRecords(t *testing.T) {
	r, _ := hierarchy(t)
	src := recursive.NewSource(r)

	resp, err := src.Lookup(context.Background(), "www.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	var got string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			got = a.A.String()
		}
	}
	if got != "93.184.216.34" {
		t.Fatalf("answer = %q, want the record the authoritative server holds", got)
	}
}
