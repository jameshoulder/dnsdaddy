package recursive_test

import (
	"context"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
)

// brokenChild adds a delegation whose nameserver has no server behind it, so
// resolving anything *in* the child fails while the referral to it is
// perfectly readable from the parent.
//
// This shape is the whole subject of this file. It is not exotic: a lame
// delegation, a child whose servers are firewalled, a zone whose operator let
// the nameserver lapse — all of them produce a cut that exists and a child
// that cannot be reached.
func brokenChild(z *[]reclab.Zone) {
	for i := range *z {
		if (*z)[i].Name == "com." {
			(*z)[i].Delegations["broken.com."] = []string{"ns1.broken.com."}
		}
	}
}

// A zone cut whose child cannot be resolved is still a zone cut.
//
// Until this change the source answered the delegation question out of one
// resolution's observations, and a resolution that failed produced no
// observations — so a broken child made the source decline to answer, and the
// validator fell back to assuming the name was not a cut. It then descended
// into the child's records holding the parent's keys, no signature verified,
// and the answer came back Bogus: an accusation against data that was fine.
//
// The parent's referral was readable the whole time. Asking for it is the fix.
//
// Non-vacuity: remove the DelegationAt fall-through from Source.establish and
// this fails with "no opinion", which is the pre-change behaviour exactly.
func TestADelegationIsEstablishedWhenTheChildCannotBeResolved(t *testing.T) {
	r, _ := hierarchy(t, brokenChild)
	src := recursive.NewSource(r)
	ctx := context.Background()

	// The premise: resolving inside the child really does fail. If this ever
	// starts succeeding the test below is measuring something else.
	if _, err := r.Resolve(ctx, "broken.com.", dns.TypeNS); err == nil {
		t.Fatal("the broken child resolved; the fixture no longer sets up the case under test")
	}

	cuts, ok := src.ZoneCutsFor(ctx, "broken.com.")
	if !ok {
		t.Fatal("no opinion about broken.com., so the validator would fall back to assuming " +
			"it is not a zone cut and report a real delegation Bogus")
	}
	isCut, present := cuts["broken.com."]
	if !present {
		t.Fatal("broken.com. is absent from the map, which the walk reads as 'no idea'")
	}
	if !isCut {
		t.Error("broken.com. reported as NOT a zone cut; com. referred us to it")
	}
}

// The other half, and the one that must stay conservative: a name that is
// genuinely not a cut is reported as such, positively, on the evidence of the
// zone above answering for it authoritatively.
func TestAnOrdinaryNameIsPositivelyNotAZoneCut(t *testing.T) {
	r, _ := hierarchy(t)

	isCut, known := r.DelegationAt(context.Background(), "www.example.com.")
	if !known {
		t.Fatal("no opinion about an ordinary name the resolver can reach")
	}
	if isCut {
		t.Error("www.example.com. reported as a zone cut; nothing delegated it")
	}
}

// A referral the resolver has already crossed needs no second opinion, and
// must not be re-derived by asking the child about itself.
//
// The ordering here is what keeps that true. DelegationAt checks the cache for
// a delegation at the exact name before it probes, so a cut the resolver has
// been referred to is answered from the referral. probeStart's own rule —
// start from the deepest delegation strictly *above* the name — is the second
// line of the same defence: were a probe ever to begin at the name itself, it
// would be asking a zone's own servers whether they are a delegation, and they
// answer authoritatively for their apex and refer nowhere at it. That reads as
// "not a cut" and inverts the answer for every name already in the cache.
func TestACrossedReferralIsReportedWithoutAskingAgain(t *testing.T) {
	r, h := hierarchy(t)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "www.example.com.", dns.TypeA); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	before := len(h.Queries())

	isCut, known := r.DelegationAt(ctx, "example.com.")
	if !known {
		t.Fatal("no opinion about a delegation the resolver has crossed")
	}
	if !isCut {
		t.Error("example.com. reported as NOT a zone cut once the cache was warm")
	}
	if after := len(h.Queries()); after != before {
		t.Errorf("%d questions were sent about a referral already held in the cache",
			after-before)
	}
}

// Establishing a boundary must not hand every ancestor the whole name.
//
// Learn mode's privacy posture rests on QNAME minimisation: the root learns
// the TLD and nothing more. A probe that asked the root about the full name
// would quietly undo that for every delegation it established, which on a
// validating resolver is most names.
func TestTheProbeTellsEachServerOnlyTheNextLabel(t *testing.T) {
	r, h := hierarchy(t)

	if _, known := r.DelegationAt(context.Background(), "www.example.com."); !known {
		t.Fatal("the probe reached no conclusion, so there is nothing to measure")
	}

	for _, q := range h.QueriesTo(".") {
		// "." is the priming query for the root's own NS RRset, which
		// carries no information about what is being looked up.
		if n := dns.CanonicalName(q.Name); n != "com." && n != "." {
			t.Errorf("the root was asked about %q; it only ever needs the TLD", q.Name)
		}
	}
	for _, q := range h.QueriesTo("com.") {
		if dns.CanonicalName(q.Name) != "example.com." {
			t.Errorf("com. was asked about %q; it only ever needs the next label down", q.Name)
		}
	}
}

// An established boundary is remembered, or a validation of a deep name pays
// for a walk per label and a busy resolver re-establishes the same cuts for
// every question.
func TestAnEstablishedBoundaryIsNotReEstablished(t *testing.T) {
	r, h := hierarchy(t)
	ctx := context.Background()

	if _, known := r.DelegationAt(ctx, "www.example.com."); !known {
		t.Fatal("first probe reached no conclusion")
	}
	before := len(h.Queries())

	for i := 0; i < 5; i++ {
		isCut, known := r.DelegationAt(ctx, "www.example.com.")
		if !known || isCut {
			t.Fatalf("repeat %d changed the answer: isCut=%v known=%v", i, isCut, known)
		}
	}
	if after := len(h.Queries()); after != before {
		t.Errorf("%d further questions were sent to establish a boundary already known",
			after-before)
	}
}

// A cancelled context is not evidence.
//
// The caller going away must produce "I could not tell", which lands on the
// walk's existing assumption, rather than a confident answer derived from
// however far the probe happened to get.
//
// Two things enforce this and only one of them is visible here: the exchange
// refuses to send on a cancelled context, and delegationAt re-checks before
// each step. Removing the re-check alone leaves this test passing, because the
// exchange catches the case it covers. The re-check earns its place on the
// step *after* a reply arrives — cancellation during a multi-label walk stops
// the next packet rather than being noticed once it has already gone.
func TestACancelledProbeConcludesNothing(t *testing.T) {
	r, _ := hierarchy(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if isCut, known := r.DelegationAt(ctx, "www.example.com."); known {
		t.Errorf("a cancelled probe reported a conclusion: isCut=%v", isCut)
	}
}

// The root is not a delegation, and saying "not a cut" about it would be a
// claim about a boundary that cannot exist.
func TestTheRootIsNotAnsweredEitherWay(t *testing.T) {
	r, _ := hierarchy(t)

	if _, known := r.DelegationAt(context.Background(), "."); known {
		t.Error("the resolver claimed to know whether the root is a zone cut")
	}
}

// The cut memo is written by probes and read by resolutions on whatever
// goroutine Learn mode's workers happen to be. Run both against one resolver
// and let the race detector look.
func TestTheCutMemoIsSafeUnderConcurrentResolution(t *testing.T) {
	r, _ := hierarchy(t, brokenChild)
	ctx := context.Background()

	names := []string{
		"www.example.com.", "other.example.com.", "example.com.",
		"com.", "broken.com.", "nosuch.example.com.",
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for _, n := range names {
				if i%2 == 0 {
					_, _ = r.DelegationAt(ctx, n)
					continue
				}
				_, _ = r.Resolve(ctx, n, dns.TypeA)
			}
		}(i)
	}
	wg.Wait()
}
