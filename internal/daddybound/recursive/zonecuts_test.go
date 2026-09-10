package recursive_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
)

// signedResolver points a resolver at the reference signed hierarchy, one
// authoritative server per zone.
func signedResolver(t *testing.T) (*recursive.Resolver, *reclab.Hierarchy) {
	t.Helper()

	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build the signed hierarchy: %v", err)
	}
	servers := reclab.Signed(t, h)
	return recursive.New(recursive.Config{
		RootHints: []recursive.RootHint{{
			Name: "ns.",
			Addr: []netip.Addr{servers.Addr(".").Addr()},
		}},
		AllowNonGlobalTargets: true,
		Exchange:              servers.Exchanger(recursive.NewNetExchanger(2*time.Second, 4096, true)),
		UDPSize:               4096,
	}), servers
}

// What the resolver knows about zone cuts must not decay as its cache warms.
//
// A resolution that begins at a cached delegation crosses no zone cuts, so it
// observes none. Reading that silence as "there are no zone cuts here" inverted
// this function's answer on the second query for any name: every cut under it
// came back reported as *not* a cut, which is the one answer that lets a
// validator authenticate a child zone's records against its parent's keys.
//
// The distinction the fix rests on is between two kinds of statement. A
// positive — "this is a cut" — may come from a referral crossed now or from one
// crossed earlier and still in the cache, because both are observations. A
// negative may only be made about names the resolver actually walked through,
// which means at or below where the walk began.
func TestZoneCutsAreStillCutsOnceTheCacheIsWarm(t *testing.T) {
	r, _ := signedResolver(t)
	src := recursive.NewSource(r)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Warm the cache: after this the delegations are known and a resolution
	// for the same name starts below the root.
	if _, err := r.Resolve(ctx, lab.AnswerName, dns.TypeA); err != nil {
		t.Fatalf("warm-up: %v", err)
	}

	for attempt := 1; attempt <= 3; attempt++ {
		cuts, ok := src.ZoneCutsFor(ctx, lab.AnswerName)
		if !ok {
			t.Fatalf("attempt %d: the resolver reported no opinion about %s", attempt, lab.AnswerName)
		}
		for _, cut := range []string{lab.MiddleZone, lab.LeafZone} {
			isCut, known := cuts[cut]
			if !known {
				t.Errorf("attempt %d: no opinion about %s, which the resolver has been referred to", attempt, cut)
				continue
			}
			if !isCut {
				t.Errorf("attempt %d: %s reported as NOT a zone cut; the walk was referred there\nfull map: %v",
					attempt, cut, cuts)
			}
		}
		// And the negative half still works: the queried name itself is not a
		// zone cut, and saying so is the point of the whole mechanism.
		if isCut, known := cuts[dns.CanonicalName(lab.AnswerName)]; !known || isCut {
			t.Errorf("attempt %d: %s should be known not to be a zone cut, got (%v, known=%v)",
				attempt, lab.AnswerName, isCut, known)
		}
	}
}

// The resolver must never claim a name above where it started is not a cut.
//
// Starting below the root is normal — it is what a cache is for — and the names
// above the starting point were not walked. "I did not look" is not "there is
// nothing there", and the map must say so by having no entry rather than a
// false one.
func TestNothingIsClaimedAboutNamesTheWalkNeverReached(t *testing.T) {
	r, _ := signedResolver(t)
	src := recursive.NewSource(r)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := r.Resolve(ctx, lab.AnswerName, dns.TypeA); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	// Flush only the answers, keeping the delegations, then ask about a name
	// under the deepest cut. The walk starts at that cut and never sees the
	// root or the middle zone.
	cuts, ok := src.ZoneCutsFor(ctx, "another."+lab.LeafZone)
	if !ok {
		t.Fatalf("no opinion at all")
	}
	for name, isCut := range cuts {
		if isCut {
			continue
		}
		// A false must only ever appear at or below the deepest known cut.
		if !dns.IsSubDomain(lab.LeafZone, name) {
			t.Errorf("%s is claimed not to be a zone cut, but it sits above the deepest cut "+
				"the resolver knows (%s) and was never walked\nfull map: %v",
				name, lab.LeafZone, cuts)
		}
	}
}
