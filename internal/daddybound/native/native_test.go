package native_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
)

// engine brings up the signed reference hierarchy as separate authoritative
// servers and points a native engine at its root.
//
// Nothing here is a stub. The zones are the ones internal/daddybound/lab signs
// for every DNSSEC test in this repository; they are served from real UDP and
// TCP sockets, one server per zone, and the resolver reaches the answer by
// being referred downwards exactly as it would be on the Internet.
func engine(t *testing.T, mutate ...func(*lab.Hierarchy)) (*native.Engine, *reclab.Hierarchy, *recursive.Resolver) {
	t.Helper()

	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build the signed hierarchy: %v", err)
	}
	for _, m := range mutate {
		m(h)
	}

	servers := reclab.Signed(t, h)
	res := recursive.New(recursive.Config{
		RootHints: []recursive.RootHint{{
			Name: "ns.",
			Addr: []netip.Addr{servers.Addr(".").Addr()},
		}},
		// The laboratory is on loopback. This is the one safety rule a test
		// may relax, and it exists so the rule stays absolute in production.
		AllowNonGlobalTargets: true,
		Exchange:              servers.Exchanger(recursive.NewNetExchanger(2*time.Second, 4096, true)),
		UDPSize:               4096,
	})

	cfg, err := h.Config(labInstant())
	if err != nil {
		t.Fatalf("lab config: %v", err)
	}
	e, err := native.New(native.Config{
		Resolver: res,
		Anchors:  cfg.Anchors,
		Policy:   cfg.Policy,
		Clock:    cfg.Clock,
		Verifier: cfg.Verifier,
		Limits:   cfg.Limits,
	})
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}
	return e, servers, res
}

// labInstant is a moment inside every signature's validity window.
func labInstant() time.Time {
	s := lab.StandardSpec()
	return s.Inception.Add(s.Expiration.Sub(s.Inception) / 2)
}

// The headline claim of this milestone, tested the only way that means
// anything: no forwarder, no public resolver, no libunbound. The engine is
// given the root's address and nothing else, and it reaches a Secure verdict on
// a name three delegations down by asking the authoritative servers itself.
func TestDaddyboundResolvesAndValidatesFromTheRootWithNoForwarder(t *testing.T) {
	e, servers, res := engine(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ans, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve %s: %v\nlaboratory write errors: %v", lab.AnswerName, err, servers.WriteErrors())
	}
	if ans.Validation.Status != dnssec.StatusSecure {
		t.Fatalf("status = %s (%s), want secure\ntrace:\n%s",
			ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
	}
	if len(ans.Msg.Answer) == 0 {
		t.Fatalf("a secure verdict on an empty answer is meaningless")
	}

	// It got there by being referred, not by asking one server everything.
	if len(ans.Delegations) < 2 {
		t.Errorf("crossed %d zone cuts, want at least root -> %s -> %s: %+v",
			len(ans.Delegations), lab.MiddleZone, lab.LeafZone, ans.Delegations)
	}
	// And it really did talk to each zone's own server.
	for _, zone := range []string{".", lab.MiddleZone, lab.LeafZone} {
		if len(servers.QueriesTo(zone)) == 0 {
			t.Errorf("never asked the servers for %s anything", zone)
		}
	}
	if q := res.Stats().Queries; q == 0 {
		t.Errorf("the resolver counted no outgoing queries")
	}
}

// The property the whole Live mode rests on: what comes back is what was
// checked.
//
// Pinned counts the lookups the validator satisfied from the resolution already
// in hand rather than by asking again. A zero on an answer that had records
// would mean the validator formed its opinion by re-fetching — which is the
// shape of a Live mode that returns one message and validates another, and is
// indistinguishable from the real thing from outside.
func TestTheMessageReturnedIsTheMessageThatWasValidated(t *testing.T) {
	e, _, _ := engine(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ans, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ans.Pinned == 0 {
		t.Fatalf("the validator answered none of its %d lookups from the resolution in hand, "+
			"so the verdict describes a message that was fetched separately", ans.Lookups)
	}
	if ans.Lookups <= ans.Pinned {
		t.Errorf("every lookup was pinned (%d of %d); the chain of trust was never fetched at all",
			ans.Pinned, ans.Lookups)
	}
}

// Insecure has to be reachable and has to mean what RFC 4033 §5 says: the
// parent proved no DS exists. A resolver that reported Insecure for anything it
// could not check would be a resolver whose Secure means nothing.
func TestAnInsecurelyDelegatedZoneIsInsecureAndNotBogus(t *testing.T) {
	e, _, _ := engine(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ans, err := e.Resolve(ctx, lab.UnsignedName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve %s: %v", lab.UnsignedName, err)
	}
	if ans.Validation.Status != dnssec.StatusInsecure {
		t.Errorf("status = %s (%s), want insecure\ntrace:\n%s",
			ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
	}
}

// A forged answer must not authenticate. The signature is left in place and one
// record's data is changed, which is what an on-path attacker does.
func TestATamperedAnswerIsBogusWhenResolvedNatively(t *testing.T) {
	e, _, _ := engine(t, func(h *lab.Hierarchy) {
		set := h.Set(lab.LeafZone, lab.AnswerName, dns.TypeA)
		if len(set) == 0 {
			t.Fatalf("the reference hierarchy has no A record at %s to tamper with", lab.AnswerName)
		}
		tampered := make([]dns.RR, 0, len(set))
		for _, rr := range set {
			if a, ok := rr.(*dns.A); ok {
				forged := *a
				forged.A = net4("6.6.6.6")
				tampered = append(tampered, &forged)
				continue
			}
			tampered = append(tampered, rr)
		}
		if err := h.Replace(lab.LeafZone, lab.AnswerName, dns.TypeA, tampered); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ans, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ans.Validation.Status != dnssec.StatusBogus {
		t.Fatalf("a forged address validated as %s (%s), want bogus\ntrace:\n%s",
			ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
	}
}

// A name that does not exist is an authenticated denial, not a failure. NXDOMAIN
// with a Secure verdict is the proof; NXDOMAIN with no verdict is a server's
// unsupported word for it.
func TestAnAuthenticatedDenialIsSecure(t *testing.T) {
	e, _, _ := engine(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ans, err := e.Resolve(ctx, lab.MissingName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve %s: %v", lab.MissingName, err)
	}
	if ans.Msg.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[ans.Msg.Rcode])
	}
	if ans.Validation.Status != dnssec.StatusSecure {
		t.Errorf("status = %s (%s), want secure — the denial is signed\ntrace:\n%s",
			ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
	}
}

// A resolution failure is an error, never a verdict.
//
// "I could not reach the servers for this zone" and "this zone's data does not
// authenticate" are statements about different things, and an engine that
// returned the second when the first happened would let anyone manufacture a
// security state by dropping packets.
func TestAnUnreachableZoneIsAnErrorRatherThanAVerdict(t *testing.T) {
	e, _, _ := engine(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	cancel() // already dead: nothing can be reached

	ans, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA)
	if err == nil {
		t.Fatalf("a resolution with no network returned a verdict of %s instead of an error",
			ans.Validation.Status)
	}
	if ans != nil {
		t.Errorf("an error came back with an answer attached: %+v", ans)
	}
}

func net4(s string) []byte {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	b := a.As4()
	return b[:]
}

// The second query for a name must reach the same verdict as the first.
//
// It did not. A resolution that starts from a cached delegation crosses no zone
// cuts, and the delegation evidence added in the previous slice read that
// silence as "there are no zone cuts here" — so from the second query onwards
// the validator walked down the tree using the root's keys and reported a
// correctly signed answer Bogus. The first query was right, which is exactly
// how it survived a review: every test that resolved a name once passed.
//
// Two queries, therefore, and the same name deliberately: one warm cache is
// the whole point.
func TestAWarmCacheDoesNotTurnASecureAnswerBogus(t *testing.T) {
	e, _, res := engine(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for attempt := 1; attempt <= 3; attempt++ {
		ans, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA)
		if err != nil {
			t.Fatalf("attempt %d: resolve: %v", attempt, err)
		}
		if ans.Validation.Status != dnssec.StatusSecure {
			t.Fatalf("attempt %d: status = %s (%s), want secure — the cache changed the verdict\ntrace:\n%s",
				attempt, ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
		}
	}
	if h := res.CacheStats(); h.Hits == 0 {
		t.Errorf("three resolutions of one name produced no cache hits (%+v), "+
			"so this test never exercised a warm cache", h)
	}
}

// A DS RRset lives in the parent zone and nowhere else.
//
// Asking the child for its own DS gets an honest NODATA carrying the child's
// own signed denial — which, read from the parent's zone, is a denial signed by
// the wrong keys and looks like an unsigned delegation. The resolver reached
// exactly that state once its cache held a delegation for the name, because the
// cached cut was where it started the walk.
//
// The check is on the verdict rather than on the packets, because the verdict
// is what an operator sees and what Live mode would act on.
func TestADelegationSigningKeyIsSoughtFromTheParent(t *testing.T) {
	e, _, _ := engine(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Warm the cache with the delegation, so the DS query below starts from a
	// cached cut rather than from the root — the case that failed.
	if _, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA); err != nil {
		t.Fatalf("warm-up resolve: %v", err)
	}

	for _, zone := range []string{lab.MiddleZone, lab.LeafZone} {
		ans, err := e.Resolve(ctx, zone, dns.TypeDS)
		if err != nil {
			t.Fatalf("resolve %s DS: %v", zone, err)
		}
		var got int
		for _, rr := range ans.Msg.Answer {
			if _, ok := rr.(*dns.DS); ok {
				got++
			}
		}
		if got == 0 {
			t.Errorf("%s DS came back with no DS record; the child was asked for its own delegation signer\nanswer: %v",
				zone, ans.Msg.Answer)
		}
		if ans.Validation.Status != dnssec.StatusSecure {
			t.Errorf("%s DS validated as %s (%s), want secure\ntrace:\n%s",
				zone, ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
		}
	}
}
