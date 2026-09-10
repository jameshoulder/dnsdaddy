package resolution_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
)

// nativeBackend brings up the signed reference hierarchy as separate
// authoritative servers and points a native backend at its root.
//
// Real sockets, real referrals, real signatures. The zones are the ones
// internal/daddybound/lab signs for every DNSSEC test in this repository.
func nativeBackend(t *testing.T, mutate ...func(*lab.Hierarchy)) *resolution.Native {
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
		// The laboratory lives on loopback. This is the one safety rule a test
		// may relax, and it exists so the rule stays absolute in production.
		AllowNonGlobalTargets: true,
		Exchange:              servers.Exchanger(recursive.NewNetExchanger(2*time.Second, 4096, true)),
		UDPSize:               4096,
	})

	spec := lab.StandardSpec()
	at := spec.Inception.Add(spec.Expiration.Sub(spec.Inception) / 2)
	cfg, err := h.Config(at)
	if err != nil {
		t.Fatalf("lab config: %v", err)
	}
	engine, err := native.New(native.Config{
		Resolver: res, Anchors: cfg.Anchors, Policy: cfg.Policy,
		Clock: cfg.Clock, Verifier: cfg.Verifier, Limits: cfg.Limits,
	})
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}
	b, err := resolution.NewNative(engine, resolution.NativeOptions{})
	if err != nil {
		t.Fatalf("build the backend: %v", err)
	}
	return b
}

// query builds a client question, with DO set when the client is validating.
func query(name string, qtype uint16, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	if do {
		m.SetEdns0(1232, true)
	}
	return m
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// A signed name resolves, validates, and comes back Secure with the answer.
//
// The headline of the milestone, at the seam a client actually reaches: no
// forwarder, no upstream's AD bit, and the verdict is this deployment's own.
func TestASignedNameIsSecureAndTheAnswerIsServed(t *testing.T) {
	b := nativeBackend(t)

	res, err := b.Resolve(ctx(t), query(lab.AnswerName, dns.TypeA, true), 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.DNSSEC != resolution.StatusSecure {
		t.Fatalf("status = %s (%s), want secure", res.DNSSEC, res.DNSSECReason)
	}
	if res.Authority != resolution.AuthorityLocal {
		t.Errorf("authority = %q, want local — a native verdict is this deployment's own",
			res.Authority)
	}
	if res.Backend != resolution.BackendNative {
		t.Errorf("backend = %q, want %q", res.Backend, resolution.BackendNative)
	}
	if len(res.Msg.Answer) == 0 {
		t.Fatal("a secure verdict on an empty answer is meaningless")
	}
	if res.Msg.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[res.Msg.Rcode])
	}
	// The client set DO, so it asked to be told. AD is this resolver's own
	// assertion here, made because it authenticated the records itself.
	if !res.Msg.AuthenticatedData {
		t.Error("AD is clear on a locally validated answer to a client that set DO")
	}
	if res.Queries == 0 {
		t.Error("no authoritative queries were counted; this did not resolve anything")
	}
}

// A client that did not ask must not be told.
//
// RFC 4035 §3.2.3. Setting AD for a client that sent neither DO nor AD tells it
// its answer was authenticated when it never asked us to check — which is
// precisely the assurance the bit is not allowed to give.
func TestADIsNotSetForAClientThatDidNotAsk(t *testing.T) {
	b := nativeBackend(t)

	res, err := b.Resolve(ctx(t), query(lab.AnswerName, dns.TypeA, false), 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.DNSSEC != resolution.StatusSecure {
		t.Fatalf("status = %s, want secure", res.DNSSEC)
	}
	if res.Msg.AuthenticatedData {
		t.Error("AD is set on an answer to a client that asked for neither DO nor AD")
	}
}

// A forged answer is refused. SERVFAIL, no records, and an extended error
// saying why.
//
// The rule that makes validation worth doing. There is no configuration to
// soften it and no fallback to the forwarder — a fallback would mean an
// attacker who forges one answer gets it served anyway, and the validation
// would be theatre.
func TestABogusAnswerIsRefusedRatherThanServed(t *testing.T) {
	b := nativeBackend(t, func(h *lab.Hierarchy) {
		set := h.Set(lab.LeafZone, lab.AnswerName, dns.TypeA)
		tampered := make([]dns.RR, 0, len(set))
		for _, rr := range set {
			if a, ok := rr.(*dns.A); ok {
				forged := *a
				forged.A = netip.MustParseAddr("6.6.6.6").AsSlice()
				tampered = append(tampered, &forged)
				continue
			}
			tampered = append(tampered, rr)
		}
		if err := h.Replace(lab.LeafZone, lab.AnswerName, dns.TypeA, tampered); err != nil {
			t.Fatalf("tamper: %v", err)
		}
	})

	res, err := b.Resolve(ctx(t), query(lab.AnswerName, dns.TypeA, true), 1)
	if err != nil {
		t.Fatalf("resolve returned an error rather than a refusal: %v", err)
	}
	if res.DNSSEC != resolution.StatusBogus {
		t.Fatalf("status = %s (%s), want bogus", res.DNSSEC, res.DNSSECReason)
	}
	if res.Msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL — a forged answer must not reach a client",
			dns.RcodeToString[res.Msg.Rcode])
	}
	for _, rr := range res.Msg.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "6.6.6.6" {
			t.Fatalf("the forged address was served alongside the failure: %s", rr)
		}
	}
	if len(res.Msg.Answer) != 0 {
		t.Errorf("a refused answer carried %d records; it must carry none", len(res.Msg.Answer))
	}
	if res.Msg.AuthenticatedData {
		t.Error("AD is set on a refused answer")
	}
	if code, ok := extendedErrorOf(res.Msg); !ok {
		t.Error("no extended DNS error was attached to a bogus refusal")
	} else if code != dns.ExtendedErrorCodeDNSBogus {
		t.Errorf("extended error = %d, want %d (DNSSEC Bogus)", code, dns.ExtendedErrorCodeDNSBogus)
	}
}

// An unsigned domain is not a DNSSEC failure.
//
// Insecure means an authenticated proof showed the data lies in an unsigned
// part of the namespace. The answer is served, AD is clear, and nothing is
// refused — confusing this with Bogus would take most of the Internet offline.
func TestAnUnsignedDomainIsServedWithoutAD(t *testing.T) {
	b := nativeBackend(t)

	res, err := b.Resolve(ctx(t), query(lab.UnsignedName, dns.TypeA, true), 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.DNSSEC != resolution.StatusInsecure {
		t.Fatalf("status = %s (%s), want insecure", res.DNSSEC, res.DNSSECReason)
	}
	if res.Msg.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR — an unsigned domain resolves normally",
			dns.RcodeToString[res.Msg.Rcode])
	}
	if len(res.Msg.Answer) == 0 {
		t.Error("an unsigned domain returned no answer")
	}
	if res.Msg.AuthenticatedData {
		t.Error("AD is set on an answer that was proved unsigned")
	}
}

// An authenticated NXDOMAIN keeps its rcode.
//
// SetReply would force NOERROR and quietly discard the one thing the denial
// proof established. The reframe used here rewrites only the header and the
// question.
func TestAnAuthenticatedNXDOMAINStaysNXDOMAIN(t *testing.T) {
	b := nativeBackend(t)

	res, err := b.Resolve(ctx(t), query(lab.MissingName, dns.TypeA, true), 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Msg.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[res.Msg.Rcode])
	}
	if res.DNSSEC != resolution.StatusSecure {
		t.Errorf("status = %s (%s), want secure — the denial is signed",
			res.DNSSEC, res.DNSSECReason)
	}
	if !res.Msg.AuthenticatedData {
		t.Error("AD is clear on an authenticated denial to a validating client")
	}
}

// The response is framed onto the client's question, not the resolver's.
func TestTheResponseAnswersTheQuestionTheClientAsked(t *testing.T) {
	b := nativeBackend(t)

	req := query(lab.AnswerName, dns.TypeA, true)
	req.Id = 0x4242
	res, err := b.Resolve(ctx(t), req, 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Msg.Id != req.Id {
		t.Errorf("response id = %d, want the client's %d", res.Msg.Id, req.Id)
	}
	if len(res.Msg.Question) != 1 || res.Msg.Question[0].Name != req.Question[0].Name {
		t.Errorf("response question = %v, want %v", res.Msg.Question, req.Question)
	}
	if !res.Msg.Response {
		t.Error("the response bit is clear")
	}
	if res.Msg.Authoritative {
		t.Error("AA is set; this resolver is not authoritative for the zone")
	}
	if !res.Msg.RecursionAvailable {
		t.Error("RA is clear; a client will think this resolver cannot recurse")
	}
}

// Identical concurrent questions cost one resolution.
//
// Not an optimisation. A recursive miss is several round trips in series
// against servers on the public Internet, so a hundred clients asking the same
// cold question at once would send a hundred walks from the root — a
// self-inflicted load on the root and TLD servers as much as on this box.
func TestIdenticalConcurrentQuestionsCollapseOntoOneResolution(t *testing.T) {
	b := nativeBackend(t)
	c := ctx(t)

	// Held open until every caller is ready, so the questions genuinely
	// overlap. Without it the laboratory answers fast enough that each
	// resolution finishes before the next begins and the test measures
	// nothing.
	const callers = 12
	type outcome struct {
		res resolution.Result
		err error
	}
	results := make(chan outcome, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			r, err := b.Resolve(c, query(lab.AnswerName, dns.TypeA, true), 1)
			results <- outcome{r, err}
		}()
	}
	close(start)

	var did, waited int
	for i := 0; i < callers; i++ {
		got := <-results
		if got.err != nil {
			t.Errorf("resolve: %v", got.err)
			continue
		}
		// Every caller gets the same correct answer, whether it did the work
		// or waited for somebody who did.
		if got.res.DNSSEC != resolution.StatusSecure {
			t.Errorf("status = %s, want secure", got.res.DNSSEC)
		}
		if len(got.res.Msg.Answer) == 0 {
			t.Error("a collapsed caller received no answer")
		}
		if got.res.Collapsed {
			waited++
			// A waiter incurred none of the leader's cost, and reporting the
			// leader's queries against it would multiply the recorded
			// outbound traffic by the size of the burst.
			if got.res.Queries != 0 {
				t.Errorf("a collapsed caller was charged %d queries it never sent", got.res.Queries)
			}
			if got.res.Cached {
				t.Error("a collapsed caller was recorded as a cache hit; it waited on a flight")
			}
		} else {
			did++
		}
	}
	if waited == 0 {
		t.Fatalf("%d concurrent callers for one name and none of them collapsed; "+
			"either the collapsing is not happening or they did not overlap", callers)
	}
	if did > 2 {
		t.Errorf("%d of %d concurrent callers each did their own recursion", did, callers)
	}

	// The window agrees, and keeps the two apart.
	h := b.Health()
	if h.Collapsed == 0 {
		t.Error("the health window recorded no collapsed callers")
	}
	if h.CacheHitRate > 0.5 {
		t.Errorf("cache hit rate is %.2f on a cold cache; collapsed waiters are "+
			"being counted as hits, which inflates the rate during exactly the "+
			"bursts an operator watches", h.CacheHitRate)
	}
}

func extendedErrorOf(msg *dns.Msg) (uint16, bool) {
	opt := msg.IsEdns0()
	if opt == nil {
		return 0, false
	}
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			return ede.InfoCode, true
		}
	}
	return 0, false
}

var _ = strings.TrimSpace
var _ = dnssec.StatusSecure
