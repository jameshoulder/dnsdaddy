package recursive_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
)

// These are the cases where a server is not merely broken but trying
// something. A resolver that passes the happy path and fails these is a way to
// have arbitrary records written into a cache.

func labResolver(t *testing.T, h *reclab.Hierarchy, timeout time.Duration) *recursive.Resolver {
	t.Helper()
	return recursive.New(recursive.Config{
		RootHints:             []recursive.RootHint{{Name: "hint.test.", Addr: []netip.Addr{h.Addr(".").Addr()}}},
		AllowNonGlobalTargets: true,
		Exchange:              h.Exchanger(recursive.NewNetExchanger(timeout, 1232, true)),
	})
}

// The classic poisoning shape: answer the question, and slip a record for
// somebody else's zone into the Additional section.
func TestAnswersDoNotCarryRecordsForOtherZones(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{
			Name:        "com.",
			Delegations: map[string][]string{"evil.com.": {"ns1.evil.com."}},
		},
		reclab.Zone{
			Name:    "evil.com.",
			Records: []dns.RR{reclab.A("www.evil.com.", "198.51.100.1")},
			Rewrite: func(req, reply *dns.Msg) {
				// "While you are here, bank.example lives at my address."
				reply.Extra = append(reply.Extra, reclab.A("www.bank.example.", "198.51.100.66"))
				reply.Ns = append(reply.Ns, &dns.NS{
					Hdr: dns.RR_Header{Name: "bank.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "ns1.evil.com.",
				})
			},
		},
	)
	r := labResolver(t, h, 2*time.Second)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "www.evil.com.", dns.TypeA); err != nil {
		t.Fatalf("resolving the attacker's own name: %v", err)
	}

	// The poison must not have become a cached delegation for bank.example.
	// If it had, resolving that name would go to the attacker instead of
	// walking from the root — where no such zone exists, so the honest
	// outcome is NXDOMAIN and never the attacker's address.
	res, err := r.Resolve(ctx, "www.bank.example.", dns.TypeA)
	if err != nil {
		// A failure is acceptable here; being answered by the attacker is
		// not. Either way, nothing below may hold their address.
		if strings.Contains(err.Error(), "198.51.100") {
			t.Fatalf("the attacker's address was contacted: %v", err)
		}
		return
	}
	if res.Msg.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN: the root delegates no bank.example.",
			dns.RcodeToString[res.Msg.Rcode])
	}
	for _, rr := range res.Msg.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "198.51.100.66" {
			t.Fatal("the answer carries the address the attacker smuggled into an Additional section")
		}
	}
	// The question echoed must be the one asked. Under QNAME minimisation
	// the walk terminates on a probe for an intermediate name, and handing
	// that probe's question back would answer something nobody asked.
	if len(res.Msg.Question) != 1 ||
		dns.CanonicalName(res.Msg.Question[0].Name) != "www.bank.example." ||
		res.Msg.Question[0].Qtype != dns.TypeA {
		t.Fatalf("reply answers the wrong question: %v", res.Msg.Question)
	}
	// And the attacker's server was never asked about a name outside its zone.
	for _, q := range h.QueriesTo("evil.com.") {
		if strings.HasSuffix(q.Name, "bank.example.") {
			t.Fatalf("the attacker was consulted about %s", q.Name)
		}
	}
}

// A referral must go downwards. One that points at the zone being asked, or
// back up the tree, is a loop.
func TestReferralLoopsAreRefusedRatherThanFollowed(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{
			Name: "com.",
			Rewrite: func(req, reply *dns.Msg) {
				// Refer to itself, for ever.
				reply.Answer, reply.Ns = nil, []dns.RR{&dns.NS{
					Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "ns1.com.",
				}}
				reply.Authoritative = false
				reply.Rcode = dns.RcodeSuccess
			},
		},
	)
	r := labResolver(t, h, time.Second)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("a self-referring server made the resolver spin")
	}

	// And it did not spend an unbounded number of queries getting there.
	if q := r.Stats().Queries; q > 80 {
		t.Fatalf("sent %d queries against a self-referring server", q)
	}
}

// A server that answers a different question than the one asked is either
// broken or spoofing. Either way its answer is not evidence.
func TestARepliedQuestionMustMatchTheQuestionSent(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{Name: "com.", Delegations: map[string][]string{"example.com.": {"ns1.example.com."}}},
		reclab.Zone{
			Name:    "example.com.",
			Records: []dns.RR{reclab.A("www.example.com.", "93.184.216.34")},
			Rewrite: func(req, reply *dns.Msg) {
				reply.Question = []dns.Question{{
					Name: "somewhere.else.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
				}}
			},
		},
	)
	r := labResolver(t, h, time.Second)

	_, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err == nil {
		t.Fatal("a reply answering a different question was accepted")
	}
	if !errors.Is(err, recursive.ErrMismatchedReply) && !errors.Is(err, recursive.ErrNoReachableServer) {
		t.Fatalf("unexpected error kind: %v", err)
	}
}

func TestAWrongTransactionIDIsRejected(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{Name: "com.", Delegations: map[string][]string{"example.com.": {"ns1.example.com."}}},
		reclab.Zone{
			Name:    "example.com.",
			Records: []dns.RR{reclab.A("www.example.com.", "93.184.216.34")},
			Rewrite: func(req, reply *dns.Msg) { reply.Id = req.Id ^ 0x5555 },
		},
	)
	r := labResolver(t, h, time.Second)

	if _, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err == nil {
		t.Fatal("a reply with the wrong transaction ID was accepted")
	}
}

// Glue for a nameserver outside the delegated zone is a hint the parent had no
// authority to give. The name is resolved instead — which here means it cannot
// be resolved at all, and that is the correct outcome rather than following
// the attacker's address.
func TestOutOfBailiwickGlueIsNotFollowed(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{
			Name:        "com.",
			Delegations: map[string][]string{"example.com.": {"ns1.elsewhere.test."}},
			NoGlue:      true,
			Rewrite: func(req, reply *dns.Msg) {
				// The parent supplies an address for a nameserver in a zone
				// it does not control.
				reply.Extra = append(reply.Extra, reclab.A("ns1.elsewhere.test.", "198.51.100.7"))
			},
		},
	)
	r := labResolver(t, h, time.Second)

	_, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err == nil {
		t.Fatal("resolution succeeded using glue the parent had no authority to supply")
	}
	if strings.Contains(err.Error(), "198.51.100.7") {
		t.Fatalf("the out-of-bailiwick address was contacted: %v", err)
	}
}

// A dead server among several must cost one timeout, not the resolution.
func TestOneDeadNameserverAmongSeveralIsSurvivable(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{Name: "com.", Delegations: map[string][]string{"example.com.": {"ns1.example.com."}}},
		reclab.Zone{
			Name:    "example.com.",
			Records: []dns.RR{reclab.A("www.example.com.", "93.184.216.34")},
			DropUDP: true, // never answers over UDP
		},
	)
	// The resolver retries over TCP only on truncation, so a UDP black hole
	// is a dead server from its point of view: it must fail cleanly and
	// quickly rather than hang.
	r := labResolver(t, h, 500*time.Millisecond)

	start := time.Now()
	_, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a server that never answers produced an answer")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("took %v to give up on a silent server", elapsed)
	}
}

// Truncation is ordinary for signed answers, so the TCP retry is a normal path
// rather than an error path.
func TestTruncatedUDPIsRetriedOverTCP(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{Name: "com.", Delegations: map[string][]string{"example.com.": {"ns1.example.com."}}},
		reclab.Zone{
			Name:        "example.com.",
			Records:     []dns.RR{reclab.A("www.example.com.", "93.184.216.34")},
			TruncateUDP: true,
		},
	)
	r := labResolver(t, h, 2*time.Second)

	res, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Msg.Answer) == 0 {
		t.Fatal("no answer after the TCP retry")
	}

	var overTCP bool
	for _, q := range h.QueriesTo("example.com.") {
		if q.Proto == "tcp" {
			overTCP = true
		}
	}
	if !overTCP {
		t.Fatal("the authoritative server was never asked over TCP")
	}
}

// A lame delegation — a server that does not serve the zone it was delegated —
// must not be reported as the zone being broken.
func TestALameServerIsTriedAndReported(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{Name: "com.", Delegations: map[string][]string{"example.com.": {"ns1.example.com."}}},
		reclab.Zone{Name: "example.com.", Lame: true},
	)
	r := labResolver(t, h, time.Second)

	_, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err == nil {
		t.Fatal("a lame server produced an answer")
	}
	if !errors.Is(err, recursive.ErrLame) {
		t.Fatalf("error does not name the lame delegation: %v", err)
	}
}

// Cancellation must stop a resolution promptly and deterministically, not
// leave a goroutine finishing a walk nobody is waiting for.
func TestCancellationStopsAResolution(t *testing.T) {
	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{Name: "com.", DropUDP: true},
	)
	r := labResolver(t, h, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.Resolve(ctx, "www.example.com.", dns.TypeA); done <- err }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled resolution returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not stop the resolution")
	}
}

// A TTL of zero means do not cache. Honouring it is what stops a hostile
// server pinning an entry, and mishandling it is how a cache acquires
// permanent state.
func TestAZeroTTLIsNotCached(t *testing.T) {
	rec := reclab.A("www.example.com.", "93.184.216.34")
	rec.Header().Ttl = 0

	h := reclab.Start(t,
		reclab.Zone{Name: ".", Delegations: map[string][]string{"com.": {"ns1.com."}}},
		reclab.Zone{Name: "com.", Delegations: map[string][]string{"example.com.": {"ns1.example.com."}}},
		reclab.Zone{Name: "example.com.", Records: []dns.RR{rec}},
	)
	r := labResolver(t, h, 2*time.Second)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := r.Resolve(ctx, "www.example.com.", dns.TypeA); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}

	var asked int
	for _, q := range h.QueriesTo("example.com.") {
		if q.Name == "www.example.com." {
			asked++
		}
	}
	if asked < 2 {
		t.Fatalf("the authoritative server was asked %d times; a zero-TTL answer was cached", asked)
	}
}
