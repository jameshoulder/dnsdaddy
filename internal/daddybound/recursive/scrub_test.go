package recursive_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
)

// rewriteZone installs a Rewrite hook on one zone of the standard hierarchy.
func rewriteZone(name string, f func(req, reply *dns.Msg)) func(*[]reclab.Zone) {
	return func(z *[]reclab.Zone) {
		for i := range *z {
			if (*z)[i].Name == name {
				(*z)[i].Rewrite = f
			}
		}
	}
}

// A server may say what it likes about its own zone and nothing about anyone
// else's. This is the oldest cache-poisoning attack in DNS and it needs no
// spoofing: the resolver chose to talk to this server, and the server simply
// answered with more than it was asked.
//
// Before the message-level scrub existed, example.com's server could attach an
// A record for bank.co.uk to an ordinary answer and the resolver handed it
// straight back to the caller. Deleting scrub in bailiwick.go fails this test
// with the smuggled address in the message.
func TestAServerCannotSmuggleRecordsAboutZonesItDoesNotHold(t *testing.T) {
	r, _ := hierarchy(t, rewriteZone("example.com.", func(req, reply *dns.Msg) {
		if len(req.Question) == 0 {
			return
		}
		// One in every section, because "which section was it in?" must not
		// be the thing that decides whether a forged record is believed.
		reply.Answer = append(reply.Answer, reclab.A("bank.co.uk.", "6.6.6.6"))
		reply.Ns = append(reply.Ns, reclab.A("bank.co.uk.", "6.6.6.7"))
		reply.Extra = append(reply.Extra, reclab.A("bank.co.uk.", "6.6.6.8"))
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "www.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, section := range [][]dns.RR{res.Msg.Answer, res.Msg.Ns, res.Msg.Extra} {
		for _, rr := range section {
			if strings.Contains(rr.Header().Name, "bank.co.uk") {
				t.Errorf("a record about bank.co.uk survived a reply from example.com's server: %s", rr)
			}
		}
	}
	// The genuine answer is still there: the scrub removes what the server
	// had no right to say, not the answer it was asked for.
	if len(res.Msg.Answer) != 1 {
		t.Fatalf("want the one real answer record, got %d: %v", len(res.Msg.Answer), res.Msg.Answer)
	}
	if got := res.Msg.Answer[0].(*dns.A).A.String(); got != "93.184.216.34" {
		t.Errorf("answer address = %s, want 93.184.216.34", got)
	}
	// And the defence is visible rather than silent.
	if n := r.Stats().Scrubbed; n < 3 {
		t.Errorf("Stats().Scrubbed = %d, want at least the 3 forged records", n)
	}
}

// The dangerous version of the same attack: an out-of-zone CNAME target whose
// address the answering server helpfully supplies.
//
// resolveOnce stops following a CNAME when the reply already carries the
// requested type for the target. That shortcut is right when the target lives
// in the same zone and is a forgery when it does not, so the scrub has to run
// before the shortcut is evaluated — otherwise example.com decides what
// attacker.test resolves to.
func TestAnOutOfZoneCNAMETargetIsResolvedRatherThanBelieved(t *testing.T) {
	r, h := hierarchy(t, func(z *[]reclab.Zone) {
		for i := range *z {
			if (*z)[i].Name == "example.com." {
				(*z)[i].Records = append((*z)[i].Records,
					reclab.CNAME("alias.example.com.", "www.example.com."))
				(*z)[i].Rewrite = func(req, reply *dns.Msg) {
					if len(req.Question) == 0 || req.Question[0].Name != "alias.example.com." {
						return
					}
					// Rewrite the alias to point out of zone, and answer the
					// target ourselves.
					reply.Answer = []dns.RR{
						reclab.CNAME("alias.example.com.", "victim.bank.co.uk."),
						reclab.A("victim.bank.co.uk.", "6.6.6.6"),
					}
				}
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "alias.example.com.", dns.TypeA)
	// The target is in a zone the laboratory does not serve, so the honest
	// outcome is a failure to resolve it. What must not happen is success
	// carrying the address example.com invented.
	if err == nil {
		for _, rr := range res.Msg.Answer {
			if a, ok := rr.(*dns.A); ok && a.A.String() == "6.6.6.6" {
				t.Fatalf("example.com's server decided what victim.bank.co.uk resolves to: %s", rr)
			}
		}
	}
	// It must have gone looking for the real answer rather than taking the
	// one it was handed: the walk restarts from the root for the new zone.
	var askedAboutTheTarget bool
	for _, q := range h.Queries() {
		if strings.HasSuffix(q.Name, "co.uk.") || q.Name == "uk." || q.Name == "co.uk." {
			askedAboutTheTarget = true
		}
	}
	if !askedAboutTheTarget {
		t.Errorf("the resolver never tried to resolve the out-of-zone target itself; queries:\n%s",
			formatQueries(h.Queries()))
	}
}

// A zone holds many names and may publish aliases for all of them. Only the
// chain the client asked about belongs in the client's answer.
//
// The first version of the splice took every CNAME and DNAME in the reply,
// which meant a resolution for one name could return aliases for others —
// presented, in Live mode, as part of that client's own answer.
func TestOnlyTheAliasChainTheClientAskedAboutIsSpliced(t *testing.T) {
	r, _ := hierarchy(t, func(z *[]reclab.Zone) {
		for i := range *z {
			if (*z)[i].Name == "example.com." {
				(*z)[i].Records = append((*z)[i].Records,
					reclab.CNAME("alias.example.com.", "www.example.com."))
				(*z)[i].Rewrite = func(req, reply *dns.Msg) {
					if len(req.Question) == 0 || req.Question[0].Name != "alias.example.com." {
						return
					}
					// An alias for a name nobody asked about, in the same
					// zone so the bailiwick rule permits it.
					reply.Answer = append(reply.Answer,
						reclab.CNAME("unrelated.example.com.", "elsewhere.example.com."))
				}
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "alias.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, rr := range res.Msg.Answer {
		if c, ok := rr.(*dns.CNAME); ok && c.Hdr.Name == "unrelated.example.com." {
			t.Errorf("an alias for a name the client never asked about was spliced into its answer: %s", rr)
		}
	}
	// The chain that was asked for survives, alias first then address.
	if len(res.Msg.Answer) != 2 {
		t.Fatalf("want CNAME then A, got %d records: %v", len(res.Msg.Answer), res.Msg.Answer)
	}
	if _, ok := res.Msg.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("first answer record = %s, want the CNAME the client asked about", res.Msg.Answer[0])
	}
}

// One Resolver, several goroutines. This is not a hypothetical arrangement: it
// is how Learn mode runs, and it is the point of a shared cache and a single
// priming state.
//
// Run with -race. Before the counters were atomic this failed immediately with
// two workers writing Stats.Queries.
func TestOneResolverServesConcurrentCallersWithoutRacing(t *testing.T) {
	r, _ := hierarchy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	names := []string{"www.example.com.", "other.example.com.", "absent.example.com."}
	const workers, each = 8, 15

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if _, err := r.Resolve(ctx, names[(i+j)%len(names)], dns.TypeA); err != nil {
					// absent.example.com is a legitimate NXDOMAIN, which is
					// not an error; anything else is worth failing on, but
					// only after every goroutine has finished.
					t.Errorf("resolve %s: %v", names[(i+j)%len(names)], err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	// A snapshot taken while nothing else is running must be internally
	// consistent: every question either got a reply or was counted a failure.
	s := r.Stats()
	if s.Queries == 0 {
		t.Fatalf("no queries were counted: %+v", s)
	}
	if s.CacheHits == 0 {
		t.Errorf("%d resolutions of %d names produced no cache hits: %+v",
			workers*each, len(names), s)
	}
}

// A trailing helper rather than an anonymous loop, so the failure messages
// above stay readable.
func formatQueries(qs []reclab.Query) string {
	var b strings.Builder
	for _, q := range qs {
		b.WriteString("  " + q.String() + "\n")
	}
	return b.String()
}

// A signed alias must keep the signature that covers it.
//
// The splice that builds an aliased answer originally took only CNAME and
// DNAME records, which quietly dropped the RRSIGs over them. A validator
// handed that message sees a CNAME in a signed zone with no signature — the
// exact shape of a stripped one — so a correctly signed chain would be
// reported Bogus and the resolver's own splice would be the forgery.
//
// The signature here does not have to verify. What is being tested is whether
// the record survives the journey from the authoritative reply to the answer.
func TestASignedAliasKeepsTheSignatureThatCoversIt(t *testing.T) {
	sig, err := dns.NewRR("alias.example.com. 3600 IN RRSIG CNAME 13 3 3600 " +
		"20990101000000 20200101000000 12345 example.com. " +
		"aGVsbG8gdGhpcyBpcyBub3QgYSByZWFsIHNpZ25hdHVyZQ==")
	if err != nil {
		t.Fatalf("build the signature: %v", err)
	}

	r, _ := hierarchy(t, func(z *[]reclab.Zone) {
		for i := range *z {
			if (*z)[i].Name == "example.com." {
				(*z)[i].Records = append((*z)[i].Records,
					reclab.CNAME("alias.example.com.", "www.example.com."))
				(*z)[i].Rewrite = func(req, reply *dns.Msg) {
					if len(req.Question) == 0 || req.Question[0].Name != "alias.example.com." {
						return
					}
					reply.Answer = append(reply.Answer, sig)
				}
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "alias.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var kept bool
	for _, rr := range res.Msg.Answer {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeCNAME {
			kept = true
		}
	}
	if !kept {
		t.Errorf("the RRSIG over the alias was dropped by the splice; answer was:\n%v", res.Msg.Answer)
	}
}

// The chain records which servers answered which link, because the splice
// destroys that. Live mode needs it to prove the message it returns is the
// message that was validated rather than a second fetch that agreed.
func TestAnAliasedAnswerRecordsEveryHopItWasBuiltFrom(t *testing.T) {
	r, _ := hierarchy(t, func(z *[]reclab.Zone) {
		for i := range *z {
			if (*z)[i].Name == "example.com." {
				(*z)[i].Records = append((*z)[i].Records,
					reclab.CNAME("alias.example.com.", "www.example.com."))
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := r.Resolve(ctx, "alias.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Chain) != 2 {
		t.Fatalf("want one hop per link of alias -> www, got %d: %+v", len(res.Chain), res.Chain)
	}
	if res.Chain[0].QName != "alias.example.com." || res.Chain[1].QName != "www.example.com." {
		t.Errorf("chain is %s then %s, want alias.example.com. then www.example.com.",
			res.Chain[0].QName, res.Chain[1].QName)
	}
	for i, hop := range res.Chain {
		if hop.Msg == nil {
			t.Errorf("hop %d (%s) carries no reply", i, hop.QName)
		}
	}

	// An unaliased name is one hop, not zero: every answer has a provenance.
	plain, err := r.Resolve(ctx, "other.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(plain.Chain) != 1 {
		t.Errorf("an unaliased answer has %d hops, want exactly 1", len(plain.Chain))
	}
}
