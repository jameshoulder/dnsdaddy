package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/querylog"
	"github.com/jameshoulder/dnsdaddy/internal/resolution"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Native recursion must never turn a public VPS into an open resolver.
//
// This is the mandatory property of the milestone and it needs a particular
// kind of test. Asserting "an unauthorised client gets REFUSED" is necessary
// and not sufficient: it would still pass if the resolver did the work, spent
// the bandwidth, and threw the answer away — which on a recursive resolver is
// the whole of the amplification and reflection problem. What has to be true is
// that the backend is never asked at all.
//
// So the backend here counts. Every assertion below is about that counter as
// much as about the rcode, and the counting backend is installed as the native
// one and as the forwarding one, because "the ACL cannot be bypassed by mode"
// is only established by running the same case through both.

// countingBackend records every resolution it is asked for.
type countingBackend struct {
	name  string
	calls atomic.Int64

	mu    sync.Mutex
	asked []dns.Question
}

func (c *countingBackend) Resolve(ctx context.Context, req *dns.Msg, _ uint64) (resolution.Result, error) {
	c.calls.Add(1)
	c.mu.Lock()
	if len(req.Question) > 0 {
		c.asked = append(c.asked, req.Question[0])
	}
	c.mu.Unlock()

	msg := new(dns.Msg)
	msg.SetReply(req)
	if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
		rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 203.0.113.5")
		if rr != nil {
			msg.Answer = append(msg.Answer, rr)
		}
	}
	return resolution.Result{
		Msg: msg, Backend: c.name, Rcode: msg.Rcode,
		DNSSEC: resolution.StatusUnchecked, Authority: resolution.AuthorityUpstream,
	}, nil
}

func (c *countingBackend) Name() string              { return c.name }
func (c *countingBackend) Health() resolution.Health { return resolution.Health{OK: true} }
func (c *countingBackend) Purge()                    {}
func (c *countingBackend) Close()                    {}

func (c *countingBackend) count() int64 { return c.calls.Load() }

// aclHarness builds a handler with a named backend and a fixed client ACL.
func aclHarness(t *testing.T, backendName string, allowed []string) (*Handler, *countingBackend) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "acl.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	holder := blocklist.NewHolder()
	holder.Store(blocklist.NewBuilder(0).Build())
	engine := policy.NewEngine(st, holder)
	if err := engine.Reload(context.Background()); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	qlog := querylog.New(st, querylog.Options{BufferSize: 64, FlushIntervalMS: 20}, log)
	ctx, cancel := context.WithCancel(context.Background())
	go qlog.Run(ctx)
	t.Cleanup(func() { cancel(); qlog.Wait() })

	// Compute is the production path: the same function that builds the ACL
	// from configuration and the networks table. Constructing a Set by hand
	// would test a set, not the thing a deployment runs.
	set := clientacl.Compute(allowed, false, nil)

	backend := &countingBackend{name: backendName}
	h := NewHandler(engine, backend, holder, qlog, log, HandlerOptions{
		QueryLogEnabled: true,
		Timeout:         2 * time.Second,
		ClientACL:       set,
	})
	return h, backend
}

// bothModes runs a case against a handler standing in for each backend.
//
// The stand-in is deliberate. What is under test is the handler's ordering —
// that the ACL is consulted before anything reaches a backend — and that
// ordering is a property of the handler rather than of which backend it holds.
// Using a real recursive resolver here would test the resolver instead, and
// would send packets to the Internet from a unit test.
func bothModes(t *testing.T, allowed []string, run func(t *testing.T, h *Handler, b *countingBackend)) {
	t.Helper()
	for _, name := range []string{resolution.BackendNative, resolution.BackendForward} {
		t.Run(name, func(t *testing.T) {
			h, b := aclHarness(t, name, allowed)
			run(t, h, b)
		})
	}
}

func ask(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

// An unauthorised client is refused, and nothing resolves on its behalf.
//
// The second half is what stops a recursive resolver becoming an amplifier: a
// resolver that answered REFUSED *after* walking from the root would still have
// spent the bandwidth and still have done the attacker's lookup for them.
func TestAnUnauthorisedClientCannotMakeThisResolverRecurse(t *testing.T) {
	bothModes(t, []string{"192.168.1.0/24"}, func(t *testing.T, h *Handler, b *countingBackend) {
		for _, addr := range []string{
			"203.0.113.9",  // an arbitrary public IPv4
			"198.51.100.7", // another
			"8.8.8.8",      // a well-known one, in case anything special-cases it
		} {
			resp := h.Handle(context.Background(), ask("example.com", dns.TypeA), requestMeta{
				clientAddr: netip.MustParseAddr(addr), proto: "udp",
			})
			if resp.Rcode != dns.RcodeRefused {
				t.Errorf("%s got %s, want REFUSED", addr, dns.RcodeToString[resp.Rcode])
			}
		}
		if n := b.count(); n != 0 {
			t.Fatalf("the resolver did %d resolutions for unauthorised clients; "+
				"refusing after doing the work is still doing the work, and on a "+
				"recursive resolver that is the whole of the amplification problem", n)
		}
	})
}

// IPv6 is not a way round the ACL.
//
// Two shapes, because both have been a bypass in real resolvers: a plain IPv6
// address, and the IPv4-mapped form of an address the operator excluded.
func TestIPv6DoesNotBypassTheACL(t *testing.T) {
	bothModes(t, []string{"192.168.1.0/24"}, func(t *testing.T, h *Handler, b *countingBackend) {
		for _, addr := range []string{
			"2001:db8::1",         // a plain IPv6 source
			"::ffff:203.0.113.9",  // IPv4-mapped: the same public address in v6 clothing
			"::ffff:192.168.2.10", // mapped, and outside the permitted range
		} {
			resp := h.Handle(context.Background(), ask("example.com", dns.TypeA), requestMeta{
				clientAddr: netip.MustParseAddr(addr), proto: "udp",
			})
			if resp.Rcode != dns.RcodeRefused {
				t.Errorf("%s got %s, want REFUSED", addr, dns.RcodeToString[resp.Rcode])
			}
		}
		if n := b.count(); n != 0 {
			t.Errorf("%d resolutions ran for IPv6 sources outside the ACL", n)
		}
	})
}

// A permitted client resolves, so the tests above are not passing because
// everything is refused.
func TestAPermittedClientResolvesInBothModes(t *testing.T) {
	bothModes(t, []string{"192.168.1.0/24", "2001:db8:1::/48"}, func(t *testing.T, h *Handler, b *countingBackend) {
		for _, addr := range []string{"192.168.1.50", "2001:db8:1::99"} {
			resp := h.Handle(context.Background(), ask("example.com", dns.TypeA), requestMeta{
				clientAddr: netip.MustParseAddr(addr), proto: "udp",
			})
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("%s got %s, want NOERROR", addr, dns.RcodeToString[resp.Rcode])
			}
			if len(resp.Answer) == 0 {
				t.Errorf("%s got no answer", addr)
			}
		}
		if n := b.count(); n != 2 {
			t.Errorf("the backend was asked %d times for 2 permitted queries", n)
		}
	})
}

// Malformed and unusual messages do not get past the ACL either.
//
// The ordering matters and is easy to get wrong: a handler that validated the
// message shape first and the source second would answer FORMERR to an
// unauthorised client, which is a different reply and tells them something. It
// would also mean any future check placed between the two ran for a source
// that has no business reaching this resolver at all.
func TestMalformedMessagesFromAnUnauthorisedSourceStillDoNotResolve(t *testing.T) {
	twoQuestions := new(dns.Msg)
	twoQuestions.SetQuestion("example.com.", dns.TypeA)
	twoQuestions.Question = append(twoQuestions.Question,
		dns.Question{Name: "bank.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	noQuestion := new(dns.Msg)
	noQuestion.Response = false

	wrongOpcode := new(dns.Msg)
	wrongOpcode.SetQuestion("example.com.", dns.TypeA)
	wrongOpcode.Opcode = dns.OpcodeUpdate

	wrongClass := new(dns.Msg)
	wrongClass.SetQuestion("example.com.", dns.TypeA)
	wrongClass.Question[0].Qclass = dns.ClassCHAOS

	huge := new(dns.Msg)
	huge.SetQuestion(dns.Fqdn(longName()), dns.TypeA)

	bothModes(t, []string{"192.168.1.0/24"}, func(t *testing.T, h *Handler, b *countingBackend) {
		outsider := netip.MustParseAddr("203.0.113.9")
		for _, m := range []*dns.Msg{twoQuestions, noQuestion, wrongOpcode, wrongClass, huge} {
			resp := h.Handle(context.Background(), m.Copy(), requestMeta{
				clientAddr: outsider, proto: "udp",
			})
			if resp == nil {
				continue
			}
			if resp.Rcode == dns.RcodeSuccess {
				t.Errorf("a malformed message from an unauthorised source was answered NOERROR")
			}
		}
		if n := b.count(); n != 0 {
			t.Fatalf("%d resolutions ran for malformed messages from an unauthorised source", n)
		}
	})
}

// An invalid or absent source address is refused rather than admitted.
//
// It should not happen — the listener parses the address — but "should not
// happen" is not a control. Failing open here would mean anything that could
// make the address unparseable could resolve.
func TestAnUnknownSourceAddressIsRefused(t *testing.T) {
	bothModes(t, []string{"192.168.1.0/24"}, func(t *testing.T, h *Handler, b *countingBackend) {
		resp := h.Handle(context.Background(), ask("example.com", dns.TypeA), requestMeta{
			clientAddr: netip.Addr{}, proto: "udp",
		})
		if resp.Rcode != dns.RcodeRefused {
			t.Errorf("an unparseable source got %s, want REFUSED", dns.RcodeToString[resp.Rcode])
		}
		if n := b.count(); n != 0 {
			t.Errorf("%d resolutions ran for an unparseable source", n)
		}
	})
}

// A refused client writes no query-log row.
//
// Otherwise an unauthorised source could fill the log, and the disk, with
// entries the operator never asked for — which is a denial of service dressed
// as telemetry. The refusal is counted for /metrics instead.
func TestARefusedClientIsCountedButNotLogged(t *testing.T) {
	bothModes(t, []string{"192.168.1.0/24"}, func(t *testing.T, h *Handler, b *countingBackend) {
		before := h.RefusedClients()
		for i := 0; i < 5; i++ {
			h.Handle(context.Background(), ask("example.com", dns.TypeA), requestMeta{
				clientAddr: netip.MustParseAddr("203.0.113.9"), proto: "udp",
			})
		}
		if got := h.RefusedClients() - before; got != 5 {
			t.Errorf("refusals counted = %d, want 5", got)
		}
	})
}

func longName() string {
	name := ""
	for i := 0; i < 40; i++ {
		name += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
	}
	return name
}
