package recursive_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
)

// Priming replaces the compiled-in bootstrap addresses with the root's own
// answer about where it lives. It is what stops a resolver running for months
// on a hints file that shipped years ago.
func TestRootPrimingLearnsTheRootFromTheRoot(t *testing.T) {
	// Started in two steps: the root's NS RRset has to name an address, and
	// that address is not known until the server is listening.
	h := reclab.Start(t, reclab.Zone{Name: "."})
	rootAddr := h.Addr(".")

	h2 := reclab.Start(t, reclab.Zone{
		Name: ".",
		Records: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  "a.root-servers.test.",
			},
			reclab.A("a.root-servers.test.", rootAddr.Addr().String()),
		},
	})

	r := recursive.New(recursive.Config{
		RootHints: []recursive.RootHint{{
			Name: "hint.root-servers.test.",
			Addr: []netip.Addr{h2.Addr(".").Addr()},
		}},
		AllowNonGlobalTargets: true,
		Exchange:              h2.Exchanger(recursive.NewNetExchanger(2*time.Second, 1232, true)),
	})

	if err := r.Prime(context.Background()); err != nil {
		t.Fatalf("Prime: %v (lab write errors: %v)", err, h2.WriteErrors())
	}

	st := r.PrimingState()
	if !st.Primed {
		t.Fatalf("priming did not succeed: %+v", st)
	}
	if st.Servers == 0 {
		t.Error("primed with no usable root addresses")
	}
	if st.UsingHints {
		t.Error("still reporting that it is running on the compiled-in hints")
	}
}

// Priming failure must not stop the resolver. The compiled-in addresses are
// usually right, and refusing to answer because one root server was
// unreachable would be less available for no security gain — the security
// comes from validating what the root says, not from how we found it.
func TestPrimingFailureFallsBackToHintsAndSaysSo(t *testing.T) {
	// A root with no NS RRset of its own: it answers, but tells us nothing
	// about where the root lives.
	h := reclab.Start(t, reclab.Zone{Name: "."})

	r := recursive.New(recursive.Config{
		RootHints:             []recursive.RootHint{{Name: "hint.test.", Addr: []netip.Addr{h.Addr(".").Addr()}}},
		AllowNonGlobalTargets: true,
		Exchange:              h.Exchanger(recursive.NewNetExchanger(time.Second, 1232, true)),
	})

	if err := r.Prime(context.Background()); err == nil {
		t.Fatal("priming reported success against a root that named no nameservers")
	}

	st := r.PrimingState()
	if st.Primed {
		t.Error("state claims primed after a failure")
	}
	if !st.UsingHints {
		t.Error("state does not report that the resolver is running on hints")
	}
	if st.Err == "" {
		t.Error("state records no reason for the failure")
	}
	if st.Servers == 0 {
		t.Error("no usable hint addresses reported; the resolver would have nothing to ask")
	}
}

// Root hints are a bootstrap and nothing more. A priming reply that tries to
// smuggle in an address for a name the root never listed must not be believed.
func TestPrimingRejectsAddressesForNamesTheRootDidNotList(t *testing.T) {
	h := reclab.Start(t, reclab.Zone{
		Name: ".",
		Records: []dns.RR{
			&dns.NS{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  "a.root-servers.test.",
			},
			reclab.A("a.root-servers.test.", "198.41.0.4"),
		},
		Rewrite: func(req, reply *dns.Msg) {
			// An address for a name that is not in the NS RRset at all.
			reply.Extra = append(reply.Extra, reclab.A("evil.example.", "198.51.100.9"))
		},
	})

	r := recursive.New(recursive.Config{
		RootHints:             []recursive.RootHint{{Name: "hint.test.", Addr: []netip.Addr{h.Addr(".").Addr()}}},
		AllowNonGlobalTargets: true,
		Exchange:              h.Exchanger(recursive.NewNetExchanger(time.Second, 1232, true)),
	})
	if err := r.Prime(context.Background()); err != nil {
		t.Fatalf("Prime: %v", err)
	}

	st := r.PrimingState()
	if st.Servers != 1 {
		t.Fatalf("primed with %d servers, want exactly the 1 the root listed", st.Servers)
	}
}
