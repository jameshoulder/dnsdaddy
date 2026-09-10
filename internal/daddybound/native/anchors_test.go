package native_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/lab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/native"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/recursive/reclab"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/trustanchors"
)

// managed brings up the signed hierarchy behind a managed trust point, seeded
// only from the digest of the root key — the form IANA publishes and the only
// form this build ships.
func managed(t *testing.T) (*native.Engine, *trustanchors.Manager, *recursive.Resolver) {
	t.Helper()

	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("build the signed hierarchy: %v", err)
	}
	servers := reclab.Signed(t, h)
	res := recursive.New(recursive.Config{
		RootHints: []recursive.RootHint{{
			Name: "ns.",
			Addr: []netip.Addr{servers.Addr(".").Addr()},
		}},
		AllowNonGlobalTargets: true,
		Exchange:              servers.Exchanger(recursive.NewNetExchanger(2*time.Second, 4096, true)),
		UDPSize:               4096,
	})

	configured, err := dnssec.NewTrustAnchors(h.Anchor)
	if err != nil {
		t.Fatalf("building the configured anchors: %v", err)
	}
	at := labInstant()
	m, err := trustanchors.NewManager(trustanchors.ManagerConfig{
		Zone:       ".",
		Configured: configured,
		Store:      &trustanchors.MemoryStore{},
		Source:     native.NewKeySource(res),
		Policy:     dnssec.DefaultPolicy(),
		Verifier:   dnssec.StdVerifier(),
		Limits:     dnssec.DefaultLimits(),
		Now:        func() time.Time { return at },
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("building the manager: %v", err)
	}

	e, err := native.New(native.Config{
		Resolver:     res,
		AnchorSource: m.Anchors,
		Policy:       dnssec.DefaultPolicy(),
		Clock:        dnssec.FixedClock{Instant: at},
		Verifier:     dnssec.StdVerifier(),
		Limits:       dnssec.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("building the engine: %v", err)
	}
	return e, m, res
}

// The two slices join: a managed trust point fetches its keys through the
// native resolver, and the engine validates with the set the manager holds.
//
// It matters that the fetch goes through the resolver. The keys that decide
// what this resolver trusts for the next thirty days are read from the
// authoritative servers by the same code that reads everything else — not from
// a forwarder, and not over HTTPS from a URL.
func TestTheManagedAnchorsAreFetchedThroughTheResolverAndUsedToValidate(t *testing.T) {
	e, m, _ := managed(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := m.Refresh(ctx)
	if !res.OK {
		t.Fatalf("the refresh failed: %s", res.Err)
	}
	if !m.Viable() {
		t.Fatal("the trust point reports itself unusable after a successful refresh")
	}

	// The root's key is now managed rather than merely configured: the
	// manager has seen it in a validly signed RRset and recorded it.
	tp := m.TrustPoint()
	if len(tp.Keys) == 0 {
		t.Fatal("a successful refresh recorded no keys")
	}
	var seeded bool
	for _, k := range tp.Keys {
		if k.State == trustanchors.StateValid && k.Seeded {
			seeded = true
		}
	}
	if !seeded {
		t.Errorf("no key was seeded from the configured digest; keys: %+v", tp.Keys)
	}

	// And the engine validates through it.
	ans, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ans.Validation.Status != dnssec.StatusSecure {
		t.Fatalf("status = %s (%s), want secure\ntrace:\n%s",
			ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
	}
}

// The anchors are read when a question is asked, not when the engine is built.
//
// A revocation has to take effect on the next query. An engine that captured
// its anchor set at construction would go on trusting a withdrawn key until
// somebody restarted the process, which for a revocation is exactly the delay
// the REVOKE bit exists to avoid.
func TestTheEngineReadsItsAnchorsPerQuestion(t *testing.T) {
	_, _, res := managed(t)

	var current dnssec.TrustAnchors
	e, err := native.New(native.Config{
		Resolver:     res,
		AnchorSource: func() dnssec.TrustAnchors { return current },
		Policy:       dnssec.DefaultPolicy(),
		Clock:        dnssec.FixedClock{Instant: labInstant()},
		Verifier:     dnssec.StdVerifier(),
		Limits:       dnssec.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("building the engine: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// With no anchors, nothing can be authenticated and the honest answer is
	// Indeterminate — never Insecure, which would be a claim that the data is
	// provably unsigned.
	ans, err := e.Resolve(ctx, lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ans.Validation.Status != dnssec.StatusIndeterminate {
		t.Fatalf("with no anchors the verdict is %s, want indeterminate", ans.Validation.Status)
	}

	// Supply the anchor and ask again. No restart, no rebuild.
	h, err := lab.Standard()
	if err != nil {
		t.Fatalf("lab: %v", err)
	}
	current, err = dnssec.NewTrustAnchors(h.Anchor)
	if err != nil {
		t.Fatalf("anchors: %v", err)
	}

	ans, err = e.Resolve(ctx, lab.AnswerName, dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ans.Validation.Status != dnssec.StatusSecure {
		t.Fatalf("after the anchor was supplied the verdict is %s (%s), want secure — "+
			"the engine is holding an anchor set captured at construction\ntrace:\n%s",
			ans.Validation.Status, ans.Validation.Reason, ans.Validation.Trace())
	}
}
