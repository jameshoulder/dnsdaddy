//go:build cgo && daddybound_unbound

package differential_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential/refdelv"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/differential/refunbound"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/dnssec"
	"github.com/jameshoulder/dnsdaddy/internal/daddybound/netsource"
)

// The live corpus run. Deliberately not part of any ordinary test invocation.
//
// It needs the network, a public recursive resolver, several minutes, and
// both oracles, and its result depends on the state of other people's zones —
// every one of which is a reason it must never gate a pull request. A CI job
// that fails because someone else let a signature expire teaches contributors
// to re-run red builds, which costs far more than this run is worth.
//
// So it is opt-in: DADDYBOUND_CORPUS=1, or `make corpus`. What it produces is
// a report to read and to quote, and one hard assertion — no false Secures —
// because that one does not depend on anyone else's zone being healthy.
func TestRealWorldCorpus(t *testing.T) {
	if os.Getenv("DADDYBOUND_CORPUS") == "" {
		t.Skip("set DADDYBOUND_CORPUS=1 to run the live corpus (needs network, both oracles, several minutes)")
	}
	if !refunbound.Available() {
		t.Skip(refunbound.Why())
	}
	if !refdelv.Available() {
		t.Skip(refdelv.Why())
	}

	server := envOr("DADDYBOUND_CORPUS_SERVER", "1.1.1.1:53")
	anchors, anchorDS := loadRootAnchors(t)

	f, err := os.Open("testdata/corpus.txt")
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	entries, err := differential.ParseCorpus(f)
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	if limit := envInt(t, "DADDYBOUND_CORPUS_LIMIT"); limit > 0 && limit < len(entries) {
		entries = entries[:limit]
	}
	t.Logf("corpus: %d questions, upstream %s, %d root anchors", len(entries), server, len(anchors))

	// One Source for the whole run, so its cache holds the root and TLD key
	// material across every name. Without that, several hundred names would
	// each re-fetch the same DNSKEY and DS records from a public resolver —
	// slow, rude, and internally inconsistent if a zone re-signs part-way
	// through.
	src := netsource.New(netsource.Config{Server: server})

	anchorSet, err := dnssec.NewTrustAnchors(anchors...)
	if err != nil {
		t.Fatalf("anchors: %v", err)
	}
	v := dnssec.New(src, dnssec.Config{
		Anchors: anchorSet,
		Policy:  dnssec.DefaultPolicy(),
		// The wall clock, which is the honest choice here and the opposite
		// of the lab's. A lab fixture has a fixed validity window and must
		// be judged at a fixed instant; a live zone's signatures are valid
		// now or they are not, and pinning the clock would manufacture
		// disagreements with two oracles that cannot be pinned to match.
		Clock:    dnssec.SystemClock{},
		Verifier: dnssec.StdVerifier(),
		Limits:   dnssec.DefaultLimits(),
	})

	unbound, err := refunbound.New(refunbound.Config{
		Forward:        server,
		TrustAnchor:    anchorDS[0],
		ValidationTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("libunbound: %v", err)
	}
	delv, err := refdelv.New(refdelv.Config{
		Forward: server, Anchors: anchors, WorkDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("delv: %v", err)
	}

	oracles := []differential.Reference{unbound, delv}
	categoryOf := map[string]string{}

	type pending struct {
		entry  differential.CorpusEntry
		oracle differential.Reference
		comp   differential.Comparison
	}

	var (
		mu       sync.Mutex
		byOracle = map[string][]differential.Comparison{}
		disputed []pending
	)

	compare := func(ctx context.Context, e differential.CorpusEntry, oracle differential.Reference) differential.Comparison {
		db := v.Validate(ctx, e.Name, e.QType)
		ref, refErr := oracle.Validate(ctx, e.Name, e.QType)
		c := differential.Comparison{
			Scenario:   e.Name + "/" + dns.TypeToString[e.QType],
			Class:      differential.Classify(db, nil, ref, refErr, ""),
			Daddybound: db,
			Reference:  ref,
		}
		if refErr != nil {
			c.ReferenceErr = refErr.Error()
		}
		return c
	}

	// Modest concurrency. Enough that several hundred names finish in
	// minutes; small enough not to look like abuse to a public resolver, and
	// small enough that a timeout is a timeout rather than self-inflicted
	// congestion. delv is a process per question, so this is also a bound on
	// how many of those exist at once.
	const workers = 4
	work := make(chan differential.CorpusEntry)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range work {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				for _, oracle := range oracles {
					c := compare(ctx, e, oracle)
					mu.Lock()
					categoryOf[c.Scenario] = e.Category
					if c.Class == differential.ClassMatch {
						byOracle[oracle.Name()] = append(byOracle[oracle.Name()], c)
					} else {
						disputed = append(disputed, pending{e, oracle, c})
					}
					mu.Unlock()
				}
				cancel()
			}
		}()
	}
	for _, e := range entries {
		work <- e
	}
	close(work)
	wg.Wait()

	// Every disagreement is asked again, once, on its own.
	//
	// Not to make failures go away — a second run that agrees with the first
	// is recorded exactly as it stands, and a genuine false Secure
	// reproduces every time. It is to stop the *network* being read as a
	// verdict. Under concurrency an oracle that loses a packet mid-chain
	// reports words indistinguishable from a real refusal: delv says
	// "broken trust chain resolving 'org/DS/IN'" whether the DS is missing
	// or the query was dropped. The first run of this corpus produced
	// exactly that against iana.org, which validates cleanly the moment it
	// is asked on its own.
	//
	// Reading it as evidence would have been the worse mistake in either
	// direction: as a false Secure it is noise that trains a reader to skim
	// past the one line that must never be skimmed, and a transport failure
	// recorded as agreement would hide the real thing.
	//
	// Serially, so the re-run is not competing with the run that produced
	// the disagreement.
	settled := 0
	for _, d := range disputed {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		again := compare(ctx, d.entry, d.oracle)
		cancel()
		if again.Class != d.comp.Class {
			settled++
		}
		byOracle[d.oracle.Name()] = append(byOracle[d.oracle.Name()], again)
	}

	stats := src.Stats()
	t.Logf("network: %d queries sent, %d served from cache, %d truncated to TCP, %d failed",
		stats.Queries, stats.Cached, stats.Truncat, stats.Errors)
	t.Logf("re-runs: %d disagreements asked again serially, %d changed class on the second ask",
		len(disputed), settled)

	var falseSecure []differential.Comparison
	for _, name := range sortedKeys(byOracle) {
		report := differential.GroupByCategory(name, byOracle[name], func(s string) string {
			return categoryOf[s]
		})
		t.Logf("\n%s", report.Summary())
		falseSecure = append(falseSecure, report.FalseSecure()...)
	}

	// The one assertion. Everything else in this run is a measurement of a
	// world nobody controls; this is the property that holds regardless of
	// whose zone is broken today.
	if len(falseSecure) > 0 {
		for _, c := range falseSecure {
			t.Errorf("FALSE SECURE on %s: daddybound=%s (%s), reference=%s — %s\n%s",
				c.Scenario, c.Daddybound.Status, c.Daddybound.Reason,
				c.Reference.Status, c.Reference.Detail, c.Daddybound.Trace())
		}
		t.Fatalf("%d false Secures against the live Internet", len(falseSecure))
	}
}

// loadRootAnchors derives the root trust anchors from the system's managed
// root key file.
//
// Read from the system rather than written into this file, and the reason is
// the whole point of a trust anchor. A key typed into source is a key nobody
// re-checks: the root has two KSKs published today and will have one again,
// and a hard-coded anchor would keep working right up until the day it
// silently reported the entire Internet Bogus. The file is maintained by the
// distribution's dns-root-data package and is what the system's own
// validators use.
//
// The DS is computed from the DNSKEY here rather than being a second thing to
// keep in step. RFC 4034 §5.1.4 defines it as a digest of the owner name and
// the key's RDATA, so it is derived data and there is nothing to get wrong
// twice.
func loadRootAnchors(t *testing.T) ([]dnssec.TrustAnchor, []string) {
	t.Helper()

	path := envOr("DADDYBOUND_ROOT_KEY", "/usr/share/dns/root.key")
	data, err := os.ReadFile(path) // #nosec G304 -- a test reading a path the operator named
	if err != nil {
		t.Skipf("no root key file at %s (apt-get install dns-root-data): %v", path, err)
	}

	var (
		out []dnssec.TrustAnchor
		ds  []string
	)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			continue
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok || key.Flags&0x0001 == 0 {
			// Flag bit 15, the Secure Entry Point. A ZSK in this file would
			// not be an anchor.
			continue
		}
		record := key.ToDS(dns.SHA256)
		if record == nil {
			continue
		}
		// Two spellings of one anchor, both derived from the same computed
		// DS so they cannot drift apart.
		//
		// IANA publishes the five bare fields, which is what
		// ParseTrustAnchorDS reads; libunbound's ub_ctx_add_ta wants a zone
		// file line, class and type included. Handing it the bare form is
		// not a parse error — it is UB_INITFAIL from ub_resolve, an
		// "initialization failure" on every single query, which reads like
		// a broken oracle rather than a malformed anchor. That cost a
		// debugging session; hence this comment rather than a tidier one.
		iana := fmt.Sprintf("%s %d %d %d %s",
			record.Hdr.Name, record.KeyTag, record.Algorithm, record.DigestType,
			strings.ToUpper(record.Digest))
		anchor, err := dnssec.ParseTrustAnchorDS(iana)
		if err != nil {
			t.Fatalf("anchor from %s: %v", path, err)
		}
		out = append(out, anchor)
		ds = append(ds, fmt.Sprintf("%s IN DS %d %d %d %s",
			record.Hdr.Name, record.KeyTag, record.Algorithm, record.DigestType,
			strings.ToUpper(record.Digest)))
	}
	if len(out) == 0 {
		t.Skipf("no key-signing keys in %s", path)
	}
	return out, ds
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envInt(t *testing.T, name string) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s=%q is not a number", name, v)
	}
	return n
}

func sortedKeys(m map[string][]differential.Comparison) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
