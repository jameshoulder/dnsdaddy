package blocklist

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

// indexDomains is the reference index size the published capacity figures are
// quoted against.
const indexDomains = 500000

// The cost of one blocked domain is not a single number: the map stores the
// name's own bytes, so it moves with the length of the names in the feeds.
// Quoting one figure — as the documentation used to — reads as a constant and
// understates a feed of long DGA-style subdomains by around a quarter.
//
// Each case below therefore carries its own ceiling, and the documentation
// quotes the range rather than the middle of it. The ceilings sit above the
// measurements with deliberate headroom, so ordinary allocator variation
// between Go versions does not fail the build, but a change that made entries
// substantially fatter would.
//
// Cutting these figures is a real optimisation and is tracked as future work:
// Category, FeedID and FeedName are drawn from a handful of distinct values,
// so interning them and storing indices instead of three string headers per
// entry would remove most of the 48-byte Entry.
var indexBudgets = []struct {
	name    string
	pattern string
	// maxBytesPerDomain is what this project is willing to spend on one
	// blocked domain at this name length. The reference deployment is a 1 GB
	// box, and the index has to leave room for the answer cache, the
	// query-log buffers and the runtime inside a 640 MB container limit.
	maxBytesPerDomain float64
}{
	// Short names — a domains-only feed of registrable names.
	{"short", "h%08d.co", 200},
	// The typical shape of a malware feed entry.
	{"typical", "malware-host%08d.example.com", 220},
	// Long third-level names, which is what a DGA or tracking feed looks like.
	// This is the case that sets the top of the published range.
	{"long", "a-rather-long-malicious-subdomain-%08d.tracking.example.net", 270},
}

// The index is the largest thing DNS Daddy holds in memory, and its cost per
// domain is a published capacity figure. This test exists so that figure has a
// source of truth in the repository rather than in somebody's recollection.
func TestIndexMemoryPerDomainStaysWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~110 MB per case")
	}

	// Three string headers, before the key or any of the bytes. This is why
	// the per-domain cost cannot be small with the current representation, and
	// it is asserted so that a change to Entry is a deliberate one.
	if got := unsafe.Sizeof(Entry{}); got != 48 {
		t.Errorf("sizeof(Entry) = %d, expected 48; the capacity figures in "+
			"README.md and docs/architecture.md are derived from this", got)
	}

	for _, tc := range indexBudgets {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			// One shared Entry: feed name, ID and category come from a small
			// fixed set in production, so sharing them here matches how the
			// builder is really fed.
			e := Entry{Category: "malware", FeedID: "f_urlhaus", FeedName: "URLhaus"}
			b := NewBuilder(indexDomains)
			for i := 0; i < indexDomains; i++ {
				b.Add(fmt.Sprintf(tc.pattern, i), e)
			}
			ix := b.Build()

			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			if ix.Len() != indexDomains {
				t.Fatalf("indexed %d domains, want %d", ix.Len(), indexDomains)
			}

			used := after.HeapAlloc - before.HeapAlloc
			perDomain := float64(used) / float64(indexDomains)
			t.Logf("name length %d: %.1f MB heap, %.1f bytes/domain",
				len(fmt.Sprintf(tc.pattern, 1)), float64(used)/(1<<20), perDomain)

			if perDomain > tc.maxBytesPerDomain {
				t.Errorf("index costs %.1f bytes/domain, above the %.0f-byte budget "+
					"for %s names — a %d-domain deployment would need %.0f MB and the "+
					"documented capacity figures need revisiting",
					perDomain, tc.maxBytesPerDomain, tc.name, indexDomains,
					float64(used)/(1<<20))
			}
			runtime.KeepAlive(ix)
		})
	}
}
