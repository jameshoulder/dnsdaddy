package blocklist

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

// maxBytesPerDomain is the ceiling this project is willing to spend on one
// blocked domain in the in-memory index.
//
// The number matters because it decides whether DNS Daddy fits on its
// reference target of a 1 GB box: a 500,000-domain index at this ceiling costs
// about 120 MB, which leaves room for the answer cache, the query-log buffers
// and the runtime inside the 640 MB container limit.
//
// Measured on linux/amd64 with Go 1.25, the current `map[string]Entry`
// representation costs roughly 167 bytes per domain for short names and 183
// for typical ones. The ceiling is set above that with deliberate headroom
// rather than at the measurement, so ordinary allocator variation between Go
// versions does not fail the build — but a change that made entries
// substantially fatter would.
//
// Cutting this figure is a real optimisation and is tracked as future work:
// Category, FeedID and FeedName are drawn from a handful of distinct values,
// so interning them and storing indices instead of three string headers per
// entry would remove most of the 48-byte Entry.
const maxBytesPerDomain = 250

// The index is the largest thing DNS Daddy holds in memory, and its cost per
// domain is a published capacity figure. This test exists so that figure has a
// source of truth in the repository rather than in somebody's recollection.
func TestIndexMemoryPerDomainStaysWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~90 MB")
	}

	// Three string headers, before the key or any of the bytes. This is why
	// the per-domain cost cannot be small with the current representation, and
	// it is asserted so that a change to Entry is a deliberate one.
	if got := unsafe.Sizeof(Entry{}); got != 48 {
		t.Errorf("sizeof(Entry) = %d, expected 48; the capacity figures in "+
			"README.md and docs/architecture.md are derived from this", got)
	}

	const n = 500000

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// One shared Entry: feed name, ID and category come from a small fixed set
	// in production, so sharing them here matches how the builder is really fed.
	e := Entry{Category: "malware", FeedID: "f_urlhaus", FeedName: "URLhaus"}
	b := NewBuilder(n)
	for i := 0; i < n; i++ {
		b.Add(fmt.Sprintf("malware-host%08d.example.com", i), e)
	}
	ix := b.Build()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if ix.Len() != n {
		t.Fatalf("indexed %d domains, want %d", ix.Len(), n)
	}

	used := after.HeapAlloc - before.HeapAlloc
	perDomain := float64(used) / float64(n)
	t.Logf("%d domains: %.1f MB heap, %.1f bytes/domain",
		n, float64(used)/(1<<20), perDomain)

	if perDomain > maxBytesPerDomain {
		t.Errorf("index costs %.1f bytes/domain, above the %d-byte budget — "+
			"a 500,000-domain deployment would need %.0f MB and the documented "+
			"capacity figures need revisiting",
			perDomain, maxBytesPerDomain, float64(used)/(1<<20))
	}
	runtime.KeepAlive(ix)
}
