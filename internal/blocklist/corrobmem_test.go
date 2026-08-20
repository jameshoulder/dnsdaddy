package blocklist

import (
	"fmt"
	"runtime"
	"testing"
)

// The corroboration table is affordable only because it is sparse. This pins
// the assumption to a measurement at the real overlap ratio: across the
// shipped feeds, 4.36% of indicators appear on two or more.
func TestCorroborationTableCostAtMeasuredOverlap(t *testing.T) {
	const (
		domains = 2878143
		overlap = 125459 // measured across the shipped feed set
	)
	feeds := []Entry{
		{Category: "malware", FeedID: "f_a", FeedName: "Feed A"},
		{Category: "phishing", FeedID: "f_b", FeedName: "Feed B"},
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	b := NewBuilder(domains)
	for i := 0; i < domains; i++ {
		b.Add(fmt.Sprintf("malware-host%08d.example.com", i), feeds[0])
	}
	runtime.GC()
	var mid runtime.MemStats
	runtime.ReadMemStats(&mid)

	for i := 0; i < overlap; i++ {
		b.Add(fmt.Sprintf("malware-host%08d.example.com", i), feeds[1])
	}
	ix := b.Build()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if got := ix.CorroboratedDomains(); got != overlap {
		t.Fatalf("CorroboratedDomains() = %d, want %d", got, overlap)
	}
	base := mid.HeapAlloc - before.HeapAlloc
	corrob := after.HeapAlloc - mid.HeapAlloc
	t.Logf("index of %d domains: %.1f MB", domains, float64(base)/(1<<20))
	t.Logf("corroboration for %d (%.2f%%): %.1f MB (%.1f bytes each)",
		overlap, 100*float64(overlap)/domains,
		float64(corrob)/(1<<20), float64(corrob)/float64(overlap))
	t.Logf("corroboration overhead: %.2f%% of the index",
		100*float64(corrob)/float64(base))

	if corrob > 24<<20 {
		t.Errorf("corroboration table costs %.1f MB, above the 24 MB budget",
			float64(corrob)/(1<<20))
	}
	runtime.KeepAlive(ix)
}
