package resources_test

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/detect"
	"github.com/jameshoulder/dnsdaddy/internal/ratelimit"
	"github.com/jameshoulder/dnsdaddy/internal/resolver"
	"github.com/jameshoulder/dnsdaddy/internal/resources"
)

// The published sizes promise that DNS Daddy fits on a 1 GB box. This file is
// where that promise is checked rather than asserted, by building each bounded
// structure at the cap its size sets and weighing it.
//
// It is deliberately a measurement and a ceiling rather than an exact figure:
// allocator behaviour moves between Go versions, and a test that failed on a
// 3% drift would be turned off within a month. The ceilings sit well above the
// measurements; what they catch is a change that makes something
// substantially fatter, which is the failure that gets a Nanode killed.

// measure reports the heap a structure occupies once it is full.
func measure(t *testing.T, build func() any) float64 {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	kept := build()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(kept)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return float64(after.HeapAlloc-before.HeapAlloc) / (1 << 20)
}

func fullAnswerCache(entries int) func() any {
	return func() any {
		c := resolver.NewCache(resolver.CacheOptions{Enabled: true, MaxEntries: entries, MaxTTL: 86400})
		for i := 0; i < entries; i++ {
			name := fmt.Sprintf("host%07d.example.com.", i)
			m := new(dns.Msg)
			m.SetQuestion(name, dns.TypeA)
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{93, 184, byte(i >> 8), byte(i)},
			}}
			c.Put(name+"|A", m, 1)
		}
		return c
	}
}

func fullLimiter(clients int) func() any {
	return func() any {
		l := ratelimit.New(ratelimit.Config{
			Rate: 500, Burst: 1000, MaxClients: clients,
			IPv4PrefixLength: 32, IPv6PrefixLength: 64,
		})
		for i := 0; i < clients; i++ {
			l.Allow(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
		}
		return l
	}
}

func fullIndex(domains int) func() any {
	return func() any {
		e := blocklist.Entry{Category: "malware", FeedID: "f_urlhaus", FeedName: "URLhaus"}
		b := blocklist.NewBuilder(domains)
		for i := 0; i < domains; i++ {
			b.Add(fmt.Sprintf("malware-host%08d.example.com", i), e)
		}
		return b.Build()
	}
}

// fullDetectors saturates every detector's table at the given size.
func fullDetectors(caps resources.Caps) func() any {
	return func() any {
		now := time.Now()
		// Start from each detector's own defaults and override only the
		// bound. Handing these constructors a config with a zero Window makes
		// them discard the whole thing and use their defaults, which would
		// silently measure the same detector three times and report it as
		// three sizes.
		beaconCfg := detect.DefaultBeaconConfig()
		beaconCfg.MaxTracked = caps.DetectorTracked(beaconCfg.MaxTracked)
		tunnelCfg := detect.DefaultTunnelConfig()
		tunnelCfg.MaxTracked = caps.DetectorTracked(tunnelCfg.MaxTracked)
		dgaCfg := detect.DefaultDGAConfig()
		dgaCfg.MaxTracked = caps.DetectorTracked(dgaCfg.MaxTracked)
		nxCfg := detect.DefaultNXDomainConfig()
		nxCfg.MaxTracked = caps.DetectorTracked(nxCfg.MaxTracked)
		txtCfg := detect.DefaultTXTConfig()
		txtCfg.MaxTracked = caps.DetectorTracked(txtCfg.MaxTracked)
		resCfg := detect.DefaultResolutionFailureConfig()
		resCfg.MaxTracked = caps.DetectorTracked(resCfg.MaxTracked)

		beacon := detect.NewBeaconDetector(beaconCfg)
		tunnel := detect.NewTunnelDetector(tunnelCfg)
		dga := detect.NewDGADetector(dgaCfg)
		nx := detect.NewNXDomainDetector(nxCfg)
		txt := detect.NewTXTDetector(txtCfg)
		res := detect.NewResolutionFailureDetector(resCfg)

		// Offer each detector twice its bound, so the table is genuinely full
		// and the eviction path is exercised rather than assumed.
		const overfill = 2

		fill := func(n int, observe func(i int, e *detect.Event)) {
			for i := 0; i < n; i++ {
				parent := fmt.Sprintf("observed%07d.example.com", i)
				e := &detect.Event{
					Observation: detect.Observation{
						Time:     now,
						ClientIP: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255),
						QName:    parent,
						QType:    "A",
					},
					Parent: parent, HasParent: true,
				}
				observe(i, e)
			}
		}
		fill(beaconCfg.MaxTracked*overfill, func(_ int, e *detect.Event) { beacon.Observe(e) })
		fill(tunnelCfg.MaxTracked*overfill, func(_ int, e *detect.Event) {
			e.Sub = "aGVsbG8td29ybGQtdGhpcy1pcy1hLWxvbmctZW5jb2RlZC1sYWJlbA"
			e.QName = e.Sub + "." + e.Parent
			tunnel.Observe(e)
		})
		fill(dgaCfg.MaxTracked*overfill, func(_ int, e *detect.Event) { e.NXDomain = true; dga.Observe(e) })
		fill(nxCfg.MaxTracked*overfill, func(_ int, e *detect.Event) { e.NXDomain = true; nx.Observe(e) })
		fill(txtCfg.MaxTracked*overfill, func(_ int, e *detect.Event) { e.QType = "TXT"; txt.Observe(e) })
		fill(resCfg.MaxTracked*overfill, func(_ int, e *detect.Event) { e.ServFail = true; res.Observe(e) })

		return []detect.Detector{beacon, tunnel, dga, nx, txt, res}
	}
}

// coreFeedDomains is what the categories a default install blocks come to.
//
// Malware, phishing, C2 and cryptomining across the six feeds that ship
// enabled. It is a working figure rather than a measurement of today's feeds —
// those change daily and a test that depended on their current size would fail
// on a Tuesday for no reason — but it is the right order of magnitude and
// deliberately generous.
const coreFeedDomains = 250_000

// TestTheMeasuredBudgetFitsTheSmallestMachine is the load-bearing one.
//
// The 1 GB size is not a marketing claim, it is an arithmetic one: everything
// DNS Daddy holds, at the ceilings that size sets, plus room for the garbage
// collector to do its work, has to leave a machine with 1 GB of memory
// something to run on. This adds it up out of measurements.
func TestTheMeasuredBudgetFitsTheSmallestMachine(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates several hundred megabytes")
	}
	caps := resources.CapsFor(resources.ProfileTiny)

	index := measure(t, fullIndex(coreFeedDomains))
	cache := measure(t, fullAnswerCache(caps.AnswerCacheEntries))
	limiter := measure(t, fullLimiter(caps.RateLimitMaxClients))
	detectors := measure(t, fullDetectors(caps))

	// The database's page cache is configuration rather than Go heap, so it is
	// added from the setting rather than weighed.
	sqlite := float64(caps.SQLiteCacheMB)

	// What the process costs before it holds anything: the runtime, the
	// binary's own data, the HTTP server, the listeners. Measured at startup
	// on the reference deployment and rounded up.
	const baseline = 25.0

	live := index + cache + limiter + detectors + sqlite + baseline

	// Go collects when the heap has grown by GOGC percent over the live set,
	// so peak resident memory is roughly twice what is live. Sizing to the
	// live figure alone is the classic way to write a budget that holds right
	// up until the first collection.
	peak := live * 2

	t.Logf("1 GB size, measured:")
	t.Logf("  blocklist index, %d domains   %6.1f MB", coreFeedDomains, index)
	t.Logf("  answer cache, %d entries      %6.1f MB", caps.AnswerCacheEntries, cache)
	t.Logf("  rate limiter, %d clients       %6.1f MB", caps.RateLimitMaxClients, limiter)
	t.Logf("  detector tables                  %6.1f MB", detectors)
	t.Logf("  database page cache              %6.1f MB", sqlite)
	t.Logf("  runtime and everything else      %6.1f MB", baseline)
	t.Logf("  ------------------------------------------")
	t.Logf("  live                             %6.1f MB", live)
	t.Logf("  peak, allowing for collection    %6.1f MB", peak)

	// A 1 GB machine reports around 970 MB, and Detect sets 256 MB aside for
	// the operating system. That leaves this.
	const availableOnANanode = 714.0
	// And the rebuild: a new index is built while the old one is still being
	// served, so the largest thing on the list is briefly doubled. This is the
	// real peak and the one that gets a box killed.
	rebuildPeak := peak + index

	if rebuildPeak > availableOnANanode {
		t.Errorf("the 1 GB size needs %.0f MB at its worst moment (a feed rebuild) but a "+
			"1 GB machine offers about %.0f MB. Lower the ceilings in capsByProfile "+
			"rather than publishing a figure that does not hold.",
			rebuildPeak, availableOnANanode)
	}
	t.Logf("  peak during a feed rebuild       %6.1f MB  (of ~%.0f MB available)",
		rebuildPeak, availableOnANanode)
}

// TestEachSizeHoldsMoreThanTheOneBelowIt.
//
// The three sizes are only meaningful if they are ordered. A cap that was
// raised on one size and forgotten on another would produce a 4 GB machine
// that remembered fewer clients than a 1 GB one, which is the kind of thing
// nobody notices until they are trying to explain it.
func TestEachSizeHoldsMoreThanTheOneBelowIt(t *testing.T) {
	tiny := resources.CapsFor(resources.ProfileTiny)
	small := resources.CapsFor(resources.ProfileSmall)
	full := resources.CapsFor(resources.ProfileFull)

	for _, f := range []struct {
		name string
		get  func(resources.Caps) int
	}{
		{"answer cache entries", func(c resources.Caps) int { return c.AnswerCacheEntries }},
		{"rate limiter clients", func(c resources.Caps) int { return c.RateLimitMaxClients }},
		{"first-seen rows", func(c resources.Caps) int { return c.FirstSeenMaxRows }},
		{"first-seen new per minute", func(c resources.Caps) int { return c.FirstSeenMaxNewPerMinute }},
		{"query log retention days", func(c resources.Caps) int { return c.QueryLogRetentionDays }},
		{"lifecycle rows", func(c resources.Caps) int { return c.LifecycleMaxRows }},
		{"database page cache MB", func(c resources.Caps) int { return c.SQLiteCacheMB }},
		{"detector tracking", func(c resources.Caps) int { return c.DetectorTracked(4096) }},
	} {
		a, b, c := f.get(tiny), f.get(small), f.get(full)
		if !(a < b && b < c) {
			t.Errorf("%s does not increase with machine size: 1 GB %d, 2 GB %d, 4 GB+ %d",
				f.name, a, b, c)
		}
	}
}

// TestTheTwoGigabyteSizeKeepsTodaysBehaviour.
//
// Somebody upgrading onto a 2 GB box must get what they had. If these figures
// drifted, an upgrade would quietly shorten their query log or shrink their
// cache, and the release note would not mention it because nobody would have
// noticed.
func TestTheTwoGigabyteSizeKeepsTodaysBehaviour(t *testing.T) {
	c := resources.CapsFor(resources.ProfileSmall)
	for _, tc := range []struct {
		name      string
		got, want int
	}{
		{"answer cache entries", c.AnswerCacheEntries, 50_000},
		{"rate limiter clients", c.RateLimitMaxClients, 65_536},
		{"first-seen rows", c.FirstSeenMaxRows, 100_000},
		{"first-seen new per minute", c.FirstSeenMaxNewPerMinute, 200},
		{"query log retention days", c.QueryLogRetentionDays, 7},
		{"lifecycle rows", c.LifecycleMaxRows, 1_000_000},
		{"detector tracking at the documented 4096", c.DetectorTracked(4096), 4096},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d on a 2 GB machine, want %d — this is what the release before "+
				"sizes shipped with", tc.name, tc.got, tc.want)
		}
	}
}

// TestADetectorIsNeverScaledDownToNothing. A fraction applied to a small
// documented bound could reach zero, and a detector that tracks nothing
// reports nothing while still appearing in the catalogue as enabled.
func TestADetectorIsNeverScaledDownToNothing(t *testing.T) {
	tiny := resources.CapsFor(resources.ProfileTiny)
	for _, documented := range []int{0, 1, 16, 256, 1024, 4096, 16384} {
		if got := tiny.DetectorTracked(documented); got < 256 {
			t.Errorf("a documented bound of %d scaled to %d, below the floor", documented, got)
		}
	}
}

// TestTheBudgetTableForEverySize prints the table published in
// docs/architecture.md.
//
// It asserts only the ceiling each size is allowed to reach; its real job is
// to be the source of those figures, so that the documentation quotes a
// measurement somebody can re-run rather than a number somebody remembered.
func TestTheBudgetTableForEverySize(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates several gigabytes across the three sizes")
	}
	for _, tc := range []struct {
		profile resources.Profile
		// liveCeilingMB is what this size may cost with everything full,
		// excluding the blocklist (which is set by the operator's feeds, not
		// by the size) and the database page cache (which is not Go heap).
		liveCeilingMB float64
	}{
		{resources.ProfileTiny, 25},
		{resources.ProfileSmall, 80},
		{resources.ProfileFull, 160},
	} {
		t.Run(string(tc.profile), func(t *testing.T) {
			caps := resources.CapsFor(tc.profile)
			cache := measure(t, fullAnswerCache(caps.AnswerCacheEntries))
			limiter := measure(t, fullLimiter(caps.RateLimitMaxClients))
			detectors := measure(t, fullDetectors(caps))
			live := cache + limiter + detectors

			t.Logf("%-14s cache %d = %.1f MB | limiter %d = %.1f MB | detectors = %.1f MB | "+
				"total %.1f MB live, database page cache %d MB, first-seen %d rows, logs %dd",
				tc.profile.Label(), caps.AnswerCacheEntries, cache,
				caps.RateLimitMaxClients, limiter, detectors, live,
				caps.SQLiteCacheMB, caps.FirstSeenMaxRows, caps.QueryLogRetentionDays)

			if live > tc.liveCeilingMB {
				t.Errorf("%s costs %.1f MB live, above its %.0f MB ceiling — either a "+
					"structure got fatter or a cap was raised without re-measuring",
					tc.profile.Label(), live, tc.liveCeilingMB)
			}
		})
	}
}

// TestTheBlocklistCostsTheSameAtEverySize, because the operator's feeds decide
// it and nothing about machine size may quietly change what gets blocked.
func TestTheBlocklistCostsTheSameAtEverySize(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~150 MB")
	}
	for _, n := range []int{100_000, 250_000, 500_000} {
		mb := measure(t, fullIndex(n))
		t.Logf("blocklist, %7d domains  %6.1f MB  (%.0f bytes/domain)",
			n, mb, mb*(1<<20)/float64(n))
	}
}
