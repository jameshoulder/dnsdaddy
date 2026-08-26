package blocklist

import (
	"slices"
	"testing"
)

func buildIndex(t *testing.T, entries map[string]string) *Index {
	t.Helper()
	b := NewBuilder(len(entries))
	for domain, category := range entries {
		b.Add(domain, Entry{Category: category, FeedID: "f_" + category, FeedName: category + " feed"})
	}
	return b.Build()
}

func TestLookupExactAndParent(t *testing.T) {
	ix := buildIndex(t, map[string]string{"evil.com": "malware"})

	for _, domain := range []string{"evil.com", "login.evil.com", "a.b.c.evil.com"} {
		entry, ok := ix.Lookup(domain)
		if !ok {
			t.Errorf("Lookup(%q) missed; blocking a domain must block its subdomains", domain)
			continue
		}
		if entry.Category != "malware" {
			t.Errorf("Lookup(%q).Category = %q, want malware", domain, entry.Category)
		}
	}
}

func TestLookupDoesNotMatchSiblingSuffix(t *testing.T) {
	ix := buildIndex(t, map[string]string{"evil.com": "malware"})

	for _, domain := range []string{"notevil.com", "myevil.com", "evil.com.au", "com"} {
		if _, ok := ix.Lookup(domain); ok {
			t.Errorf("Lookup(%q) matched, but it is not under evil.com", domain)
		}
	}
}

func TestLookupPrefersMostSpecificEntry(t *testing.T) {
	// A specific subdomain classified differently from its parent should win,
	// because the suffix walk starts at the full name.
	ix := buildIndex(t, map[string]string{
		"example.com":       "ads",
		"phish.example.com": "phishing",
	})

	entry, ok := ix.Lookup("phish.example.com")
	if !ok || entry.Category != "phishing" {
		t.Errorf("Lookup returned (%+v, %v), want the phishing entry", entry, ok)
	}
}

func TestEmptyIndexNeverMatches(t *testing.T) {
	if _, ok := NewIndex().Lookup("evil.com"); ok {
		t.Error("empty index matched a domain")
	}
	var nilIndex *Index
	if _, ok := nilIndex.Lookup("evil.com"); ok {
		t.Error("nil index matched a domain")
	}
	if nilIndex.Len() != 0 {
		t.Error("nil index reported a non-zero length")
	}
}

func TestBuilderKeepsFirstClaimAsPrimary(t *testing.T) {
	// A domain already held at a more severe category keeps it as the primary
	// claim: the block reason in the query log has to be the one that matters,
	// and the less severe feed is not credited with the domain.
	b := NewBuilder(4)
	if !b.Add("evil.com", Entry{Category: "malware", FeedID: "f1"}) {
		t.Fatal("first Add reported the domain was already present")
	}
	if b.Add("evil.com", Entry{Category: "ads", FeedID: "f2"}) {
		t.Error("a less severe claim was made primary")
	}

	ix := b.Build()
	entry, _ := ix.Lookup("evil.com")
	if entry.Category != "malware" {
		t.Errorf("category = %q, want malware (most severe claim is primary)", entry.Category)
	}
	if ix.Len() != 1 {
		t.Errorf("Len() = %d, want 1", ix.Len())
	}
	if ix.CountsByFeed()["f2"] != 0 {
		t.Error("the losing feed was credited with a domain it did not contribute")
	}

	// The ads claim is still there, so an ads-enabled policy blocks it too.
	if _, ok := ix.LookupEnabled("evil.com", map[string]bool{"ads": true}); !ok {
		t.Error("the less severe claim was discarded; an ads policy would miss it")
	}
}

func TestBuilderIgnoresEmptyDomain(t *testing.T) {
	b := NewBuilder(1)
	if b.Add("", Entry{Category: "malware"}) {
		t.Error("Add(\"\") reported success")
	}
	if b.Build().Len() != 0 {
		t.Error("empty domain was indexed")
	}
}

func TestCounts(t *testing.T) {
	ix := buildIndex(t, map[string]string{
		"a.example": "malware",
		"b.example": "malware",
		"c.example": "phishing",
	})

	cats := ix.CountsByCategory()
	if cats["malware"] != 2 || cats["phishing"] != 1 {
		t.Errorf("CountsByCategory() = %v, want malware:2 phishing:1", cats)
	}
	if ix.Len() != 3 {
		t.Errorf("Len() = %d, want 3", ix.Len())
	}
}

func TestHolderSwapAndGeneration(t *testing.T) {
	h := NewHolder()
	if h.Load().Len() != 0 {
		t.Error("a new holder should start with an empty index")
	}
	start := h.Generation()

	h.Store(buildIndex(t, map[string]string{"evil.com": "malware"}))
	if _, ok := h.Load().Lookup("evil.com"); !ok {
		t.Error("the swapped-in index is not visible")
	}
	if h.Generation() == start {
		t.Error("generation did not advance; cached answers would not be invalidated")
	}
}

func BenchmarkLookupMiss(b *testing.B) {
	builder := NewBuilder(100000)
	for i := 0; i < 100000; i++ {
		builder.Add(randomDomain(i), Entry{Category: "malware"})
	}
	ix := builder.Build()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.Lookup("www.legitimate-business.co.uk")
	}
}

func BenchmarkLookupEnabledHit(b *testing.B) {
	builder := NewBuilder(100000)
	for i := 0; i < 100000; i++ {
		builder.Add(randomDomain(i), Entry{Category: "malware", FeedID: "f1"})
	}
	ix := builder.Build()
	enabled := map[string]bool{"malware": true, "phishing": true, "c2": true, "cryptomining": true}
	target := randomDomain(500)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.LookupEnabled(target, enabled)
	}
}

func BenchmarkLookupEnabledMiss(b *testing.B) {
	builder := NewBuilder(100000)
	for i := 0; i < 100000; i++ {
		builder.Add(randomDomain(i), Entry{Category: "malware", FeedID: "f1"})
	}
	ix := builder.Build()
	enabled := map[string]bool{"malware": true, "phishing": true, "c2": true, "cryptomining": true}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ix.LookupEnabled("www.legitimate-business.co.uk", enabled)
	}
}

func randomDomain(i int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, 0, 16)
	n := i
	for j := 0; j < 8; j++ {
		buf = append(buf, letters[n%26])
		n /= 26
	}
	return string(buf) + ".example"
}

func TestBuilderUpgradesToTheMoreSevereClaim(t *testing.T) {
	// Feed order is an optimisation, not the rule. A feed whose entries carry
	// their own categories — the Observatory format — contributes domains at
	// several severities at once, so a later, more severe claim has to win.
	//
	// This is not cosmetic. A policy that enables malware but not cryptomining
	// must still block a domain that one feed called cryptomining and another
	// called malware.
	b := NewBuilder(4)
	if !b.Add("evil.com", Entry{Category: "cryptomining", FeedID: "f_observatory"}) {
		t.Fatal("first Add reported the domain was already present")
	}
	if !b.Add("evil.com", Entry{Category: "malware", FeedID: "f_urlhaus"}) {
		t.Error("a more severe claim did not take the domain")
	}

	ix := b.Build()
	entry, _ := ix.Lookup("evil.com")
	if entry.Category != "malware" {
		t.Errorf("category = %q, want malware", entry.Category)
	}
	if entry.FeedID != "f_urlhaus" {
		t.Errorf("feed = %q, want f_urlhaus", entry.FeedID)
	}
	if ix.Len() != 1 {
		t.Errorf("Len() = %d, want 1", ix.Len())
	}

	// The displaced feed stops being credited with the domain, so per-feed
	// counts still sum to the index size.
	if got := ix.CountsByFeed()["f_observatory"]; got != 0 {
		t.Errorf("the displaced feed is still credited with %d domains", got)
	}
	if got := ix.CountsByFeed()["f_urlhaus"]; got != 1 {
		t.Errorf("the winning feed is credited with %d domains, want 1", got)
	}

	// The displaced CLAIM survives, though: a cryptomining-only policy still
	// blocks this domain, and the category count says so.
	if got := ix.CountsByCategory()["cryptomining"]; got != 1 {
		t.Errorf("cryptomining count = %d, want 1 — the claim is still live", got)
	}
	if got := ix.CountsByCategory()["malware"]; got != 1 {
		t.Errorf("malware count = %d, want 1", got)
	}
	if e, ok := ix.LookupEnabled("evil.com", map[string]bool{"cryptomining": true}); !ok {
		t.Error("a cryptomining-only policy no longer blocks the displaced claim")
	} else if e.Category != "cryptomining" || e.FeedID != "f_observatory" {
		t.Errorf("displaced claim resolved to %+v, want the cryptomining/f_observatory claim", e)
	}
}

func TestBuilderTreatsEqualAndUnknownCategoriesAsNoUpgrade(t *testing.T) {
	// An equal claim changes nothing, and an unrecognised category sorts last
	// so it can never displace a real one.
	b := NewBuilder(4)
	b.Add("evil.com", Entry{Category: "phishing", FeedID: "f1"})

	if b.Add("evil.com", Entry{Category: "phishing", FeedID: "f2"}) {
		t.Error("an equally severe claim took the domain")
	}
	if b.Add("evil.com", Entry{Category: "not-a-category", FeedID: "f3"}) {
		t.Error("an unknown category displaced a real one")
	}

	ix := b.Build()
	entry, _ := ix.Lookup("evil.com")
	if entry.FeedID != "f1" {
		t.Errorf("feed = %q, want f1", entry.FeedID)
	}
	if ix.CountsByCategory()["phishing"] != 1 {
		t.Errorf("phishing count = %d, want 1", ix.CountsByCategory()["phishing"])
	}
}

func TestCategoriesReportsEveryClaimMostSevereFirst(t *testing.T) {
	b := NewBuilder(4)
	// Claimed in ascending severity, which is the awkward order.
	b.Add("evil.com", Entry{Category: "ads", FeedID: "f1"})
	b.Add("evil.com", Entry{Category: "cryptomining", FeedID: "f2"})
	b.Add("evil.com", Entry{Category: "malware", FeedID: "f3"})
	b.Add("evil.com", Entry{Category: "malware", FeedID: "f4"}) // duplicate

	ix := b.Build()
	got := ix.Categories("evil.com")
	if !slices.Equal(got, []string{"malware", "cryptomining", "ads"}) {
		t.Errorf("Categories = %v, want [malware cryptomining ads]", got)
	}

	// Every one of them blocks, on its own.
	for _, c := range got {
		if _, ok := ix.LookupEnabled("evil.com", map[string]bool{c: true}); !ok {
			t.Errorf("a %s-only policy does not block a domain claimed under %s", c, c)
		}
	}
	if ix.Len() != 1 {
		t.Errorf("Len() = %d, want 1 — claims are not extra domains", ix.Len())
	}
	if ix.Categories("not-listed.example") != nil {
		t.Error("Categories reported claims for an unlisted domain")
	}
}
