package blocklist

import "testing"

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

func TestBuilderKeepsFirstClaim(t *testing.T) {
	// A domain already held at a more severe category keeps that claim: the
	// block reason in the query log has to be the one that matters.
	b := NewBuilder(4)
	if !b.Add("evil.com", Entry{Category: "malware", FeedID: "f1"}) {
		t.Fatal("first Add reported the domain was already present")
	}
	if b.Add("evil.com", Entry{Category: "ads", FeedID: "f2"}) {
		t.Error("second Add reported the domain as new")
	}

	ix := b.Build()
	entry, _ := ix.Lookup("evil.com")
	if entry.Category != "malware" {
		t.Errorf("category = %q, want malware (first claim wins)", entry.Category)
	}
	if ix.Len() != 1 {
		t.Errorf("Len() = %d, want 1", ix.Len())
	}
	if ix.CountsByFeed()["f2"] != 0 {
		t.Error("the losing feed was credited with a domain it did not contribute")
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

	// The displaced feed stops being credited, and the counts still add up.
	if got := ix.CountsByFeed()["f_observatory"]; got != 0 {
		t.Errorf("the displaced feed is still credited with %d domains", got)
	}
	if got := ix.CountsByFeed()["f_urlhaus"]; got != 1 {
		t.Errorf("the winning feed is credited with %d domains, want 1", got)
	}
	if got := ix.CountsByCategory()["cryptomining"]; got != 0 {
		t.Errorf("cryptomining count = %d, want 0", got)
	}
	if got := ix.CountsByCategory()["malware"]; got != 1 {
		t.Errorf("malware count = %d, want 1", got)
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
