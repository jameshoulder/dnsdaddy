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
	// Feeds are added in category-priority order, so the first claim on a
	// domain is the most severe classification and must not be overwritten.
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

// The index stores an index into a table of distinct entries rather than the
// entry itself, so the way this can go wrong is no longer "the entry is
// missing" but "the domain resolves to the wrong feed". A domain attributed to
// the wrong source puts a false reason in the query log, which is the one thing
// the block reason exists to get right.
func TestInternedEntriesResolveToTheirOwnFeed(t *testing.T) {
	feeds := []Entry{
		{Category: "malware", FeedID: "f_malware", FeedName: "URLhaus"},
		{Category: "phishing", FeedID: "f_phishing", FeedName: "Phishing Army"},
		{Category: "c2", FeedID: "f_c2", FeedName: "Feodo"},
		{Category: "ads", FeedID: "f_ads", FeedName: "StevenBlack"},
	}

	// Interleaved rather than grouped by feed, so a bug that happened to work
	// when each feed's domains are contiguous still fails here.
	b := NewBuilder(64)
	want := map[string]Entry{}
	for i := 0; i < 40; i++ {
		e := feeds[i%len(feeds)]
		domain := e.Category + "-" + string(rune('a'+i)) + ".example"
		if !b.Add(domain, e) {
			t.Fatalf("Add(%q) reported the domain was already present", domain)
		}
		want[domain] = e
	}
	ix := b.Build()

	for domain, expected := range want {
		got, ok := ix.Lookup(domain)
		if !ok {
			t.Errorf("Lookup(%q) missed", domain)
			continue
		}
		if got != expected {
			t.Errorf("Lookup(%q) = %+v, want %+v", domain, got, expected)
		}
	}

	// One table slot per distinct feed, however many domains reference it.
	if len(ix.entries) != len(feeds) {
		t.Errorf("entry table holds %d entries, want %d — interning is not "+
			"de-duplicating and the memory budget does not hold",
			len(ix.entries), len(feeds))
	}
	for _, e := range feeds {
		if got := ix.CountsByFeed()[e.FeedID]; got != 10 {
			t.Errorf("CountsByFeed()[%q] = %d, want 10", e.FeedID, got)
		}
	}
}
