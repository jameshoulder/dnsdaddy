package catalog

import "testing"

func TestMapObservatoryCategory(t *testing.T) {
	cases := map[string]string{
		"c2":                    "c2",
		"C2":                    "c2",
		"command_and_control":   "c2",
		"Command And Control":   "c2",
		"botnet":                "c2",
		"ransomware":            "malware",
		"credential-harvesting": "phishing",
		"cryptojacking":         "cryptomining",
		"nrd":                   "newly-registered",
		// A label that is already one of our own IDs needs no translation.
		"gambling": "gambling",
	}
	for label, want := range cases {
		got, ok := MapObservatoryCategory(label)
		if !ok || got != want {
			t.Errorf("MapObservatoryCategory(%q) = %q, %v; want %q, true", label, got, ok, want)
		}
	}

	for _, label := range []string{"", "   ", "spam-relay", "who-knows"} {
		if got, ok := MapObservatoryCategory(label); ok {
			t.Errorf("MapObservatoryCategory(%q) = %q, true; want no match", label, got)
		}
	}
}

func TestMappedCategoriesAllExist(t *testing.T) {
	// A typo here would file indicators under a category no policy can enable,
	// which fails open: the domain would be indexed and never blocked.
	for label, id := range observatoryCategories {
		if !ValidCategory(id) {
			t.Errorf("label %q maps to %q, which is not a category any policy can enable", label, id)
		}
	}
}

func TestBestObservatoryCategoryFollowsCanonicalOrder(t *testing.T) {
	// The same ordering that decides which feed claims a domain shared between
	// two lists decides which of an indicator's labels wins, so a domain has one
	// category whichever path it took into the index.
	cases := []struct {
		labels []string
		want   string
	}{
		{[]string{"c2", "malware"}, "malware"},
		{[]string{"malware", "c2"}, "malware"},
		{[]string{"cryptojacking", "phishing"}, "phishing"},
		{[]string{"never-heard-of-it", "botnet"}, "c2"},
		{[]string{"ads", "ransomware"}, "malware"},
	}
	for _, c := range cases {
		got, ok := BestObservatoryCategory(c.labels)
		if !ok || got != c.want {
			t.Errorf("BestObservatoryCategory(%v) = %q, %v; want %q, true", c.labels, got, ok, c.want)
		}
	}

	if got, ok := BestObservatoryCategory([]string{"spam", "unknown"}); ok {
		t.Errorf("BestObservatoryCategory of unknown labels = %q, true; want no match", got)
	}
	if got, ok := BestObservatoryCategory(nil); ok {
		t.Errorf("BestObservatoryCategory(nil) = %q, true; want no match", got)
	}
}

func TestCategoryPriorityMatchesCatalogOrder(t *testing.T) {
	for i, c := range Categories {
		if got := CategoryPriority(c.ID); got != i {
			t.Errorf("CategoryPriority(%q) = %d, want %d", c.ID, got, i)
		}
	}
	if got := CategoryPriority("not-a-category"); got != len(Categories) {
		t.Errorf("an unknown category sorted at %d, want last (%d)", got, len(Categories))
	}
}

func TestSeverityRank(t *testing.T) {
	if !(SeverityRank("low") < SeverityRank("medium") &&
		SeverityRank("medium") < SeverityRank("high") &&
		SeverityRank("high") < SeverityRank("critical")) {
		t.Error("severities do not rank in order")
	}
	if SeverityRank("CRITICAL ") != SeverityRank("critical") {
		t.Error("severity ranking is not case- and space-insensitive")
	}
	// Unknown ranks 0, which callers read as "no severity declared" rather than
	// "lowest" — the difference between keeping an indicator and losing it.
	for _, s := range []string{"", "urgent", "3"} {
		if got := SeverityRank(s); got != 0 {
			t.Errorf("SeverityRank(%q) = %d, want 0", s, got)
		}
	}
}

func TestValidSeverity(t *testing.T) {
	// Empty means "no floor", so config validation must accept it.
	for _, s := range append(SeverityNames(), "", "  ", "HIGH") {
		if !ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"urgent", "info", "none"} {
		if ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = true, want false", s)
		}
	}
}

func TestObservatoryFeedIsInCatalogAndDisabled(t *testing.T) {
	for _, f := range DefaultFeeds {
		if f.ID != ObservatoryFeedID {
			continue
		}
		if f.Enabled {
			t.Error("the Threat Observatory ships enabled; a default install must not depend on us")
		}
		if !ValidCategory(f.Category) {
			t.Errorf("Observatory fallback category %q is not a real category", f.Category)
		}
		return
	}
	t.Fatal("the Threat Observatory feed is missing from DefaultFeeds")
}
