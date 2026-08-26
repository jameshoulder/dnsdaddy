package catalog

import (
	"slices"
	"testing"
)

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

func TestMapObservatoryCategoriesKeepsEveryMappedLabel(t *testing.T) {
	// Every category an indicator names is kept, most severe first. Collapsing
	// them would silently decide that one of the categories an operator ticked
	// does not apply to this domain.
	cases := []struct {
		labels []string
		want   []string
	}{
		{[]string{"c2", "malware"}, []string{"malware", "c2"}},
		{[]string{"malware", "c2"}, []string{"malware", "c2"}},
		{[]string{"cryptojacking", "phishing"}, []string{"phishing", "cryptomining"}},
		{[]string{"never-heard-of-it", "botnet"}, []string{"c2"}},
		{[]string{"ads", "ransomware"}, []string{"malware", "ads"}},
		// Two labels that mean the same thing are one category, not two.
		{[]string{"c2", "botnet", "cnc"}, []string{"c2"}},
	}
	for _, c := range cases {
		if got := MapObservatoryCategories(c.labels); !slices.Equal(got, c.want) {
			t.Errorf("MapObservatoryCategories(%v) = %v, want %v", c.labels, got, c.want)
		}
	}

	for _, labels := range [][]string{{"spam", "unknown"}, nil, {}} {
		if got := MapObservatoryCategories(labels); len(got) != 0 {
			t.Errorf("MapObservatoryCategories(%v) = %v, want none", labels, got)
		}
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
