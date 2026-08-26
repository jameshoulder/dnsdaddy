package blocklist

import (
	"strings"
	"testing"
	"time"
)

const observatoryFeed = `{
  "generated_at": "2026-08-26T09:15:00Z",
  "source": "dnsdaddy-threat-observatory",
  "indicators": [
    {"value": "c2.example", "type": "domain", "severity": "critical",
     "categories": ["c2", "malware"], "family": "qakbot", "last_seen": "2026-08-26T09:10:00Z"},
    {"value": "PHISH.example", "type": "domain", "severity": "high",
     "categories": ["credential-harvesting"]},
    {"value": "miner.example", "type": "domain", "severity": "medium",
     "categories": ["cryptojacking"]},
    {"value": "203.0.113.9", "type": "ip", "severity": "high", "categories": ["c2"]},
    {"value": "unmapped.example", "type": "domain", "severity": "low",
     "categories": ["spam-relay"]}
  ]
}`

func collectObservatory(t *testing.T, body, minSeverity string) (map[string]ObservatoryRecord, ObservatoryResult) {
	t.Helper()
	got := map[string]ObservatoryRecord{}
	res, err := ParseObservatory(strings.NewReader(body), minSeverity, func(r ObservatoryRecord) {
		got[r.Domain] = r
	})
	if err != nil {
		t.Fatalf("ParseObservatory: %v", err)
	}
	return got, res
}

func TestParseObservatoryMapsCategories(t *testing.T) {
	got, res := collectObservatory(t, observatoryFeed, "")

	if res.Source != "dnsdaddy-threat-observatory" {
		t.Errorf("source = %q", res.Source)
	}
	want := time.Date(2026, 8, 26, 9, 15, 0, 0, time.UTC)
	if !res.GeneratedAt.Equal(want) {
		t.Errorf("generatedAt = %v, want %v", res.GeneratedAt, want)
	}

	// An indicator tagged both c2 and malware resolves to malware: the same
	// canonical ordering that decides which feed claims a shared domain also
	// decides which of an indicator's own labels wins.
	if c := got["c2.example"].Category; c != "malware" {
		t.Errorf("c2.example category = %q, want malware", c)
	}
	if f := got["c2.example"].Family; f != "qakbot" {
		t.Errorf("c2.example family = %q, want qakbot", f)
	}
	// Domains are normalised the same way as every other feed format.
	if c := got["phish.example"].Category; c != "phishing" {
		t.Errorf("phish.example category = %q, want phishing", c)
	}
	if c := got["miner.example"].Category; c != "cryptomining" {
		t.Errorf("miner.example category = %q, want cryptomining", c)
	}

	// An unrecognised label leaves the category empty so the caller can fall
	// back to the feed's own — an unfamiliar word must not lose a block.
	rec, ok := got["unmapped.example"]
	if !ok {
		t.Fatal("unmapped.example was dropped; an unknown label must not lose the indicator")
	}
	if rec.Category != "" {
		t.Errorf("unmapped.example category = %q, want empty", rec.Category)
	}

	// An IP indicator is real intelligence with no name for DNS to block.
	if _, blocked := got["203.0.113.9"]; blocked {
		t.Error("an IP indicator was indexed as a domain")
	}
	if res.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the IP indicator)", res.Skipped)
	}
	if res.Accepted != 4 {
		t.Errorf("accepted = %d, want 4", res.Accepted)
	}
}

func TestParseObservatoryHonoursMinSeverity(t *testing.T) {
	got, res := collectObservatory(t, observatoryFeed, "high")

	for _, d := range []string{"c2.example", "phish.example"} {
		if _, ok := got[d]; !ok {
			t.Errorf("%s should survive a high floor", d)
		}
	}
	for _, d := range []string{"miner.example", "unmapped.example"} {
		if _, ok := got[d]; ok {
			t.Errorf("%s is below the high floor and should have been dropped", d)
		}
	}
	if res.BelowSeverity != 2 {
		t.Errorf("belowSeverity = %d, want 2", res.BelowSeverity)
	}
	// Severity filtering is counted separately from junk, so an operator can
	// tell "I asked for critical only" from "this feed is full of rubbish".
	if res.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", res.Skipped)
	}
}

func TestParseObservatoryKeepsIndicatorsWithNoSeverity(t *testing.T) {
	// Dropping an indicator because a field was missing would quietly lose
	// protection over a schema gap, which is the wrong way round.
	body := `{"indicators": [{"value": "nosev.example", "categories": ["malware"]}]}`
	got, _ := collectObservatory(t, body, "critical")
	if _, ok := got["nosev.example"]; !ok {
		t.Error("an indicator with no severity was dropped by a severity floor")
	}
}

func TestParseObservatoryRejectsUnblockableValues(t *testing.T) {
	// The same guards as every other format: a single-label entry would
	// blackhole a whole TLD, and there is no name in an IP to block.
	body := `{"indicators": [
		{"value": "com", "type": "domain"},
		{"value": "localhost", "type": "domain"},
		{"value": "2001:db8::1", "type": "domain"},
		{"value": "", "type": "domain"},
		{"value": "https://evil.example/path", "type": "url"},
		{"value": "good.example", "type": "domain"}
	]}`
	got, res := collectObservatory(t, body, "")
	if len(got) != 1 {
		t.Fatalf("indexed %v, want only good.example", got)
	}
	if _, ok := got["good.example"]; !ok {
		t.Error("good.example was not indexed")
	}
	if res.Skipped != 5 {
		t.Errorf("skipped = %d, want 5", res.Skipped)
	}
}

func TestParseObservatoryToleratesSchemaDrift(t *testing.T) {
	// A feed is a file served by a remote host. Odd shapes cost the indicator
	// that carries them, never the whole feed.
	body := `{
	  "generated_at": 12345,
	  "meta": {"nested": {"anything": [1, 2, 3]}},
	  "indicators": [
	    {"value": "one.example", "type": "domain", "categories": "phishing"},
	    {"value": "two.example", "type": "domain", "categories": ["c2", 7, null]},
	    {"value": "three.example", "type": "domain", "category": "malware"},
	    {"value": "four.example", "type": "Domain ", "severity": "HIGH", "categories": []},
	    {"value": "five.example", "type": "domain", "severity": 3, "categories": ["malware"]}
	  ],
	  "count": 5
	}`
	got, res := collectObservatory(t, body, "")

	if len(got) != 5 {
		t.Fatalf("indexed %d indicators, want 5: %v", len(got), got)
	}
	if c := got["one.example"].Category; c != "phishing" {
		t.Errorf("a bare-string categories field gave %q, want phishing", c)
	}
	if c := got["two.example"].Category; c != "c2" {
		t.Errorf("a mixed-type categories array gave %q, want c2", c)
	}
	if c := got["three.example"].Category; c != "malware" {
		t.Errorf("a singular category field gave %q, want malware", c)
	}
	if c := got["four.example"].Category; c != "" {
		t.Errorf("an empty categories array gave %q, want empty", c)
	}
	// A numeric severity is unreadable, not a reason to lose the indicator.
	if _, ok := got["five.example"]; !ok {
		t.Error("an indicator with a numeric severity was dropped")
	}
	if res.Accepted != 5 {
		t.Errorf("accepted = %d, want 5", res.Accepted)
	}
	if !res.GeneratedAt.IsZero() {
		t.Errorf("a non-string generated_at should be ignored, got %v", res.GeneratedAt)
	}
}

func TestParseObservatoryAcceptsBareArray(t *testing.T) {
	body := `[{"value": "bare.example", "type": "domain", "categories": ["malware"]}]`
	got, _ := collectObservatory(t, body, "")
	if _, ok := got["bare.example"]; !ok {
		t.Error("a bare indicator array was not parsed")
	}
}

func TestParseObservatoryTruncatedKeepsWhatItRead(t *testing.T) {
	// A download cut off mid-array is still real intelligence up to the cut.
	body := `{"indicators": [
	  {"value": "first.example", "type": "domain", "categories": ["c2"]},
	  {"value": "second.example", "type": "domain", "categ`

	var got []string
	res, err := ParseObservatory(strings.NewReader(body), "", func(r ObservatoryRecord) {
		got = append(got, r.Domain)
	})
	if err == nil {
		t.Fatal("a truncated document should report an error")
	}
	if len(got) != 1 || got[0] != "first.example" {
		t.Errorf("emitted %v, want the indicators read before the cut", got)
	}
	if res.Accepted != 1 {
		t.Errorf("accepted = %d, want 1", res.Accepted)
	}
}

func TestParseObservatoryRejectsNonJSON(t *testing.T) {
	for name, body := range map[string]string{
		"hosts file":  "0.0.0.0 evil.example\n",
		"empty":       "",
		"json string": `"not a feed"`,
	} {
		if _, err := ParseObservatory(strings.NewReader(body), "", func(ObservatoryRecord) {}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseObservatoryIndicatorsNotAnArray(t *testing.T) {
	body := `{"indicators": {"value": "evil.example"}}`
	if _, err := ParseObservatory(strings.NewReader(body), "", func(ObservatoryRecord) {}); err == nil {
		t.Error("expected an error when indicators is not an array")
	}
}

func TestParseRejectsObservatoryFormat(t *testing.T) {
	// Line-parsing a JSON document would quietly extract nonsense from it.
	_, _, err := Parse(strings.NewReader(observatoryFeed), FormatObservatory, func(string) {})
	if err == nil {
		t.Error("Parse should refuse the observatory format outright")
	}
}
