package blocklist

import (
	"fmt"
	"io"
	"slices"
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

func collectObservatory(t *testing.T, body string) (map[string]ObservatoryRecord, ObservatoryResult) {
	t.Helper()
	got := map[string]ObservatoryRecord{}
	res, err := ParseObservatory(strings.NewReader(body), func(r ObservatoryRecord) {
		got[r.Domain] = r
	})
	if err != nil {
		t.Fatalf("ParseObservatory: %v", err)
	}
	return got, res
}

func TestParseObservatoryMapsCategories(t *testing.T) {
	got, res := collectObservatory(t, observatoryFeed)

	if res.Source != "dnsdaddy-threat-observatory" {
		t.Errorf("source = %q", res.Source)
	}
	want := time.Date(2026, 8, 26, 9, 15, 0, 0, time.UTC)
	if !res.GeneratedAt.Equal(want) {
		t.Errorf("generatedAt = %v, want %v", res.GeneratedAt, want)
	}

	// An indicator tagged both c2 and malware keeps BOTH, most severe first.
	// Collapsing them here would decide for the operator that one of the
	// categories they ticked does not apply to this domain.
	if got := got["c2.example"].Categories; !slices.Equal(got, []string{"malware", "c2"}) {
		t.Errorf("c2.example categories = %v, want [malware c2]", got)
	}
	// Domains are normalised the same way as every other feed format.
	if got := got["phish.example"].Categories; !slices.Equal(got, []string{"phishing"}) {
		t.Errorf("phish.example categories = %v, want [phishing]", got)
	}
	if got := got["miner.example"].Categories; !slices.Equal(got, []string{"cryptomining"}) {
		t.Errorf("miner.example categories = %v, want [cryptomining]", got)
	}

	// An unrecognised label leaves the category empty so the caller can fall
	// back to the feed's own — an unfamiliar word must not lose a block.
	rec, ok := got["unmapped.example"]
	if !ok {
		t.Fatal("unmapped.example was dropped; an unknown label must not lose the indicator")
	}
	if len(rec.Categories) != 0 {
		t.Errorf("unmapped.example categories = %v, want none", rec.Categories)
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
	got, res := collectObservatory(t, body)
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
	got, res := collectObservatory(t, body)

	if len(got) != 5 {
		t.Fatalf("indexed %d indicators, want 5: %v", len(got), got)
	}
	if c := got["one.example"].Categories; !slices.Equal(c, []string{"phishing"}) {
		t.Errorf("a bare-string categories field gave %v, want [phishing]", c)
	}
	if c := got["two.example"].Categories; !slices.Equal(c, []string{"c2"}) {
		t.Errorf("a mixed-type categories array gave %v, want [c2]", c)
	}
	if c := got["three.example"].Categories; !slices.Equal(c, []string{"malware"}) {
		t.Errorf("a singular category field gave %v, want [malware]", c)
	}
	if c := got["four.example"].Categories; len(c) != 0 {
		t.Errorf("an empty categories array gave %v, want none", c)
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
	got, _ := collectObservatory(t, body)
	if _, ok := got["bare.example"]; !ok {
		t.Error("a bare indicator array was not parsed")
	}
}

func TestParseObservatoryReportsTruncationToItsCaller(t *testing.T) {
	// The parser hands back what it read AND an error. Both matter: the error
	// is what makes the caller discard the lot rather than install a partial
	// feed, and callers that ignore it would silently do the wrong thing — so
	// the contract is pinned here.
	//
	// Nothing in DNS Daddy indexes this partial result. ValidateObservatory
	// rejects such a document before it can reach the cache or the index.
	body := `{"indicators": [
	  {"value": "first.example", "type": "domain", "categories": ["c2"]},
	  {"value": "second.example", "type": "domain", "categ`

	var got []string
	res, err := ParseObservatory(strings.NewReader(body), func(r ObservatoryRecord) {
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
	// And the document-level check refuses it outright, which is what actually
	// protects the blocklist.
	if err := ValidateObservatory(strings.NewReader(body)); err == nil {
		t.Error("ValidateObservatory accepted a truncated document")
	}
}

func TestParseObservatoryRejectsNonJSON(t *testing.T) {
	for name, body := range map[string]string{
		"hosts file":  "0.0.0.0 evil.example\n",
		"empty":       "",
		"json string": `"not a feed"`,
	} {
		if _, err := ParseObservatory(strings.NewReader(body), func(ObservatoryRecord) {}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseObservatoryIndicatorsNotAnArray(t *testing.T) {
	body := `{"indicators": {"value": "evil.example"}}`
	if _, err := ParseObservatory(strings.NewReader(body), func(ObservatoryRecord) {}); err == nil {
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

func TestValidateObservatoryAcceptsCompleteDocuments(t *testing.T) {
	for name, body := range map[string]string{
		"full feed":       observatoryFeed,
		"bare array":      `[{"value": "a.example", "type": "domain"}]`,
		"empty envelope":  `{"generated_at": "2026-08-26T09:15:00Z", "indicators": []}`,
		"unknown fields":  `{"meta": {"a": [1, 2, {"b": null}]}, "indicators": [], "count": 0}`,
		"trailing spaces": observatoryFeed + "\n\n  ",
	} {
		if err := ValidateObservatory(strings.NewReader(body)); err != nil {
			t.Errorf("%s: ValidateObservatory returned %v, want nil", name, err)
		}
	}
}

func TestValidateObservatoryRejectsAnythingIncomplete(t *testing.T) {
	// Each of these would, if accepted, replace a working blocklist with less
	// than the operator had before.
	cases := map[string]string{
		"truncated mid-indicator": `{"indicators": [{"value": "a.example", "typ`,
		"truncated mid-array":     `{"indicators": [{"value": "a.example"},`,
		"missing closing brace":   `{"indicators": []`,
		"empty body":              "",
		"whitespace only":         "   \n  ",
		"HTML error page":         "<!DOCTYPE html><html><body>502 Bad Gateway</body></html>",
		"plain text":              "0.0.0.0 evil.example\n",
		"bare JSON string":        `"not a feed"`,
		"two documents":           `{"indicators": []}{"indicators": []}`,
		"trailing junk":           `{"indicators": []} oops`,
	}
	for name, body := range cases {
		if err := ValidateObservatory(strings.NewReader(body)); err == nil {
			t.Errorf("%s: ValidateObservatory accepted it", name)
		}
	}
}

func TestValidateObservatoryDoesNotBufferTheDocument(t *testing.T) {
	// The validator runs over feeds that can be tens of megabytes, at download
	// time and again at load time. It must stream.
	var b strings.Builder
	b.WriteString(`{"indicators": [`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"value": "d%d.example", "type": "domain", "categories": ["malware"]}`, i)
	}
	b.WriteString(`]}`)

	r := &countingReader{r: strings.NewReader(b.String())}
	if err := ValidateObservatory(r); err != nil {
		t.Fatalf("ValidateObservatory: %v", err)
	}
	if r.maxBuf > 1<<20 {
		t.Errorf("validator read %d bytes in a single call; it should stream", r.maxBuf)
	}
}

type countingReader struct {
	r      io.Reader
	maxBuf int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if len(p) > c.maxBuf {
		c.maxBuf = len(p)
	}
	return c.r.Read(p)
}

// --- structural validation -------------------------------------------------
//
// ValidateObservatory is the gate a download passes through before it is
// allowed to replace a cache that is currently blocking traffic. A document
// that is syntactically valid JSON but is not a feed must not get through: it
// would be renamed over the good copy, recorded as a successful refresh, and
// then fail at load time, leaving the feed contributing nothing while the
// dashboard showed it healthy.

func TestValidateObservatoryRejectsWellFormedJSONThatIsNotAFeed(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{
			name: "indicators is an object",
			doc:  `{"indicators":{}}`,
			want: "not an array",
		},
		{
			name: "indicators is a string",
			doc:  `{"source":"x","indicators":"none"}`,
			want: "not an array",
		},
		{
			name: "indicators is a number",
			doc:  `{"indicators":42}`,
			want: "not an array",
		},
		{
			name: "no indicators at all",
			doc:  `{"generated_at":"2026-08-26T09:15:00Z","source":"dnsdaddy-threat-observatory"}`,
			want: "not a feed document",
		},
		{
			name: "an API error served as 200",
			doc:  `{"error":"rate limited","retry_after":60}`,
			want: "not a feed document",
		},
		{
			name: "an empty object",
			doc:  `{}`,
			want: "not a feed document",
		},
		{
			name: "a bare JSON string",
			doc:  `"nope"`,
			want: "not a JSON object or array",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateObservatory(strings.NewReader(tc.doc))
			if err == nil {
				t.Fatalf("ValidateObservatory(%s) accepted a document that is not a feed", tc.doc)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}

			// Whatever the validator refuses, the loader must refuse too, or a
			// cached file damaged on disk could still half-populate the index.
			if _, perr := ParseObservatory(strings.NewReader(tc.doc), func(ObservatoryRecord) {}); perr == nil {
				t.Errorf("ParseObservatory accepted %s but ValidateObservatory refused it; "+
					"the two must not disagree", tc.doc)
			}
		})
	}
}

func TestValidateObservatoryAcceptsRealDocuments(t *testing.T) {
	// The shapes that must keep working, including a deliberately empty feed:
	// there is no way to tell a cleaned-up list from a broken one, and the
	// documented contract is that a valid smaller feed is accepted.
	cases := map[string]string{
		"documented envelope": `{"generated_at":"2026-08-26T09:15:00Z","source":"dnsdaddy-threat-observatory",
			"indicators":[{"value":"evil.example","type":"domain","categories":["malware"]}]}`,
		"bare array":          `[{"value":"evil.example","type":"domain"}]`,
		"empty indicators":    `{"indicators":[]}`,
		"empty bare array":    `[]`,
		"unknown top field":   `{"schema_version":3,"indicators":[{"value":"evil.example"}]}`,
		"malformed indicator": `{"indicators":[{"value":"evil.example"},{"value":123},"junk"]}`,
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateObservatory(strings.NewReader(doc)); err != nil {
				t.Errorf("ValidateObservatory rejected a valid document: %v", err)
			}
		})
	}
}

func TestObservatoryValidationAndParsingCannotDrift(t *testing.T) {
	// The two are the same code path with and without an emit function, which
	// is the only way to be sure a document the validator waves through is one
	// the loader can actually use. This pins that property rather than the
	// implementation detail behind it.
	docs := []string{
		`{"indicators":[{"value":"a.example"}]}`,
		`{"indicators":{}}`,
		`{"indicators":[{"value":"a.example"}]}{"indicators":[]}`,
		`{"indicators":[{"value":"a.example"}`,
		`[{"value":"a.example"}`,
		`{}`,
		`not json at all`,
		``,
	}

	for _, doc := range docs {
		validateErr := ValidateObservatory(strings.NewReader(doc))
		_, parseErr := ParseObservatory(strings.NewReader(doc), func(ObservatoryRecord) {})
		if (validateErr == nil) != (parseErr == nil) {
			t.Errorf("validate and parse disagree on %q: validate=%v parse=%v", doc, validateErr, parseErr)
		}
	}
}
