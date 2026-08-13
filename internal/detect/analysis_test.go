package detect

import (
	"strings"
	"testing"
	"time"
)

func TestSplitRegisteredDomain(t *testing.T) {
	cases := []struct {
		name      string
		parent    string
		sub       string
		hasParent bool
		why       string
	}{
		{"www.example.com", "example.com", "www", true, ""},
		{"a.b.c.example.co.uk", "example.co.uk", "a.b.c", true, "multi-label public suffix"},
		{"example.com", "example.com", "", true, "an apex query is still attributable"},
		{"com", "", "", false, "a bare public suffix has no registered domain"},
		{"co.uk", "", "", false, "a bare multi-label public suffix likewise"},
		{"printer", "", "", false, "a single label cannot have a registered domain"},
		{"printer.corp.local", "", "", false, "private namespace"},
		{"wpad.corp.internal", "", "", false, "private namespace"},
		{"host.home", "", "", false, "private namespace"},
		{"nas.lan", "", "", false, "private namespace"},
		{"tunnel.example", "tunnel.example", "", true, "reserved documentation TLD is treated normally"},
		{"a.b.tunnel.example", "tunnel.example", "a.b", true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent, sub, ok := split(tc.name)
			if ok != tc.hasParent {
				t.Fatalf("ok = %v, want %v (%s)", ok, tc.hasParent, tc.why)
			}
			if parent != tc.parent {
				t.Errorf("parent = %q, want %q", parent, tc.parent)
			}
			if sub != tc.sub {
				t.Errorf("sub = %q, want %q", sub, tc.sub)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	if h := shannonEntropy(""); h != 0 {
		t.Errorf("entropy of empty string = %v, want 0", h)
	}
	if h := shannonEntropy("aaaaaaaa"); h != 0 {
		t.Errorf("entropy of a constant string = %v, want 0", h)
	}
	// Four symbols, uniform: exactly 2 bits per character.
	if h := shannonEntropy("abcdabcd"); h < 1.99 || h > 2.01 {
		t.Errorf("entropy of a uniform 4-symbol string = %v, want 2", h)
	}
	// A word should sit well below an encoded label of the same length.
	word := shannonEntropy("newsletters")
	encoded := shannonEntropy("mfzwizltoqyc")
	if word >= encoded {
		t.Errorf("entropy failed to separate a word (%.2f) from an encoded label (%.2f)", word, encoded)
	}
}

func TestLooksEncoded(t *testing.T) {
	encoded := []string{
		"mfzwizltoqycu4ylbmnqxgzjan52geylu", // base32
		"a3f9c2e81b7d4056a3f9c2e81b7d4056",  // hex
		"2b7f6c1d9e4a8350fbca27de91056a4c",  // hex
		"kzq2w7vx3mb5nrt4pdj6",              // base32-alphabet, low vowels
	}
	notEncoded := []string{
		"www",
		"static",
		"newsletter",
		"my-company-name",
		"login-portal-uk",
		"images",
		"shortish",                  // below the length floor
		"the-quick-brown-fox-jumps", // words with hyphens
	}

	for _, s := range encoded {
		if !looksEncoded(s) {
			t.Errorf("looksEncoded(%q) = false, want true", s)
		}
	}
	for _, s := range notEncoded {
		if looksEncoded(s) {
			t.Errorf("looksEncoded(%q) = true, want false", s)
		}
	}
}

// Entropy per character is bounded by log2(length), so a short label cannot
// clear a 4-bit threshold however random it is. This pins the length gate that
// stops the tunnel detector measuring length and calling it randomness.
func TestEntropyLengthCaveat(t *testing.T) {
	short := "abcdefgh" // 8 distinct characters: exactly 3 bits, the maximum
	if h := shannonEntropy(short); h > 3.01 {
		t.Fatalf("entropy of an 8-character string = %v, which exceeds log2(8)", h)
	}
	if len(short) >= minEntropyLabelLen {
		t.Errorf("minEntropyLabelLen = %d does not exclude an 8-character label", minEntropyLabelLen)
	}
}

func TestRamp(t *testing.T) {
	cases := []struct{ v, floor, ceiling, want float64 }{
		{0, 10, 20, 0},
		{10, 10, 20, 0},
		{15, 10, 20, 0.5},
		{20, 10, 20, 1},
		{99, 10, 20, 1},
		{-5, 10, 20, 0},
	}
	for _, tc := range cases {
		if got := ramp(tc.v, tc.floor, tc.ceiling); got != tc.want {
			t.Errorf("ramp(%v, %v, %v) = %v, want %v", tc.v, tc.floor, tc.ceiling, got, tc.want)
		}
	}
}

func TestExclusionsMatchSuffixes(t *testing.T) {
	ex := NewExclusions([]string{"vendor.example"}, false)

	shouldMatch := []string{
		"vendor.example",
		"api.vendor.example",
		"deep.nested.api.vendor.example",
		"1.2.3.4.zen.spamhaus.org",
		"a.b.c.d.e.f.ip6.arpa",
		"4.3.2.1.in-addr.arpa",
		"something.akamaiedge.net",
	}
	shouldNot := []string{
		"vendor.example.com", // a different registered domain entirely
		"notvendor.example",
		"spamhaus.org.evil.example",
		"example.com",
	}

	for _, n := range shouldMatch {
		if !ex.Excluded(n) {
			t.Errorf("Excluded(%q) = false, want true", n)
		}
	}
	for _, n := range shouldNot {
		if ex.Excluded(n) {
			t.Errorf("Excluded(%q) = true, want false", n)
		}
	}
}

func TestExclusionsCanBeDisabled(t *testing.T) {
	bare := NewExclusions(nil, true)
	if bare.Excluded("1.2.3.4.zen.spamhaus.org") {
		t.Error("defaults were applied despite skipDefaults")
	}
	if bare.Len() != 0 {
		t.Errorf("bare exclusion set has %d entries, want 0", bare.Len())
	}
}

// Malformed and hostile input reaches this package straight off the network,
// so it must not panic on anything.
func TestAnalysisHandlesMalformedInput(t *testing.T) {
	inputs := []string{
		"",
		".",
		"..",
		"...............",
		strings.Repeat("a", 1024),
		strings.Repeat("a.", 500),
		strings.Repeat(".", 300),
		"xn--",
		"xn--a.xn--b",
		"-",
		"_",
		"a..b",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + ".example.com",
	}

	ex := NewExclusions(nil, false)
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on input %q: %v", truncate(in), r)
				}
			}()
			split(in)
			shannonEntropy(in)
			looksEncoded(in)
			randomnessIndex(in)
			labelsOf(in)
			isTXTInfrastructure(in)
			ex.Excluded(in)
		}()
	}
}

// The same inputs must survive the full pipeline, not just the primitives.
func TestDetectorsHandleMalformedInput(t *testing.T) {
	e := New(defaultDetectorsForTest(), &recordingSink{}, NewExclusions(nil, false), Options{}, testLogger())

	now := time.Now()
	for _, name := range []string{
		"", ".", "..", strings.Repeat("a.", 400), strings.Repeat("z", 300),
		"a..b.example.com", "xn--.xn--.example.com",
	} {
		for _, qtype := range []string{"A", "TXT", "NULL", "TYPE65535", ""} {
			e.ingest(Observation{Time: now, ClientIP: "10.0.0.1", QName: name, QType: qtype, Rcode: "NXDOMAIN"})
		}
	}
	// Evaluating must not panic either.
	e.evaluate(nil, now.Add(time.Hour)) //nolint:staticcheck // nil ctx is only passed to sinks, and there is no sink here
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
