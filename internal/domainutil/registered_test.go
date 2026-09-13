package domainutil_test

import (
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
)

// TestRegisteredDomain covers the cases the first-seen index depends on. The
// detector-facing behaviour is pinned by internal/detect's own tests; these
// are the ones that decide whether a row is created and under what key.
func TestRegisteredDomain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		parent string
		ok     bool
		why    string
	}{
		{"example.com", "example.com", true, "an apex lookup is attributed to itself"},
		{"www.example.com", "example.com", true, "a subdomain rolls up to its registered domain"},
		{"a.b.c.example.co.uk", "example.co.uk", true, "a multi-label public suffix is one registered domain"},
		{"com", "", false, "a bare public suffix is not a registered domain"},
		{"co.uk", "", false, "nor a bare multi-label one"},
		{"printer", "", false, "a single label cannot have a registered domain"},
		{"printer.corp.local", "", false, "a private namespace is not something anyone registered"},
		{"nas.home", "", false, "nor is .home"},
		{"host.internal", "", false, "nor .internal"},

		// An IP literal arriving as a QNAME. I expected the public suffix
		// list's default rule to treat "4" as an unknown top-level label and
		// hand back "3.4" as a registered domain; it does not — x/net's
		// EffectiveTLDPlusOne refuses an all-numeric label. Pinned because the
		// first-seen index depends on it: if this ever started returning a
		// value, every reverse lookup and every scanner probing by address
		// would mint an index row.
		{"1.2.3.4", "", false, "an address is not a registered domain"},
		{"8.8.8.8.in-addr.arpa", "8.in-addr.arpa", true, "reverse lookups do have a registered domain, under arpa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, _, ok := domainutil.RegisteredDomain(tc.name)
			if ok != tc.ok || parent != tc.parent {
				t.Errorf("RegisteredDomain(%q) = (%q, %v), want (%q, %v) — %s",
					tc.name, parent, ok, tc.parent, tc.ok, tc.why)
			}
		})
	}
}

// TestRegisteredDomainIsCaseFoldedByNormalize. RegisteredDomain itself assumes
// a normalised name, so the fold has to happen before it. Both spellings of a
// punycode label must reach one key or the index grows a row per capitalisation
// an attacker chooses.
func TestRegisteredDomainIsCaseFoldedByNormalize(t *testing.T) {
	upper := domainutil.Normalize("WWW.XN--CAF-DMA.EXAMPLE.COM")
	lower := domainutil.Normalize("www.xn--caf-dma.example.com")
	if upper != lower {
		t.Fatalf("Normalize disagreed on case: %q vs %q", upper, lower)
	}
	a, _, okA := domainutil.RegisteredDomain(upper)
	b, _, okB := domainutil.RegisteredDomain(lower)
	if !okA || !okB || a != b {
		t.Errorf("case folding produced two keys: %q and %q", a, b)
	}
}

// TestUnicodeNamesAreRejectedByNormalize, which is worth stating because it
// bounds what the first-seen index can claim. DNS carries A-labels on the
// wire, so a client asking for a Unicode name sends punycode and is indexed
// correctly. A Unicode string reaching this package came from somewhere other
// than the wire, and Normalize refuses it rather than inventing an encoding.
func TestUnicodeNamesAreRejectedByNormalize(t *testing.T) {
	if got := domainutil.Normalize("café.example.com"); got != "" {
		t.Errorf("Normalize(unicode) = %q, want \"\" — this package does no IDNA conversion", got)
	}
}
