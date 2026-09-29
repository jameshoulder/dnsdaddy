package domainutil

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"already normal", "evil.com", "evil.com"},
		{"uppercase", "EVIL.COM", "evil.com"},
		{"trailing root dot", "evil.com.", "evil.com"},
		{"surrounding space", "  evil.com \t", "evil.com"},
		{"pasted url", "https://evil.com/login?next=1", "evil.com"},
		{"url without scheme", "evil.com/login", "evil.com"},
		{"with port", "evil.com:8080", "evil.com"},
		{"with userinfo", "user@evil.com", "evil.com"},
		{"subdomain", "a.b.evil.com", "a.b.evil.com"},
		{"underscore label", "_dmarc.evil.com", "_dmarc.evil.com"},
		{"hyphenated", "e-vil.co.uk", "e-vil.co.uk"},

		{"empty", "", ""},
		{"only dots", "...", ""},
		{"empty label", "a..com", ""},
		{"space inside", "ev il.com", ""},
		{"non-ascii", "évil.com", ""},
		{"too long label", strings.Repeat("a", 64) + ".com", ""},
		{"too long name", strings.Repeat("a.", 130) + "com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.in); got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSuffixes(t *testing.T) {
	var got []string
	Suffixes("a.b.evil.com", func(s string) bool {
		got = append(got, s)
		return false
	})

	want := []string{"a.b.evil.com", "b.evil.com", "evil.com", "com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Suffixes walked %v, want %v", got, want)
	}
}

func TestSuffixesStopsEarly(t *testing.T) {
	var visited int
	Suffixes("a.b.evil.com", func(s string) bool {
		visited++
		return s == "evil.com"
	})

	if visited != 3 {
		t.Errorf("visited %d suffixes, want 3 (should stop at the match)", visited)
	}
}

func TestSuffixesSingleLabel(t *testing.T) {
	var got []string
	Suffixes("localhost", func(s string) bool {
		got = append(got, s)
		return false
	})
	if !reflect.DeepEqual(got, []string{"localhost"}) {
		t.Errorf("got %v, want [localhost]", got)
	}
}

func TestIsSubdomainOf(t *testing.T) {
	tests := []struct {
		domain, parent string
		want           bool
	}{
		{"evil.com", "evil.com", true},
		{"login.evil.com", "evil.com", true},
		{"a.b.evil.com", "evil.com", true},
		{"evil.com", "login.evil.com", false},
		{"notevil.com", "evil.com", false},
		// The classic suffix-matching bug: "myevil.com" must not match "evil.com".
		{"myevil.com", "evil.com", false},
		{"evil.com.au", "evil.com", false},
	}

	for _, tt := range tests {
		if got := IsSubdomainOf(tt.domain, tt.parent); got != tt.want {
			t.Errorf("IsSubdomainOf(%q, %q) = %v, want %v", tt.domain, tt.parent, got, tt.want)
		}
	}
}

func BenchmarkSuffixes(b *testing.B) {
	set := map[string]bool{"evil.com": true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Suffixes("deeply.nested.subdomain.of.evil.com", func(s string) bool { return set[s] })
	}
}

// A person types names the way they read them; the query log holds them the
// way they were sent. NormalizeInput has to bridge the two, and refuse what
// is not a name at all.
func TestNormalizeInputBridgesTypedNamesToTheWireForm(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":                 "example.com",
		"  https://Evil.Example/path ": "evil.example",
		"bücher.example":               "xn--bcher-kva.example",
		"Bücher.Example.":              "xn--bcher-kva.example",
		"xn--bcher-kva.example":        "xn--bcher-kva.example",
		"10.0.0.1":                     "10.0.0.1",
	}
	for in, want := range cases {
		got, err := NormalizeInput(in)
		if err != nil {
			t.Errorf("NormalizeInput(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeInput(%q) = %q, want %q", in, got, want)
		}
	}
	// What the lookup profile maps or accepts is not for this test to
	// second-guess — a zero-width space maps away and a symbol becomes an
	// A-label, as in a browser. What can never be a name is refused.
	for _, bad := range []string{"", "   ", ".", "a..b", "not a domain", "exa mple.com", "tab\there.example",
		strings.Repeat("a", 64) + ".example", strings.Repeat("ab.", 200) + "example"} {
		if got, err := NormalizeInput(bad); err == nil {
			t.Errorf("NormalizeInput(%q) = %q, want an error", bad, got)
		}
	}
}
