package domainutil

import (
	"strings"
	"testing"
)

// FuzzNormalize checks that arbitrary input cannot panic, and that the output
// obeys the invariants the rest of the resolver relies on.
//
// Normalize is the single choke point every untrusted name passes through —
// DNS questions, feed lines, and operator-typed allow-list entries all reach
// the blocklist index through it. If it can emit something with a dot-run, an
// uppercase letter, or a stray pipe, then suffix matching and the Markdown
// report both inherit that bug.
func FuzzNormalize(f *testing.F) {
	seeds := []string{
		"example.com", "Sub.Example.com.", "xn--bcher-kva.example",
		"https://evil.com/path?x=1", "user@host.example:8080",
		"", ".", "..", "a..b", "-leading.example", "trailing-.example",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 200) + "com",
		"_dmarc.example.com", "192.168.1.1", "::1",
		"evil.com\x00.good.com", "evil.com\n", "eviI.com",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		got := Normalize(in)
		if got == "" {
			return // rejected, which is always a valid outcome
		}

		if len(got) > MaxLen {
			t.Fatalf("Normalize(%q) = %q, longer than the %d-byte DNS limit", in, got, MaxLen)
		}
		if got != strings.ToLower(got) {
			t.Fatalf("Normalize(%q) = %q, which is not lower-cased", in, got)
		}
		if strings.HasPrefix(got, ".") || strings.HasSuffix(got, ".") {
			t.Fatalf("Normalize(%q) = %q, which has a leading or trailing dot", in, got)
		}
		if strings.Contains(got, "..") {
			t.Fatalf("Normalize(%q) = %q, which contains an empty label", in, got)
		}

		// Only LDH plus underscore may survive. Anything else — a pipe, a
		// backtick, a control byte — would flow into the Markdown report and
		// the query log unescaped.
		for i := 0; i < len(got); i++ {
			c := got[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '-' || c == '_' || c == '.'
			if !ok {
				t.Fatalf("Normalize(%q) = %q, which contains disallowed byte %q at %d", in, got, c, i)
			}
		}

		// Idempotence: re-normalising an already normal name must not change
		// it, or the value stored in the database could differ from the value
		// matched at query time.
		if again := Normalize(got); again != got {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q", in, got, again)
		}
	})
}

// FuzzSuffixes checks the allocation-free suffix walk against arbitrary input.
// It runs on every DNS query, so a panic here is a remote denial of service.
func FuzzSuffixes(f *testing.F) {
	for _, s := range []string{
		"a.b.evil.com", "evil.com", "com", "", ".", "..", "a..b",
		strings.Repeat(".", 100), strings.Repeat("a.", 100) + "com",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		// The real invariant is that the walk is linear in the input: each
		// step consumes at least one byte, so it can never exceed one
		// iteration per byte plus the initial full name. (An earlier version
		// of this test asserted a constant cap, which a string of 300 dots
		// correctly violated — the walk was fine, the assertion was wrong.)
		maxSteps := len(in) + 1

		var seen []string
		Suffixes(in, func(s string) bool {
			seen = append(seen, s)
			if len(seen) > maxSteps {
				t.Fatalf("Suffixes(%q) produced %d suffixes, more than one per byte", in, len(seen))
			}
			return false
		})

		if len(seen) == 0 {
			t.Fatalf("Suffixes(%q) yielded nothing; it must always offer the full name", in)
		}
		if seen[0] != in {
			t.Fatalf("Suffixes(%q) started at %q, want the full name first", in, seen[0])
		}
		// Each step must be strictly shorter, otherwise the walk could loop.
		for i := 1; i < len(seen); i++ {
			if len(seen[i]) >= len(seen[i-1]) {
				t.Fatalf("Suffixes(%q) did not shrink: %q then %q", in, seen[i-1], seen[i])
			}
		}
	})
}
