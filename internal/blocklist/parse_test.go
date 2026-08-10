package blocklist

import (
	"strings"
	"testing"
)

func collect(t *testing.T, body string, format Format) ([]string, int) {
	t.Helper()
	var got []string
	_, skipped, err := Parse(strings.NewReader(body), format, func(d string) {
		got = append(got, d)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return got, skipped
}

func TestParseHostsFormat(t *testing.T) {
	body := `# Title: some hosts file
# Comment line

0.0.0.0 evil.com
0.0.0.0	tabbed.example
127.0.0.1 also-evil.com  # trailing comment
0.0.0.0 UPPER.EXAMPLE
:: ipv6-sink.example
`
	got, _ := collect(t, body, FormatHosts)
	want := []string{"evil.com", "tabbed.example", "also-evil.com", "upper.example", "ipv6-sink.example"}
	assertDomains(t, got, want)
}

func TestParseHostsIgnoresRealMappings(t *testing.T) {
	// A hosts file line pointing at a real address is a name resolution, not a
	// block. Treating it as one would blackhole a legitimate internal host.
	body := "192.168.1.10 fileserver.internal\n0.0.0.0 evil.com\n"
	got, _ := collect(t, body, FormatHosts)
	assertDomains(t, got, []string{"evil.com"})
}

func TestParseDomainsFormat(t *testing.T) {
	body := `! adblock-style comment
; another comment
evil.com
sub.evil.com

not a domain
1.2.3.4
localhost
`
	got, _ := collect(t, body, FormatDomains)
	assertDomains(t, got, []string{"evil.com", "sub.evil.com"})
}

func TestParseRejectsBareIPsAndSingleLabels(t *testing.T) {
	// A single-label entry would block an entire TLD if a feed shipped one by
	// mistake, which is the kind of failure that takes a network offline.
	body := "com\nlocalhost\n8.8.8.8\n2001:db8::1\nevil.com\n"
	got, _ := collect(t, body, FormatDomains)
	assertDomains(t, got, []string{"evil.com"})
}

func TestParseAdblockFormat(t *testing.T) {
	body := `||evil.com^
||tracker.example^$third-party
||plain.example
@@||allowlisted.example^
example.com##.ad-banner
`
	got, _ := collect(t, body, FormatAdblock)
	assertDomains(t, got, []string{"evil.com", "tracker.example", "plain.example"})
}

func TestParseAutoDetectsPerLine(t *testing.T) {
	body := "0.0.0.0 hosts-style.example\nbare.example\n||adblock.example^\n"
	got, _ := collect(t, body, FormatAuto)
	assertDomains(t, got, []string{"hosts-style.example", "bare.example", "adblock.example"})
}

func TestParseCountsSkippedWithoutFailing(t *testing.T) {
	// Third-party feeds contain junk. One bad line must not cost a whole
	// category of protection.
	body := "evil.com\n<<<not a domain>>>\nok.example\n"
	got, skipped := collect(t, body, FormatDomains)
	assertDomains(t, got, []string{"evil.com", "ok.example"})
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
}

func TestParseHandlesVeryLongLines(t *testing.T) {
	long := "# " + strings.Repeat("x", 200_000)
	body := long + "\nevil.com\n"
	got, _ := collect(t, body, FormatDomains)
	assertDomains(t, got, []string{"evil.com"})
}

func assertDomains(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d domains %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("domain[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
