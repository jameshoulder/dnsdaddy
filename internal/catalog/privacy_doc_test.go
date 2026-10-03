package catalog

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func defaultFeedDisclosure(t *testing.T, feeds []Feed) string {
	t.Helper()
	hosts := map[string]bool{}
	ids := map[string]bool{}
	count := 0
	var rows strings.Builder
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		u, err := url.Parse(f.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || ids[f.ID] {
			t.Fatalf("invalid or duplicate default feed: %s", f.ID)
		}
		ids[f.ID] = true
		hosts[u.Hostname()] = true
		count++
		fmt.Fprintf(&rows, "| `%s` | %s | `%s` | `%s` |\n", f.ID, f.Name, f.URL, f.Category)
	}
	if count == 0 {
		t.Fatal("no enabled feeds to disclose")
	}
	return fmt.Sprintf("<!-- default-feed-disclosure:start -->\nDefault-enabled feeds: **%d**. Initial receiving hosts: **%d**. Disabled built-in feeds: **%d**.\n\n| Feed ID | Name | Initial download URL | Category |\n|---|---|---|---|\n%s<!-- default-feed-disclosure:end -->", count, len(hosts), len(feeds)-count, rows.String())
}

func TestPrivacyDisclosureExactlyMatchesDefaultFeeds(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "privacy.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	const start = "<!-- default-feed-disclosure:start -->"
	const end = "<!-- default-feed-disclosure:end -->"
	if strings.Count(doc, start) != 1 || strings.Count(doc, end) != 1 {
		t.Fatal("missing/duplicate feed disclosure boundaries")
	}
	a, z := strings.Index(doc, start), strings.Index(doc, end)
	if z < a {
		t.Fatal("invalid disclosure boundaries")
	}
	want := defaultFeedDisclosure(t, DefaultFeeds)
	if got := doc[a : z+len(end)]; got != want {
		t.Fatalf("privacy disclosure drift; replace the bounded block with:\n%s", want)
	}
}

func TestFeedDisclosureIncludesMembershipCountsAndURLs(t *testing.T) {
	original := defaultFeedDisclosure(t, DefaultFeeds)
	for _, mutation := range []func([]Feed){
		func(f []Feed) { f[0].Enabled = false },
		func(f []Feed) { f[0].URL += "changed" },
		func(f []Feed) { f[0].Name += "changed" },
		func(f []Feed) { f[0].Category = "changed" },
	} {
		copy := append([]Feed(nil), DefaultFeeds...)
		mutation(copy)
		if defaultFeedDisclosure(t, copy) == original {
			t.Fatal("changed feed would not change exact disclosure")
		}
	}
}
