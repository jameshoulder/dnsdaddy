package feedimport

import (
	"math"
	"net/url"
	"path/filepath"
	"testing"
)

func TestFiniteLimits(t *testing.T) {
	for _, n := range []int64{-1, math.MaxInt64, (1 << 30) + 1} {
		if _, _, _, err := (Limits{}).Normalize(n); err == nil {
			t.Fatalf("accepted %d", n)
		}
	}
	l, n, d, err := (Limits{}).Normalize(0)
	if err != nil || n != 128<<20 || l.Records != 1000000 || d.Seconds() != 90 {
		t.Fatal(l, n, d, err)
	}
	for _, l := range []Limits{{Records: -1}, {Records: 5000001}, {LocalRecords: -1}, {Domains: -1}, {Claims: -1}, {MemoryBytes: -1}, {TempBytes: -1}, {Timeout: "invalid"}, {Timeout: "0s"}, {Timeout: "11m"}} {
		if _, _, _, err := l.Normalize(0); err == nil {
			t.Fatal("invalid limit accepted", l)
		}
	}
}
func TestLocalURLPolicy(t *testing.T) {
	root := t.TempDir()
	good := "file://" + filepath.Join(root, "feed")
	for _, raw := range []string{good, "file://localhost" + filepath.Join(root, "feed")} {
		if n, e := LocalName(root, raw); e != nil || n != "feed" {
			t.Fatal(n, e)
		}
	}
	for _, raw := range []string{"file:relative", "https://feed.example/file", "file://remote" + root + "/feed", good + "?token=secret", good + "?", good + "#", good + "#secret", "file://user:pass@localhost" + root + "/feed", "file://" + root + "/../outside", "file://" + root + "-sibling/feed", good + "%00", "file://" + root + "/%2e%2e/outside"} {
		if _, e := LocalName(root, raw); e == nil {
			t.Error("accepted unsafe URL", url.PathEscape(raw))
		}
	}
}
