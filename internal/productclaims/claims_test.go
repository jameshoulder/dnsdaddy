package productclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInventoryLoadsAndReferencesResolve(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Load(filepath.Join(root, InventoryFile))
	if err != nil {
		t.Fatal(err)
	}
	if dig := inv.CriticalDigest(); dig == "" || len(dig) != 64 {
		t.Fatalf("unexpected critical digest %q", dig)
	}
	if errs := inv.CheckReferences(root); len(errs) > 0 {
		for _, e := range errs {
			t.Error(e)
		}
	}
	if err := Check(root); err != nil {
		t.Fatal(err)
	}
	var critical int
	for _, c := range inv.Claims {
		if c.Critical {
			critical++
		}
		if c.Availability == "open-pr" && !strings.Contains(c.OpenPullRequest, "104") && c.ID == "feed.supply-chain-evidence" {
			t.Fatalf("feed claim should point at PR 104")
		}
	}
	if critical < 10 {
		t.Fatalf("expected a substantial critical claim set, got %d", critical)
	}
}

func TestExportRoundTripAndCheck(t *testing.T) {
	root := t.TempDir()
	srcRoot, err := FindRepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Load(filepath.Join(srcRoot, InventoryFile))
	if err != nil {
		t.Fatal(err)
	}
	// Copy inventory and create stub referenced paths that may be missing only
	// in the temp tree: re-run check against the real root for references.
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(srcRoot, InventoryFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, InventoryFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Export(root, inv, time.Unix(1_700_000_000, 0).UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if err := ArtefactsCurrent(root, inv); err != nil {
		t.Fatal(err)
	}
	// Mutate markdown and ensure check notices.
	mdPath := filepath.Join(root, MarkdownArtifact)
	if err := os.WriteFile(mdPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ArtefactsCurrent(root, inv); err == nil {
		t.Fatal("expected stale markdown detection")
	}
}

func TestCriticalDigestStableAcrossCaveatOrder(t *testing.T) {
	a := &Inventory{Claims: []Claim{{
		ID: "x", Title: "T", Maturity: "available", Availability: "main",
		Scope: "S", Caveats: []string{"b", "a"}, Critical: true,
	}}}
	b := &Inventory{Claims: []Claim{{
		ID: "x", Title: "T", Maturity: "available", Availability: "main",
		Scope: "S", Caveats: []string{"a", "b"}, Critical: true,
	}}}
	if a.CriticalDigest() != b.CriticalDigest() {
		t.Fatal("digest should ignore caveat order")
	}
}
