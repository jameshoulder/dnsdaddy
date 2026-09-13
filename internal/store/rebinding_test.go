package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func strp(s string) *string { return &s }

// TestExemptionsRoundTrip. They are read on the answer path through
// ListPolicies, so a write that does not come back is an exemption an operator
// set and never got.
func TestExemptionsRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	p, err := st.CreatePolicy(ctx, PolicyInput{
		Name:                strp("Office"),
		RebindingExemptions: &[]string{"10.0.0.0/8", "192.168.10.0/24"},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if len(p.RebindingExemptions) != 0 {
		// CreatePolicy returns the row it wrote; the exemptions are read back
		// by ListPolicies, which is what the engine uses.
		t.Logf("create returned %v", p.RebindingExemptions)
	}

	got, err := st.GetPolicy(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if strings.Join(got.RebindingExemptions, ",") != "10.0.0.0/8,192.168.10.0/24" {
		t.Errorf("exemptions = %v, want both in masked form", got.RebindingExemptions)
	}
}

// TestAnExemptionIsStoredMasked, so what the engine matches against is what
// the operator meant rather than a prefix with stray host bits.
func TestAnExemptionIsStoredMasked(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// Host bits are refused outright rather than silently masked: an operator
	// who wrote 10.1.2.3/8 may have meant a host, and guessing which would
	// either exempt far more than they asked or far less.
	if _, err := st.CreatePolicy(ctx, PolicyInput{
		Name:                strp("Sloppy"),
		RebindingExemptions: &[]string{"10.1.2.3/8"},
	}); err == nil {
		t.Error("an exemption with host bits set was accepted")
	}
}

// TestADefaultRouteExemptionIsRefusedByTheStore. The API is one writer; the
// store is the one path all of them go through, so the check lives here too.
func TestADefaultRouteExemptionIsRefusedByTheStore(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		_, err := st.CreatePolicy(ctx, PolicyInput{
			Name:                strp("Everything " + cidr),
			RebindingExemptions: &[]string{cidr},
		})
		if err == nil {
			t.Errorf("%s was accepted as an exemption", cidr)
			continue
		}
		if !strings.Contains(err.Error(), "every address") {
			t.Errorf("the error for %s does not explain why: %v", cidr, err)
		}
	}
}

// TestAMalformedExemptionFailsTheWholeWrite rather than being skipped. An
// operator whose exemption was silently dropped believes a range is reachable
// when it is being filtered.
func TestAMalformedExemptionFailsTheWholeWrite(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	_, err := st.CreatePolicy(ctx, PolicyInput{
		Name:                strp("Typo"),
		RebindingExemptions: &[]string{"10.0.0.0/8", "not-a-cidr"},
	})
	if err == nil {
		t.Fatal("a malformed exemption was accepted")
	}

	// And nothing was half-written.
	all, err := st.ListPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		if p.Name == "Typo" {
			t.Error("the policy was created despite the failed exemption list")
		}
	}
}

// TestClearingExemptionsIsPossible: nil means unchanged, empty means none.
// Without the distinction an operator could add an exemption and never remove
// it.
func TestClearingExemptionsIsPossible(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	p, err := st.CreatePolicy(ctx, PolicyInput{
		Name:                strp("Office"),
		RebindingExemptions: &[]string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// nil: unchanged.
	if _, err := st.UpdatePolicy(ctx, p.ID, PolicyInput{Name: strp("Office renamed")}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	got, _ := st.GetPolicy(ctx, p.ID)
	if len(got.RebindingExemptions) != 1 {
		t.Errorf("an unrelated update cleared the exemptions: %v", got.RebindingExemptions)
	}

	// empty: cleared.
	if _, err := st.UpdatePolicy(ctx, p.ID, PolicyInput{RebindingExemptions: &[]string{}}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	got, _ = st.GetPolicy(ctx, p.ID)
	if len(got.RebindingExemptions) != 0 {
		t.Errorf("exemptions survived being cleared: %v", got.RebindingExemptions)
	}
}

// TestTheRebindingInstallDefaultIsRecordedOnce, and says "on" only for a
// database that has never run DNS Daddy before.
func TestTheRebindingInstallDefaultIsRecordedOnce(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	v, err := st.GetSetting(ctx, SettingRebindingDefault)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if v != "on" {
		t.Errorf("a fresh database recorded %q, want \"on\"", v)
	}
}

// TestAnUpgradeDoesNotStartFiltering is the upgrade contract seen from the
// database: a store that already has networks is not a fresh install, and must
// not have the filter switched on underneath it.
//
// The marker used by the DNSSEC decision is deliberately not reused, and this
// test is why: every installation that upgraded before this setting existed
// already has that marker, so keying off it would skip the decision for
// exactly the databases that need it taken.
func TestAnUpgradeDoesNotStartFiltering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upgrade.db")

	// A database that has run before: seeded, and then the new setting
	// removed to model a binary that predates it.
	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	if _, err := first.db.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", SettingRebindingDefault); err != nil {
		t.Fatalf("delete setting: %v", err)
	}
	first.Close()

	// Reopening runs the seed again, which is where the decision is taken.
	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	v, err := second.GetSetting(ctx, SettingRebindingDefault)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if v != "off" {
		t.Errorf("an upgrade recorded %q, want \"off\": the filter would have switched itself on", v)
	}
}
