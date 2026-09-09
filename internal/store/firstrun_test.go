package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
)

// The first-run decisions are the ones that cannot be taken later: a database
// with networks in it has run DNS Daddy before, and once seed has written its
// own row that is no longer visible. These tests pin both sides of that fork
// and the fact that it happens exactly once.

func defaultNetwork(t *testing.T, st *Store) Network {
	t.Helper()
	n, err := st.GetNetwork(context.Background(), clientacl.DefaultNetworkID)
	if err != nil {
		t.Fatalf("GetNetwork(%s): %v", clientacl.DefaultNetworkID, err)
	}
	return n
}

// A fresh install refuses unmatched clients. Someone who has just installed
// DNS Daddy has not yet told it who to serve, and guessing "everyone in the
// private ranges" is the guess this switch exists to stop making.
func TestAFreshDatabaseSeedsAdHocAccessOff(t *testing.T) {
	st := newTestStore(t)

	if got := defaultNetwork(t, st); got.AllowResolver {
		t.Fatal("a fresh install seeded the Default network with ad-hoc access on")
	}
	if got, err := st.GetSetting(context.Background(), SettingLocalDNSSECDefault); err != nil {
		t.Fatalf("GetSetting(%s): %v", SettingLocalDNSSECDefault, err)
	} else if got != "observe" {
		t.Fatalf("fresh installation DNSSEC default = %q, want observe (Learn)", got)
	}
}

// The upgrade case, and the one that would take DNS away from every existing
// deployment if it were wrong.
//
// The fixture is what an old database really looks like: networks present, the
// Default row's permission bit clear — because before this feature that bit
// granted nothing — and no first-run marker, because the version that wrote
// the database had never heard of one.
func TestAnUpgradePreservesTheAccessItAlreadyHad(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Rewind to the pre-feature state: an installation with a network, the
	// Default row unpermitted, and no record of any first-run decision.
	if _, err := st.CreateNetwork(ctx, NetworkInput{
		Name: ptr("HQ"), CIDRs: &[]string{"10.1.0.0/16"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		"UPDATE networks SET allow_resolver = 0 WHERE id = ?", clientacl.DefaultNetworkID); err != nil {
		t.Fatalf("rewinding the Default row: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		"DELETE FROM settings WHERE key IN (?, ?)", installMarkerKey, SettingLocalDNSSECDefault); err != nil {
		t.Fatalf("rewinding the first-run markers: %v", err)
	}
	st.Close()

	// Upgrade: the new binary opens the same database.
	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()

	if got := defaultNetwork(t, st); !got.AllowResolver {
		t.Fatal("an upgrade left ad-hoc access off; every client of this deployment would " +
			"have been refused after a routine version bump")
	}
	if got, err := st.GetSetting(ctx, SettingLocalDNSSECDefault); err != nil {
		t.Fatalf("GetSetting: %v", err)
	} else if got != "off" {
		t.Fatalf("upgrade DNSSEC default = %q, want off — Learn must not arrive unannounced", got)
	}
}

// The migration is a one-off, not a policy. An operator who turns ad-hoc access
// off after upgrading must find it still off tomorrow.
func TestTheUpgradeMigrationDoesNotRunTwice(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := st.CreateNetwork(ctx, NetworkInput{
		Name: ptr("HQ"), CIDRs: &[]string{"10.1.0.0/16"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	// The operator's own decision, after the feature exists.
	if _, err := st.UpdateNetwork(ctx, clientacl.DefaultNetworkID,
		NetworkInput{AllowResolver: ptr(false)}); err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}
	st.Close()

	for i := 0; i < 3; i++ {
		st, err = Open(path)
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		if got := defaultNetwork(t, st); got.AllowResolver {
			t.Fatalf("restart %d turned ad-hoc access back on; the operator's decision was overwritten", i)
		}
		st.Close()
	}
}

// Both first-run decisions come from one determination, so they can never
// disagree about whether an installation is new.
func TestTheFirstRunMarkerIsWrittenOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	st.Close()

	for i := 0; i < 3; i++ {
		st, err = Open(path)
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		var n int
		if err := st.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM settings WHERE key = ?", installMarkerKey).Scan(&n); err != nil {
			t.Fatalf("count marker: %v", err)
		}
		if n != 1 {
			t.Fatalf("first-run marker rows = %d after %d reopens, want 1", n, i+1)
		}
		st.Close()
	}
}

// The Default row is the policy catch-all and the ad-hoc access switch at once,
// and nothing recreates it. Deleting it would leave the resolver with no
// fallback policy and the dashboard with nowhere to put the control.
func TestTheDefaultNetworkCannotBeDeleted(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// A second network, so the "cannot delete the only network" rule is not
	// what is doing the work here.
	if _, err := st.CreateNetwork(ctx, NetworkInput{
		Name: ptr("HQ"), CIDRs: &[]string{"10.1.0.0/16"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	_, err := st.DeleteNetwork(ctx, clientacl.DefaultNetworkID)
	if !errors.Is(err, ErrProtectedNetwork) {
		t.Fatalf("DeleteNetwork(%s) = %v, want ErrProtectedNetwork", clientacl.DefaultNetworkID, err)
	}
	if _, err := st.GetNetwork(ctx, clientacl.DefaultNetworkID); err != nil {
		t.Fatalf("the Default network is gone after a refused delete: %v", err)
	}

	// And an ordinary network still deletes, so the guard is not simply
	// refusing everything.
	list, err := st.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	for _, n := range list {
		if n.ID == clientacl.DefaultNetworkID {
			continue
		}
		if _, err := st.DeleteNetwork(ctx, n.ID); err != nil {
			t.Fatalf("DeleteNetwork(%s): %v", n.ID, err)
		}
	}
}

// A database whose Default row was removed by hand is not a supported state,
// but it must not be a broken one: the seed leaves it alone rather than
// recreating a row whose access bit nobody chose.
func TestSeedDoesNotResurrectADeletedDefaultRow(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := st.CreateNetwork(ctx, NetworkInput{
		Name: ptr("HQ"), CIDRs: &[]string{"10.1.0.0/16"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		"DELETE FROM networks WHERE id = ?", clientacl.DefaultNetworkID); err != nil {
		t.Fatalf("removing the Default row: %v", err)
	}
	st.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()

	_, err = st.GetNetwork(ctx, clientacl.DefaultNetworkID)
	if err == nil {
		t.Fatal("seed recreated the Default row on a database that still has networks")
	}
	if !errors.Is(err, ErrNotFound) && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetNetwork returned an unexpected error: %v", err)
	}
}
