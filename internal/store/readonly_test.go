package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// dbState is the part of a database a diagnostic must not disturb.
type dbState struct {
	journalMode string
	policies    int
	networks    int
	feeds       int
}

func inspect(t *testing.T, path string) dbState {
	t.Helper()
	// A separate ordinary connection, so the reading itself is not the thing
	// under test.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open for inspection: %v", err)
	}
	defer db.Close()

	var s dbState
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&s.journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	for _, c := range []struct {
		table string
		into  *int
	}{{"policies", &s.policies}, {"networks", &s.networks}, {"feeds", &s.feeds}} {
		if err := db.QueryRow("SELECT count(*) FROM " + c.table).Scan(c.into); err != nil {
			t.Fatalf("count %s: %v", c.table, err)
		}
	}
	return s
}

// olderDeployment builds a database as an earlier binary would have left it:
// the schema applied, journalling left at the SQLite default, and none of the
// first-run defaults seeded.
func olderDeployment(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "existing.db")

	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=journal_mode(DELETE)", path))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

// `dnsdaddy doctor` documents that it changes nothing, and it reached the
// database through store.Open — which applies the schema, runs migrations,
// seeds first-run defaults and switches the database into WAL mode. Running a
// newer diagnostic binary against an older live deployment therefore modified
// it.
func TestOpenReadOnlyDoesNotMutateTheDatabase(t *testing.T) {
	path := olderDeployment(t)
	before := inspect(t, path)

	st, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	// Do the reads the diagnostic actually does.
	ctx := context.Background()
	if _, err := st.ListNetworks(ctx); err != nil {
		t.Errorf("ListNetworks: %v", err)
	}
	if _, err := st.ListPolicies(ctx); err != nil {
		t.Errorf("ListPolicies: %v", err)
	}
	if _, err := st.ListFeeds(ctx); err != nil {
		t.Errorf("ListFeeds: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	after := inspect(t, path)
	if after != before {
		t.Errorf("a read-only inspection changed the database\n before: %+v\n  after: %+v", before, after)
	}
}

// The contrast that makes the two functions worth keeping apart. This pins the
// mutation to store.Open deliberately: if Open ever stops seeding, this test
// should be updated rather than quietly passing for a new reason.
func TestOpenIsNotSafeForInspection(t *testing.T) {
	path := olderDeployment(t)
	before := inspect(t, path)

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	after := inspect(t, path)
	if after == before {
		t.Fatal("store.Open no longer mutates an existing database; if that is now true, " +
			"OpenReadOnly's reason for existing has changed and this test should say so")
	}
	if after.journalMode == before.journalMode && after.policies == before.policies {
		t.Errorf("expected Open to switch journalling and seed defaults; before %+v after %+v", before, after)
	}
}

// mode=ro is the guarantee; query_only is the belt to its braces. A write
// attempted through this handle must fail rather than succeed quietly.
func TestOpenReadOnlyRejectsWrites(t *testing.T) {
	st, err := OpenReadOnly(olderDeployment(t))
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer st.Close()

	if _, err := st.db.Exec("INSERT INTO policies (id, name) VALUES ('p_x', 'x')"); err == nil {
		t.Fatal("a write through the read-only handle succeeded")
	}
}

// Pointed at a mistyped data_dir, the diagnostic must report that there is no
// database — not manufacture one and then pronounce it healthy.
func TestOpenReadOnlyDoesNotCreateAMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")

	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("OpenReadOnly succeeded against a database that does not exist")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("OpenReadOnly created the database file it was asked to inspect")
	}
}

// The daemon holds the database open in WAL mode. Inspecting it while it runs
// is the normal case, and must see committed data.
func TestOpenReadOnlyReadsAliveDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.db")

	live, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer live.Close()

	ctx := context.Background()
	name := "Written while the daemon was running"
	if _, err := live.CreateNetwork(ctx, NetworkInput{
		Name: &name, CIDRs: &[]string{"192.168.9.0/24"},
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly against a live database: %v", err)
	}
	defer ro.Close()

	networks, err := ro.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	var found bool
	for _, n := range networks {
		if n.Name == name {
			found = true
		}
	}
	if !found {
		t.Error("the read-only handle did not see a network committed by the running daemon")
	}
}
