package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// oldSchema is the query_log table as it shipped before the dnssec column was
// added. Reproduced literally rather than derived from schema.sql, because the
// point of this test is to simulate a database written by the previous release
// — deriving it from the current schema would test nothing.
const oldSchema = `
CREATE TABLE query_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    client_ip   TEXT    NOT NULL DEFAULT '',
    client_name TEXT    NOT NULL DEFAULT '',
    network_id  TEXT    NOT NULL DEFAULT '',
    qname       TEXT    NOT NULL,
    qtype       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '',
    category    TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT '',
    proto       TEXT    NOT NULL DEFAULT '',
    elapsed_ms  INTEGER NOT NULL DEFAULT 0,
    cached      INTEGER NOT NULL DEFAULT 0
);`

// An upgrade must work on a database the previous release wrote. This is the
// path every existing operator takes, and it is not exercised by any test that
// starts from an empty directory.
func TestUpgradeFromPreDNSSECDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// Build a database that looks like the previous release's, complete with a
	// row of real data that must survive.
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := raw.Exec(oldSchema); err != nil {
		t.Fatalf("apply old schema: %v", err)
	}
	if _, err := raw.Exec(`
		INSERT INTO query_log (ts, client_ip, qname, qtype, action, reason)
		VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().UnixMilli(), "10.0.0.9", "legacy.example", "A", ActionAllowed, "Resolved"); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Now open it with the current code.
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a pre-upgrade database failed: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// The pre-existing row must still be readable, with the new column empty
	// rather than the read failing.
	rows, _, err := st.ListQueries(ctx, QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries after upgrade: %v", err)
	}
	var found bool
	for _, r := range rows {
		if r.Domain == "legacy.example" {
			found = true
			if r.DNSSEC != "" {
				t.Errorf("legacy row has dnssec=%q, want empty", r.DNSSEC)
			}
		}
	}
	if !found {
		t.Error("the row written by the previous release was lost during upgrade")
	}

	// And a new write using the new column must work.
	if err := st.InsertQueryBatch(ctx, []QueryEvent{{
		Time: time.Now(), Domain: "new.example", QType: "A",
		Action: ActionAllowed, DNSSEC: DNSSECValidated,
	}}, true); err != nil {
		t.Fatalf("insert after upgrade: %v", err)
	}

	rows, _, err = st.ListQueries(ctx, QueryFilter{Domain: "new.example", Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(rows) != 1 || rows[0].DNSSEC != DNSSECValidated {
		t.Errorf("new row did not round-trip its dnssec status: %+v", rows)
	}

	// The findings table is created by CREATE TABLE IF NOT EXISTS, so it should
	// simply appear.
	if _, err := st.CountFindings(ctx); err != nil {
		t.Errorf("findings table missing after upgrade: %v", err)
	}
}

// Startup runs the migration every time, so it has to be a no-op on a database
// that already has the column. A restart loop is not an acceptable failure
// mode for a resolver.
func TestMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repeat.db")

	for i := 0; i < 3; i++ {
		st, err := Open(path)
		if err != nil {
			t.Fatalf("Open #%d failed: %v", i+1, err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
}

// A finding written before a restart must still be there afterwards. Findings
// are the record of what was detected, and losing them on restart would make
// the detection engine useless for anything but a live dashboard.
func TestFindingsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.db")
	ctx := context.Background()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.InsertFindings(ctx, []Finding{{
		ID: "persist-1", Time: time.Now(), EventType: "dns_tunnel_suspected",
		Severity: "high", Confidence: 0.9, ClientIP: "10.0.0.5",
		Domain: "tunnel.example", Detail: `{"schemaVersion":"1.0"}`,
	}}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()

	got, err := st2.GetFinding(ctx, "persist-1")
	if err != nil {
		t.Fatalf("finding lost across restart: %v", err)
	}
	if got.Domain != "tunnel.example" || got.Severity != "high" {
		t.Errorf("finding came back altered: %+v", got)
	}
	if got.Detail != `{"schemaVersion":"1.0"}` {
		t.Errorf("detail did not round-trip: %q", got.Detail)
	}
}

// Findings carry random IDs, so a duplicate ID means the same finding is being
// written twice — a retried sink, say. Keeping the first and ignoring the
// second is the intended behaviour; an error would take down the sink.
func TestDuplicateFindingIsIgnoredNotAnError(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "dupe.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	f := Finding{ID: "dupe", Time: time.Now(), EventType: "nxdomain_burst",
		Severity: "medium", Summary: "first", Detail: "{}"}

	if err := st.InsertFindings(ctx, []Finding{f}); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	f.Summary = "second"
	if err := st.InsertFindings(ctx, []Finding{f}); err != nil {
		t.Fatalf("duplicate insert returned an error: %v", err)
	}

	got, err := st.GetFinding(ctx, "dupe")
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got.Summary != "first" {
		t.Errorf("summary = %q, want the first write to be kept", got.Summary)
	}
	n, err := st.CountFindings(ctx)
	if err != nil {
		t.Fatalf("CountFindings: %v", err)
	}
	if n != 1 {
		t.Errorf("stored %d findings, want 1", n)
	}
}

// Retention has to actually delete, or the database grows without bound on a
// long-running instance.
func TestPruneFindingsRespectsRetention(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "prune.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	now := time.Now()

	if err := st.InsertFindings(ctx, []Finding{
		{ID: "old", Time: now.Add(-40 * 24 * time.Hour), EventType: "x", Severity: "low", Detail: "{}"},
		{ID: "recent", Time: now.Add(-1 * time.Hour), EventType: "x", Severity: "low", Detail: "{}"},
	}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}

	removed, err := st.PruneFindings(ctx, 30)
	if err != nil {
		t.Fatalf("PruneFindings: %v", err)
	}
	if removed != 1 {
		t.Errorf("pruned %d rows, want 1", removed)
	}
	if _, err := st.GetFinding(ctx, "recent"); err != nil {
		t.Errorf("prune removed a finding inside the retention window: %v", err)
	}
	if _, err := st.GetFinding(ctx, "old"); err == nil {
		t.Error("prune left a finding older than the retention window")
	}

	// Zero must mean "keep everything", not "delete everything" — an operator
	// who unsets retention should not lose their data.
	if n, err := st.PruneFindings(ctx, 0); err != nil || n != 0 {
		t.Errorf("PruneFindings(0) = %d, %v; want 0, nil (retention disabled)", n, err)
	}
}
