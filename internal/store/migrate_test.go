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

// oldFeedsSchema is the feeds table as it shipped before last_success_at.
const oldFeedsSchema = `
CREATE TABLE feeds (
    id                TEXT PRIMARY KEY,
    name              TEXT    NOT NULL,
    url               TEXT    NOT NULL,
    category          TEXT    NOT NULL,
    format            TEXT    NOT NULL DEFAULT 'auto',
    enabled           INTEGER NOT NULL DEFAULT 1,
    builtin           INTEGER NOT NULL DEFAULT 0,
    domain_count      INTEGER NOT NULL DEFAULT 0,
    last_refreshed_at INTEGER,
    last_status       TEXT    NOT NULL DEFAULT '',
    last_error        TEXT    NOT NULL DEFAULT '',
    etag              TEXT    NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);`

// An operator upgrading into the version that added last_success_at has feeds
// with refresh history and, crucially, an enabled/disabled choice per feed.
// Losing either would either re-enable a feed somebody deliberately turned off
// or make every working feed look like it had never downloaded.
func TestUpgradeFromPreLastSuccessDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-feeds.db")

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := raw.Exec(oldFeedsSchema); err != nil {
		t.Fatalf("apply old feeds schema: %v", err)
	}
	now := time.Now().UnixMilli()
	// A built-in feed the operator had switched on before the upgrade.
	if _, err := raw.Exec(`
		INSERT INTO feeds (id, name, url, category, format, enabled, builtin,
		                   domain_count, last_refreshed_at, last_status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, 1, 42, ?, 'ok', ?, ?)`,
		"legacy-feed", "Legacy feed", "https://example.org/list.txt", "malware", "hosts",
		now, now, now); err != nil {
		t.Fatalf("seed legacy feed: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a pre-upgrade database failed: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	f, err := st.GetFeed(ctx, "legacy-feed")
	if err != nil {
		t.Fatalf("GetFeed after upgrade: %v", err)
	}
	if !f.Enabled {
		t.Error("the operator's enabled choice was lost during upgrade")
	}
	if f.DomainCount != 42 {
		t.Errorf("DomainCount = %d, want 42", f.DomainCount)
	}
	if f.LastSuccess != nil {
		t.Errorf("LastSuccess = %v on a row written before the column existed, want nil", f.LastSuccess)
	}

	// The first refresh after the upgrade fills it in.
	if err := st.RecordFeedRefresh(ctx, "legacy-feed", FeedResult{Status: "ok", DomainCount: 43}); err != nil {
		t.Fatalf("RecordFeedRefresh: %v", err)
	}
	f, err = st.GetFeed(ctx, "legacy-feed")
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if f.LastSuccess == nil {
		t.Error("the new column is not written after an upgrade")
	}
}

// oldNetworkSchema is networks and network_cidrs as they shipped before
// per-network resolver access. Reproduced literally, for the same reason as
// oldSchema above: deriving it from the current schema would test nothing.
const oldNetworkSchema = `
CREATE TABLE policies (
    id          TEXT PRIMARY KEY,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    categories  TEXT    NOT NULL DEFAULT '[]',
    block_mode  TEXT    NOT NULL DEFAULT 'nxdomain',
    safe_search INTEGER NOT NULL DEFAULT 0,
    log_queries INTEGER NOT NULL DEFAULT 1,
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE TABLE networks (
    id         TEXT PRIMARY KEY,
    name       TEXT    NOT NULL,
    location   TEXT    NOT NULL DEFAULT '',
    policy_id  TEXT    NOT NULL REFERENCES policies(id),
    token      TEXT    UNIQUE,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE network_cidrs (
    id         INTEGER PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    cidr       TEXT NOT NULL,
    UNIQUE (network_id, cidr)
);`

// Scenario E of the deployment review: an existing operator upgrades.
//
// The requirement is not "it still starts" but "nobody's resolver exposure
// changed". Every network written before per-network access existed must come
// back unpermitted, so the bootstrap ACL alone keeps admitting exactly who it
// admitted before — an upgrade that silently granted access to every
// configured network would widen a live deployment's ACL without anyone asking
// for it.
func TestUpgradeFromPreResolverAccessDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := raw.Exec(oldNetworkSchema); err != nil {
		t.Fatalf("apply old schema: %v", err)
	}
	now := time.Now().UnixMilli()
	if _, err := raw.Exec(`
		INSERT INTO policies (id, name, created_at, updated_at) VALUES ('p_standard', 'Standard', ?, ?)`,
		now, now); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if _, err := raw.Exec(`
		INSERT INTO networks (id, name, policy_id, token, enabled, created_at, updated_at)
		VALUES ('n_hq', 'HQ', 'p_standard', 'legacytoken', 1, ?, ?)`, now, now); err != nil {
		t.Fatalf("seed network: %v", err)
	}
	if _, err := raw.Exec(`
		INSERT INTO network_cidrs (network_id, cidr) VALUES ('n_hq', '203.0.113.0/24')`); err != nil {
		t.Fatalf("seed cidr: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade open: %v", err)
	}
	defer st.Close()

	n, err := st.GetNetwork(context.Background(), "n_hq")
	if err != nil {
		t.Fatalf("GetNetwork after upgrade: %v", err)
	}
	if n.AllowResolver {
		t.Error("an upgrade granted resolver access to a pre-existing network, widening the ACL " +
			"of a running deployment without anyone asking")
	}
	if len(n.CIDRs) != 1 || n.CIDRs[0] != "203.0.113.0/24" {
		t.Errorf("cidrs = %v, want the existing range preserved", n.CIDRs)
	}
	if len(n.AcknowledgedPublicCIDRs) != 0 {
		t.Errorf("acknowledged = %v, want none — nobody has affirmed anything", n.AcknowledgedPublicCIDRs)
	}
	// And the DoH token, which never depended on the client ACL, still works.
	if id, err := st.NetworkByToken(context.Background(), "legacytoken"); err != nil || id != "n_hq" {
		t.Errorf("NetworkByToken after upgrade = %q, %v; want n_hq — an upgrade must not break "+
			"roaming DoH clients", id, err)
	}
}
