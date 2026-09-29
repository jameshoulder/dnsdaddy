package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The overview's measured block is only as honest as these rows. Each test
// here pins one property the API relies on and cannot check for itself.

func TestErrorsAreCountedInTheSameRollupRowAsQueries(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	events := []QueryEvent{
		{Time: now, Domain: "ok.example", QType: "A", Action: ActionAllowed},
		{Time: now, Domain: "bad.example", QType: "A", Action: ActionBlocked, Category: "malware"},
		{Time: now, Domain: "down.example", QType: "A", Action: ActionError},
		{Time: now, Domain: "down2.example", QType: "A", Action: ActionError},
	}
	if err := st.InsertQueryBatch(ctx, events, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	totals, err := st.TotalsSince(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("TotalsSince: %v", err)
	}
	// Errors are inside the total, not beside it: the denominator of an error
	// rate is every query, and a failed one is still a query.
	if totals.Queries != 4 || totals.Blocked != 1 || totals.Errors != 2 {
		t.Errorf("totals = %+v, want 4 queries, 1 blocked, 2 errors", totals)
	}

	// A count-only batch — the zero-log mode — still counts errors, so a
	// privacy setting does not blind the error rate.
	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: now, Domain: "quiet.example", QType: "A", Action: ActionError},
	}, false); err != nil {
		t.Fatalf("InsertQueryBatch(count only): %v", err)
	}
	totals, err = st.TotalsSince(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("TotalsSince: %v", err)
	}
	if totals.Queries != 5 || totals.Errors != 3 {
		t.Errorf("after count-only batch: totals = %+v, want 5 queries, 3 errors", totals)
	}
}

func TestDistinctClientsAreCountedFromPresenceRowsNotQueryRows(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Three clients, one of them chatty, across two batches. The chatty one
	// must count once, and the second batch must not fail on rows the first
	// already wrote.
	batch := func(ips ...string) []QueryEvent {
		out := make([]QueryEvent, 0, len(ips))
		for _, ip := range ips {
			out = append(out, QueryEvent{Time: now, ClientIP: ip, Domain: "a.example", QType: "A", Action: ActionAllowed})
		}
		return out
	}
	if err := st.InsertQueryBatch(ctx, batch("10.0.0.1", "10.0.0.1", "10.0.0.2"), true); err != nil {
		t.Fatalf("first batch: %v", err)
	}
	if err := st.InsertQueryBatch(ctx, batch("10.0.0.1", "10.0.0.3"), true); err != nil {
		t.Fatalf("second batch: %v", err)
	}

	n, err := st.DistinctClientsSince(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DistinctClientsSince: %v", err)
	}
	if n != 3 {
		t.Errorf("distinct clients = %d, want 3", n)
	}

	// The de-duplication memory is an optimisation over an idempotent write,
	// so a store that has forgotten it — a restart — must still count right.
	st.clientHours = clientHourSet{}
	if err := st.InsertQueryBatch(ctx, batch("10.0.0.1"), true); err != nil {
		t.Fatalf("batch after forgetting: %v", err)
	}
	if n, _ := st.DistinctClientsSince(ctx, now.Add(-time.Hour)); n != 3 {
		t.Errorf("distinct clients after forgetting = %d, want 3", n)
	}

	// A window that excludes the hour sees nothing.
	if n, _ := st.DistinctClientsSince(ctx, now.Add(2*time.Hour)); n != 0 {
		t.Errorf("distinct clients in an empty window = %d, want 0", n)
	}
}

func TestClientPresenceIsNotRecordedWhenTheQueryRowIsNot(t *testing.T) {
	// Zero-log mode counts queries and keeps no per-query row. It must keep
	// no per-client row either: the row would name the device the operator
	// asked not to name.
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: now, ClientIP: "10.0.0.7", Domain: "a.example", QType: "A", Action: ActionAllowed},
	}, false); err != nil {
		t.Fatalf("InsertQueryBatch(count only): %v", err)
	}
	n, err := st.DistinctClientsSince(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DistinctClientsSince: %v", err)
	}
	if n != 0 {
		t.Errorf("count-only batch recorded %d client(s); it must record none", n)
	}
	// And an event with no address — log_client_ip off — writes nothing.
	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: now, Domain: "a.example", QType: "A", Action: ActionAllowed},
	}, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}
	if n, _ := st.DistinctClientsSince(ctx, now.Add(-time.Hour)); n != 0 {
		t.Errorf("an unattributed event recorded %d client(s)", n)
	}
}

func TestClientPresenceExpiresWithTheQueryLog(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	old := time.Now().UTC().AddDate(0, 0, -10)
	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: old, ClientIP: "10.0.0.9", Domain: "a.example", QType: "A", Action: ActionAllowed},
	}, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}
	if n, _ := st.DistinctClientsSince(ctx, old.Add(-time.Hour)); n != 1 {
		t.Fatalf("precondition: expected the client to be present, got %d", n)
	}

	// Seven days of query-log retention against ninety of rollups: the
	// presence row follows the shorter one.
	if _, err := st.Prune(ctx, 7, 90); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n, _ := st.DistinctClientsSince(ctx, old.Add(-time.Hour)); n != 0 {
		t.Errorf("client presence survived query-log retention: %d row(s)", n)
	}
}

func TestClientHourSetIsBoundedAndForgetsOldHours(t *testing.T) {
	var set clientHourSet
	hour := time.Now().UTC().Truncate(time.Hour)

	// Beyond the bound the set stops remembering and every later pair reads
	// as unseen — repeated no-op writes, never a missing one.
	var pairs []clientHour
	for i := 0; i < maxRememberedClients+5; i++ {
		pairs = append(pairs, clientHour{hour: hour.Unix(), ip: "10.0." + itoa(i/256) + "." + itoa(i%256)})
	}
	set.remember(pairs)
	if len(set.seen) != maxRememberedClients {
		t.Fatalf("remembered %d clients, want the bound %d", len(set.seen), maxRememberedClients)
	}
	unseen := set.unseen([]QueryEvent{
		{Time: hour, ClientIP: "10.0.0.0"},  // remembered
		{Time: hour, ClientIP: "10.0.64.4"}, // beyond the bound
		{Time: hour, ClientIP: "10.0.64.4"}, // duplicate within the batch
		{Time: hour, ClientIP: ""},          // unattributed
	})
	if len(unseen) != 1 || unseen[0].ip != "10.0.64.4" {
		t.Errorf("unseen = %+v, want only the client beyond the bound", unseen)
	}

	// A new hour discards the old one's memory rather than growing past it.
	next := hour.Add(time.Hour)
	set.remember([]clientHour{{hour: next.Unix(), ip: "10.1.1.1"}})
	if set.hour != next.Unix() || len(set.seen) != 1 {
		t.Errorf("after a new hour: hour=%d seen=%d, want the new hour with one client", set.hour, len(set.seen))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// oldStatsSchema is stats_hourly as it shipped before the errors column.
const oldStatsSchema = `
CREATE TABLE stats_hourly (
    hour       INTEGER NOT NULL,
    network_id TEXT    NOT NULL,
    category   TEXT    NOT NULL,
    total      INTEGER NOT NULL DEFAULT 0,
    blocked    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, network_id, category)
);`

func TestUpgradeRecordsWhenErrorCountingBegan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := raw.Exec(oldStatsSchema); err != nil {
		t.Fatalf("apply old schema: %v", err)
	}
	hour := time.Now().UTC().Truncate(time.Hour).Unix()
	if _, err := raw.Exec(`INSERT INTO stats_hourly (hour, network_id, category, total, blocked)
		VALUES (?, 'n_default', '', 40, 3)`, hour); err != nil {
		t.Fatalf("seed: %v", err)
	}
	raw.Close()

	before := time.Now().Add(-time.Second)
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open upgraded: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	// The old row survives and reads zero errors, because nothing counted
	// them — and the database says so.
	totals, err := st.TotalsSince(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("TotalsSince: %v", err)
	}
	if totals.Queries != 40 || totals.Blocked != 3 || totals.Errors != 0 {
		t.Errorf("totals = %+v, want the legacy row with zero errors", totals)
	}
	since, err := st.GetSetting(ctx, SettingStatsErrorsSince)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if since == "" {
		t.Fatal("the upgrade did not record when error counting began")
	}
	at, err := time.Parse(time.RFC3339, since)
	if err != nil || at.Before(before) {
		t.Errorf("errors-since = %q, want an RFC 3339 time at or after the upgrade", since)
	}

	// Reopening does not move it: the moment is when the column arrived,
	// not the last restart.
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if again, _ := st2.GetSetting(ctx, SettingStatsErrorsSince); again != since {
		t.Errorf("errors-since moved on reopen: %q → %q", since, again)
	}
}

func TestAFreshDatabaseHasCountedErrorsFromTheStart(t *testing.T) {
	st := newTestStore(t)
	since, err := st.GetSetting(context.Background(), SettingStatsErrorsSince)
	// Absent means every retained hour has been counted, which is the truth
	// for a database whose schema had the column from its first write.
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("a fresh database recorded an errors-since of %q (err %v); it should record none", since, err)
	}
}
