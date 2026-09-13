package audit_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/audit"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func auditStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// record pushes entries through a live logger and returns what was stored.
func record(t *testing.T, st *store.Store, entries ...audit.Entry) []store.AuditEntry {
	t.Helper()

	l := audit.New(st, audit.Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	go l.Run(ctx)
	for _, e := range entries {
		l.Record(e)
	}
	cancel()
	l.Wait()

	got, err := st.ListAudit(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	return got
}

// TestAPolicyEditStoresBothStates. The point of an audit log is being able to
// answer "what did it say before?", which needs both halves.
func TestAPolicyEditStoresBothStates(t *testing.T) {
	st := auditStore(t)
	got := record(t, st, audit.Entry{
		Actor: "admin", ActorKind: audit.ActorSession, Source: audit.SourceDashboard,
		Action: audit.ActionPolicyUpdate, TargetType: "policy", TargetID: "p_standard",
		Before: map[string]any{"name": "Standard", "categories": []string{"malware"}},
		After:  map[string]any{"name": "Standard", "categories": []string{"malware", "phishing"}},
	})

	if len(got) != 1 {
		t.Fatalf("%d entries, want 1", len(got))
	}
	e := got[0]
	if e.Action != audit.ActionPolicyUpdate || e.TargetID != "p_standard" {
		t.Errorf("entry = %+v", e)
	}
	if !strings.Contains(e.Before, "malware") || strings.Contains(e.Before, "phishing") {
		t.Errorf("before = %q, want the pre-edit categories", e.Before)
	}
	if !strings.Contains(e.After, "phishing") {
		t.Errorf("after = %q, want the post-edit categories", e.After)
	}
	if e.Actor != "admin" || e.Source != audit.SourceDashboard {
		t.Errorf("actor/source not recorded: %+v", e)
	}
}

// TestASecretNeverReachesTheDatabase.
//
// The audit log is the table an operator is most likely to export and hand to
// somebody else — an auditor, an insurer, a support engineer. A live
// credential in it is a credential disclosed. Redaction therefore happens on
// the way in, so there is no path from a struct field to disk that skips it.
func TestASecretNeverReachesTheDatabase(t *testing.T) {
	const secret = "sk-live-THIS-MUST-NEVER-BE-STORED"

	st := auditStore(t)
	got := record(t, st, audit.Entry{
		Action: audit.ActionProviderWrite, TargetType: "provider", TargetID: "safebrowsing",
		Before: map[string]any{"apiKey": "", "enabled": false},
		After: map[string]any{
			"apiKey":         secret,
			"api_key":        secret,
			"API-KEY":        secret,
			"token":          secret,
			"secret":         secret,
			"password":       secret,
			"passwordHash":   "$2a$10$abcdefghijklmnopqrstuv",
			"providerSecret": secret,
			"enabled":        true,
			"nested": map[string]any{
				"credentials": map[string]any{"key": secret},
				"list":        []any{map[string]any{"bearerToken": secret}},
			},
		},
	})

	if len(got) != 1 {
		t.Fatalf("%d entries, want 1", len(got))
	}
	blob := got[0].Before + got[0].After
	if strings.Contains(blob, secret) {
		t.Fatalf("the secret was stored verbatim:\n%s", blob)
	}
	if strings.Contains(blob, "$2a$10$") {
		t.Fatalf("a password hash was stored:\n%s", blob)
	}

	// The shape survives: an operator must still be able to see that a key was
	// set on this provider and that it had been empty before.
	var after map[string]any
	if err := json.Unmarshal([]byte(got[0].After), &after); err != nil {
		t.Fatal(err)
	}
	if after["apiKey"] != audit.Redacted {
		t.Errorf("apiKey = %v, want the redaction marker so \"a key was set\" is still visible", after["apiKey"])
	}
	if after["enabled"] != true {
		t.Errorf("a non-secret field was redacted: enabled = %v", after["enabled"])
	}

	var before map[string]any
	if err := json.Unmarshal([]byte(got[0].Before), &before); err != nil {
		t.Fatal(err)
	}
	if before["apiKey"] != "" {
		t.Errorf("an empty key was reported as %v; \"set\" and \"cleared\" must stay distinguishable", before["apiKey"])
	}
}

// TestRedactCoversNestedAndArrayShapes, because a credential inside a list of
// providers is as disclosed as one at the top level.
func TestRedactCoversNestedAndArrayShapes(t *testing.T) {
	out := audit.Redact(map[string]any{
		"providers": []any{
			map[string]any{"id": "p1", "apiKey": "one"},
			map[string]any{"id": "p2", "apiKey": "two"},
		},
	})
	raw, _ := json.Marshal(out)
	s := string(raw)
	if strings.Contains(s, "one") || strings.Contains(s, "two") {
		t.Errorf("a key inside an array survived redaction: %s", s)
	}
	if !strings.Contains(s, "p1") || !strings.Contains(s, "p2") {
		t.Errorf("redaction removed the identifiers too: %s", s)
	}
}

// TestATokenCreateStoresTheIdentifierNotTheToken.
func TestATokenCreateStoresTheIdentifierNotTheToken(t *testing.T) {
	st := auditStore(t)
	got := record(t, st, audit.Entry{
		Action: audit.ActionTokenCreate, TargetType: "token", TargetID: "tok_abc",
		After: map[string]any{"id": "tok_abc", "name": "CI", "prefix": "dd_12ab", "token": "dd_12ab_FULLSECRET"},
	})
	if strings.Contains(got[0].After, "FULLSECRET") {
		t.Fatalf("the raw token was stored: %s", got[0].After)
	}
	for _, want := range []string{"tok_abc", "CI", "dd_12ab"} {
		if !strings.Contains(got[0].After, want) {
			t.Errorf("after = %q, want it to still identify the token (%q)", got[0].After, want)
		}
	}
}

// TestAFullQueueDropsRatherThanBlocking. A management mutation that already
// committed must never be held up, or failed, because an audit row could not
// be queued.
func TestAFullQueueDropsRatherThanBlocking(t *testing.T) {
	st := auditStore(t)
	// Deliberately never Run: nothing drains the channel.
	l := audit.New(st, audit.Options{QueueSize: 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			l.Record(audit.Entry{Action: audit.ActionPolicyUpdate, TargetID: "p"})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a full queue")
	}
	if l.Stats().Dropped[audit.DropFull] == 0 {
		t.Error("nothing was counted as dropped although the queue holds one")
	}
}

// TestANilLoggerIsAWorkingSwitchedOffLogger.
func TestANilLoggerIsAWorkingSwitchedOffLogger(t *testing.T) {
	var l *audit.Logger
	l.Record(audit.Entry{Action: audit.ActionPolicyUpdate})
	l.Run(context.Background())
	l.Wait()

	s := l.Stats()
	if s.Written != 0 || len(s.Dropped) != len(audit.DropReasons()) {
		t.Errorf("a nil logger reported %+v", s)
	}
}

// TestShutdownWritesWhatIsQueued, so the last few changes before a restart are
// not the ones missing from the record.
func TestShutdownWritesWhatIsQueued(t *testing.T) {
	st := auditStore(t)
	got := record(t, st,
		audit.Entry{Action: audit.ActionPolicyCreate, TargetID: "p1"},
		audit.Entry{Action: audit.ActionPolicyUpdate, TargetID: "p2"},
		audit.Entry{Action: audit.ActionTokenRevoke, TargetID: "t1"},
	)
	if len(got) != 3 {
		t.Errorf("%d entries survived shutdown, want 3", len(got))
	}
}

// TestListingIsFilterableAndCapped, because an audit log is the thing an
// operator searches when something changed and they do not know what.
func TestListingIsFilterableAndCapped(t *testing.T) {
	st := auditStore(t)
	var entries []audit.Entry
	for i := 0; i < 20; i++ {
		entries = append(entries, audit.Entry{
			Action: audit.ActionPolicyUpdate, TargetType: "policy", TargetID: "p_standard",
		})
	}
	entries = append(entries, audit.Entry{
		Action: audit.ActionTokenRevoke, TargetType: "token", TargetID: "tok_1",
	})
	record(t, st, entries...)

	ctx := context.Background()
	byAction, err := st.ListAudit(ctx, store.AuditFilter{Action: audit.ActionTokenRevoke})
	if err != nil {
		t.Fatal(err)
	}
	if len(byAction) != 1 || byAction[0].TargetID != "tok_1" {
		t.Errorf("filtering by action returned %d rows", len(byAction))
	}

	byTarget, err := st.ListAudit(ctx, store.AuditFilter{TargetType: "policy", TargetID: "p_standard"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byTarget) != 20 {
		t.Errorf("filtering by target returned %d rows, want 20", len(byTarget))
	}

	all, err := st.ListAudit(ctx, store.AuditFilter{Limit: 1_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) > 500 {
		t.Errorf("an unbounded request returned %d rows", len(all))
	}
}

// TestThePrunerTouchesOnlyTheAuditLog.
//
// Both directions matter. Audit retention is a different question from
// query-log retention — an operator who shortened the latter for privacy said
// nothing about how long to keep a record of policy edits — and a pruner that
// crossed between them would answer the wrong question in whichever direction
// it leaked.
func TestThePrunerTouchesOnlyTheAuditLog(t *testing.T) {
	st := auditStore(t)
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -400).Truncate(time.Millisecond)

	// An ancient audit entry, and an ancient first-seen row beside it.
	if err := st.RecordAudit(ctx, store.AuditEntry{
		Time: old, Action: audit.ActionPolicyUpdate, TargetID: "p_old",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyFirstSeen(ctx, []store.FirstSeenTouch{
		{Domain: "old.example", Count: 1, At: old},
	}, -1); err != nil {
		t.Fatal(err)
	}
	fresh := store.AuditEntry{Time: time.Now().UTC(), Action: audit.ActionTokenCreate, TargetID: "t_new"}
	if err := st.RecordAudit(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	n, err := st.PruneAudit(ctx, time.Now().AddDate(0, 0, -90))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned %d audit rows, want 1", n)
	}

	// The recent audit row survives.
	left, _ := st.ListAudit(ctx, store.AuditFilter{Limit: 10})
	if len(left) != 1 || left[0].TargetID != "t_new" {
		t.Errorf("audit rows left = %+v", left)
	}
	// And the first-seen index is untouched: it is bounded by eviction, not by
	// anybody's retention setting.
	if _, err := st.LookupFirstSeen(ctx, "old.example"); err != nil {
		t.Error("the audit pruner deleted a first-seen row")
	}

	// The query-log pruner, in turn, must not reach the audit log — and the
	// row it is tested against has to be old enough for a seven-day cutoff to
	// reach it, or the test passes against a pruner that deletes everything
	// older than a week. An earlier version asserted on the fresh row and
	// could not fail.
	aged := store.AuditEntry{
		Time:   time.Now().UTC().AddDate(0, 0, -60).Truncate(time.Millisecond),
		Action: audit.ActionPolicyCreate, TargetID: "p_aged",
	}
	if err := st.RecordAudit(ctx, aged); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Prune(ctx, 7, 90); err != nil {
		t.Fatal(err)
	}
	after, _ := st.ListAudit(ctx, store.AuditFilter{Limit: 10})
	if len(after) != 2 {
		t.Errorf("the query-log prune removed audit rows: %d left, want the fresh and the 60-day-old one", len(after))
	}
	var sawAged bool
	for _, e := range after {
		if e.TargetID == "p_aged" {
			sawAged = true
		}
	}
	if !sawAged {
		t.Error("the query-log prune deleted a 60-day-old audit row")
	}
}

// TestLastAuditAtReportsNothingOnAFreshInstall, so doctor can tell "never
// written" from "written long ago" without guessing.
func TestLastAuditAtReportsNothingOnAFreshInstall(t *testing.T) {
	st := auditStore(t)
	at, err := st.LastAuditAt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !at.IsZero() {
		t.Errorf("a fresh install reported a last audit time of %v", at)
	}
}
