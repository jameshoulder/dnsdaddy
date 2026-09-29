package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/evidence"
)

func seedActivity(t *testing.T, st *Store) time.Time {
	t.Helper()
	now := time.Now().UTC()
	ev := func(ago time.Duration, ip, name, domain, action, category, qtype string, elapsed int, cached bool) QueryEvent {
		return QueryEvent{
			Time: now.Add(-ago), ClientIP: ip, ClientName: name, NetworkID: "n_default",
			Domain: domain, QType: qtype, Action: action, Category: category,
			ElapsedMS: elapsed, Cached: cached,
		}
	}
	events := []QueryEvent{
		ev(10*time.Minute, "10.0.0.1", "laptop", "evil.example", ActionBlocked, "malware", "A", 1, false),
		ev(9*time.Minute, "10.0.0.1", "laptop", "evil.example", ActionBlocked, "malware", "AAAA", 1, false),
		ev(8*time.Minute, "10.0.0.2", "", "evil.example", ActionAllowed, "", "A", 40, false),
		ev(7*time.Minute, "10.0.0.2", "", "evil.example", ActionAllowed, "", "A", 2, true),
		ev(6*time.Minute, "10.0.0.2", "", "evil.example", ActionError, "", "A", 5000, false),
		ev(5*time.Minute, "10.0.0.1", "laptop", "fine.example", ActionAllowed, "", "A", 30, false),
		ev(4*time.Minute, "", "", "evil.example", ActionAllowed, "", "A", 10, false), // unattributed
		ev(3*time.Minute, "10.0.0.1", "laptop", "notevil.example", ActionAllowed, "", "A", 10, false),
		ev(48*time.Hour, "10.0.0.9", "", "evil.example", ActionBlocked, "malware", "A", 1, false), // outside the window
	}
	if err := st.InsertQueryBatch(context.Background(), events, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}
	return now
}

func TestActivitySummaryCountsOneNameExactlyWithinTheWindow(t *testing.T) {
	st := newTestStore(t)
	now := seedActivity(t, st)
	ctx := context.Background()

	sum, err := st.ActivitySummarySince(ctx, "evil.example", "", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("ActivitySummarySince: %v", err)
	}
	if sum.Queries != 6 || sum.Allowed != 3 || sum.Blocked != 2 || sum.Errors != 1 {
		t.Errorf("summary = %+v, want 6 queries: 3 allowed, 2 blocked, 1 error", sum)
	}
	if sum.QTypes["A"] != 5 || sum.QTypes["AAAA"] != 1 {
		t.Errorf("qtypes = %v, want A:5 AAAA:1", sum.QTypes)
	}
	if sum.Cached != 1 || sum.MaxElapsedMS != 5000 {
		t.Errorf("cached=%d max=%d, want 1 and 5000", sum.Cached, sum.MaxElapsedMS)
	}
	if sum.FirstSeen == nil || sum.LastSeen == nil || !sum.LastSeen.After(*sum.FirstSeen) {
		t.Errorf("first/last = %v/%v", sum.FirstSeen, sum.LastSeen)
	}
	// "notevil.example" is not "evil.example": exact, never substring.
	if sum.Queries+sum.Errors > 7 {
		t.Error("a substring neighbour leaked into the exact-name summary")
	}

	// Narrowed to one client.
	sum, err = st.ActivitySummarySince(ctx, "evil.example", "10.0.0.1", now.Add(-24*time.Hour))
	if err != nil || sum.Queries != 2 || sum.Blocked != 2 {
		t.Errorf("client-narrowed summary = %+v (%v), want the client's 2 blocks", sum, err)
	}

	// Nothing in the window: zeroes, and no first/last.
	sum, err = st.ActivitySummarySince(ctx, "evil.example", "", now.Add(time.Hour))
	if err != nil || sum.Queries != 0 || sum.FirstSeen != nil {
		t.Errorf("empty window summary = %+v (%v)", sum, err)
	}
	// No subject at all is an empty summary, not a scan.
	if sum, err := st.ActivitySummarySince(ctx, "", "", now); err != nil || sum.Queries != 0 {
		t.Errorf("no-subject summary = %+v (%v)", sum, err)
	}
}

func TestClientsOfDomainListsOnlyAttributedClients(t *testing.T) {
	st := newTestStore(t)
	now := seedActivity(t, st)

	clients, err := st.ClientsOfDomainSince(context.Background(), "evil.example", now.Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatalf("ClientsOfDomainSince: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("listed %d clients, want 2 (the unattributed row must not become a client)", len(clients))
	}
	// Busiest first.
	if clients[0].ClientIP != "10.0.0.2" || clients[0].Queries != 3 || clients[0].Blocked != 0 {
		t.Errorf("first client = %+v, want 10.0.0.2 with 3 queries", clients[0])
	}
	if clients[1].ClientIP != "10.0.0.1" || clients[1].ClientName != "laptop" || clients[1].Blocked != 2 {
		t.Errorf("second client = %+v, want laptop with 2 blocks", clients[1])
	}
	for _, c := range clients {
		if c.ClientIP == "10.0.0.9" {
			t.Error("a client outside the window was listed")
		}
	}
}

func TestDomainsOfClientRanksNamesAndCarriesTheBlockCategory(t *testing.T) {
	st := newTestStore(t)
	now := seedActivity(t, st)

	domains, err := st.DomainsOfClientSince(context.Background(), "10.0.0.1", now.Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatalf("DomainsOfClientSince: %v", err)
	}
	if len(domains) != 3 {
		t.Fatalf("listed %d names, want 3", len(domains))
	}
	if domains[0].Domain != "evil.example" || domains[0].Queries != 2 || domains[0].Blocked != 2 || domains[0].Category != "malware" {
		t.Errorf("top name = %+v, want evil.example, 2 queries, 2 blocked, malware", domains[0])
	}
	for _, d := range domains[1:] {
		if d.Blocked != 0 || d.Category != "" {
			t.Errorf("%s reports a block it did not have: %+v", d.Domain, d)
		}
	}
	// A client that was never recorded has nothing, not an error.
	none, err := st.DomainsOfClientSince(context.Background(), "10.9.9.9", now.Add(-24*time.Hour), 10)
	if err != nil || len(none) != 0 {
		t.Errorf("unknown client: %d names, %v", len(none), err)
	}
}

func TestFindingsForDomainsMatchExactlyAndReportTruncation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rows := []Finding{
		{ID: "a", Time: now, EventType: "x", Severity: "low", Domain: "example.com", Detail: "{}"},
		{ID: "b", Time: now.Add(-time.Minute), EventType: "x", Severity: "low", Domain: "example.com", Detail: "{}"},
		{ID: "c", Time: now, EventType: "x", Severity: "low", Domain: "notexample.com", Detail: "{}"},
		{ID: "d", Time: now.Add(-48 * time.Hour), EventType: "x", Severity: "low", Domain: "example.com", Detail: "{}"},
	}
	if err := st.InsertFindings(ctx, rows); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}

	got, truncated, err := st.FindingsForDomainsSince(ctx, []string{"www.example.com", "example.com", "com"}, now.Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatalf("FindingsForDomainsSince: %v", err)
	}
	if len(got) != 2 || truncated {
		t.Fatalf("got %d findings (truncated %v), want the 2 in-window rows for example.com", len(got), truncated)
	}
	for _, f := range got {
		if f.Domain != "example.com" {
			t.Errorf("a finding for %q matched; only exact names may", f.Domain)
		}
	}
	got, truncated, err = st.FindingsForDomainsSince(ctx, []string{"example.com"}, now.Add(-24*time.Hour), 1)
	if err != nil || len(got) != 1 || !truncated {
		t.Errorf("limit 1: %d rows, truncated %v, %v; want 1 row and truncated", len(got), truncated, err)
	}
	if got, _, _ := st.FindingsForDomainsSince(ctx, nil, now, 10); len(got) != 0 {
		t.Error("no names matched something")
	}
}

func TestEvidenceContributionsCountOnlyDecidingCitations(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Two evidence rows; one decided two decisions, the other was merely
	// on file for one of them.
	put := func(source string) evidence.Evidence {
		e, err := st.PutEvidence(ctx, claim(source, "listed as malware", now))
		if err != nil {
			t.Fatalf("PutEvidence(%s): %v", source, err)
		}
		return e
	}
	decider := put("f_urlhaus")
	bystander := put("f_other")
	for i := 0; i < 2; i++ {
		cited := []CitedEvidence{{Evidence: decider, Contributed: true}}
		if i == 0 {
			cited = append(cited, CitedEvidence{Evidence: bystander, Contributed: false})
		}
		if _, err := st.RecordDecision(ctx, Decision{
			Time: now, Subject: decider.Subject, Action: ActionBlocked, Rule: "category",
		}, cited); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}

	counts, err := st.EvidenceContributions(ctx, []string{decider.ID, bystander.ID, "ev_missing"})
	if err != nil {
		t.Fatalf("EvidenceContributions: %v", err)
	}
	if counts[decider.ID] != 2 {
		t.Errorf("decider contributed to %d decisions, want 2", counts[decider.ID])
	}
	if counts[bystander.ID] != 0 {
		t.Errorf("a row that was only on file counts as contributing %d time(s)", counts[bystander.ID])
	}
	if _, ok := counts["ev_missing"]; ok {
		t.Error("an unknown id gained a count")
	}
}

func TestDomainInvestigationFiltersClientBeforeThePageLimit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rows := []Finding{{ID: "quiet-client", Time: now.Add(-time.Hour), ClientIP: "192.0.2.1", Domain: "example.com", Detail: "{}"}}
	for i := 0; i < 60; i++ {
		rows = append(rows, Finding{ID: fmt.Sprintf("busy-%02d", i), Time: now.Add(-time.Minute), ClientIP: "192.0.2.2", Domain: "example.com", Detail: "{}"})
	}
	if err := st.InsertFindings(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, truncated, err := st.FindingsForDomains(ctx, []string{"www.example.com", "example.com"}, "192.0.2.1", now.Add(-24*time.Hour), now, 50)
	if err != nil || truncated || len(got) != 1 || got[0].ID != "quiet-client" {
		t.Fatalf("client filter after page cap: %v truncated=%v err=%v", got, truncated, err)
	}
}

func TestInvestigationSummariesShareWindowAndDoNotDuplicateRenamedClients(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: at.Add(-time.Minute), Domain: "scope.example", ClientIP: "192.0.2.1", ClientName: "Old label", NetworkID: "old", Action: ActionBlocked, Category: "z_old"},
		{Time: at, Domain: "scope.example", ClientIP: "192.0.2.1", ClientName: "Current label", NetworkID: "current", Action: ActionBlocked, Category: "a_current"},
		{Time: at.Add(time.Minute), Domain: "scope.example", ClientIP: "192.0.2.2", ClientName: "Future", Action: ActionBlocked},
	}, true); err != nil {
		t.Fatal(err)
	}
	since := at.Add(-time.Hour)
	summary, err := st.ActivitySummaryWindow(ctx, "scope.example", "", since, at)
	if err != nil || summary.Queries != 2 {
		t.Fatalf("summary includes out-of-window rows: %+v %v", summary, err)
	}
	clients, err := st.ClientsOfDomainWindow(ctx, "scope.example", since, at, 50)
	if err != nil || len(clients) != 1 || clients[0].Queries != 2 || clients[0].ClientName != "Current label" || clients[0].NetworkID != "current" {
		t.Fatalf("client identity split by rename: %+v %v", clients, err)
	}
	domains, err := st.DomainsOfClientWindow(ctx, "192.0.2.1", since, at, 50)
	if err != nil || len(domains) != 1 || domains[0].Queries != 2 || domains[0].Category != "a_current" {
		t.Fatalf("latest category chosen lexically instead of chronologically: %+v %v", domains, err)
	}
}
