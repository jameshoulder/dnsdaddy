package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func ptr[T any](v T) *T { return &v }

func TestSeedCreatesDefaults(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	policies, err := st.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("got %d seeded policies, want 3", len(policies))
	}

	var defaults int
	for _, p := range policies {
		if p.IsDefault {
			defaults++
			if len(p.Categories) == 0 {
				t.Error("the default policy blocks nothing; a fresh install would not protect anyone")
			}
		}
	}
	if defaults != 1 {
		t.Errorf("got %d default policies, want exactly 1", defaults)
	}

	networks, err := st.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("got %d seeded networks, want 1", len(networks))
	}
	if len(networks[0].CIDRs) != 0 {
		t.Error("the seeded network should be a catch-all with no CIDRs")
	}
	if networks[0].Token == "" {
		t.Error("the seeded network has no DoH token")
	}

	feeds, err := st.ListFeeds(ctx)
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	if len(feeds) == 0 {
		t.Fatal("no feeds were seeded")
	}
}

func TestSeedIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	// Simulate an operator turning a built-in feed off, then upgrading.
	if _, err := st.UpdateFeed(ctx, "urlhaus", FeedInput{Enabled: ptr(false)}); err != nil {
		t.Fatalf("UpdateFeed: %v", err)
	}
	before, _ := st.ListFeeds(ctx)
	st.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()

	after, err := st2.ListFeeds(ctx)
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("feed count changed across restart: %d then %d", len(before), len(after))
	}

	f, err := st2.GetFeed(ctx, "urlhaus")
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if f.Enabled {
		t.Error("re-seeding re-enabled a feed the operator had turned off")
	}
}

func TestPolicyCRUD(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	p, err := st.CreatePolicy(ctx, PolicyInput{
		Name:         ptr("Warehouse"),
		Categories:   &[]string{"malware", "phishing"},
		AllowDomains: &[]string{"Supplier.example.COM", "supplier.example.com"},
		BlockDomains: &[]string{"https://timewaster.example/feed"},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	if len(p.AllowDomains) != 1 || p.AllowDomains[0] != "supplier.example.com" {
		t.Errorf("allow list = %v, want a single normalised entry", p.AllowDomains)
	}
	if len(p.BlockDomains) != 1 || p.BlockDomains[0] != "timewaster.example" {
		t.Errorf("block list = %v, want the host extracted from the URL", p.BlockDomains)
	}

	updated, err := st.UpdatePolicy(ctx, p.ID, PolicyInput{Categories: &[]string{"malware"}})
	if err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if len(updated.Categories) != 1 {
		t.Errorf("categories = %v, want 1", updated.Categories)
	}
	if len(updated.AllowDomains) != 1 {
		t.Error("a partial update dropped the allow list; omitted fields must be left alone")
	}

	if err := st.DeletePolicy(ctx, p.ID); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if _, err := st.GetPolicy(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPolicy after delete returned %v, want ErrNotFound", err)
	}
}

func TestPolicyRejectsUnknownCategory(t *testing.T) {
	st := newTestStore(t)
	_, err := st.CreatePolicy(context.Background(), PolicyInput{
		Name:       ptr("Bad"),
		Categories: &[]string{"malware", "not-a-category"},
	})
	if err == nil {
		t.Fatal("CreatePolicy accepted an unknown category")
	}
}

func TestCannotDeleteDefaultOrInUsePolicy(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.DeletePolicy(ctx, "p_standard"); err == nil {
		t.Error("the default policy was deleted")
	}

	p, err := st.CreatePolicy(ctx, PolicyInput{Name: ptr("Temp")})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if _, err := st.CreateNetwork(ctx, NetworkInput{Name: ptr("Site"), PolicyID: &p.ID}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := st.DeletePolicy(ctx, p.ID); err == nil {
		t.Error("a policy still assigned to a network was deleted")
	}
}

func TestNetworkCIDRNormalisation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	n, err := st.CreateNetwork(ctx, NetworkInput{
		Name:  ptr("HQ"),
		CIDRs: &[]string{"10.0.10.5/24", "192.168.1.50", "10.0.10.0/24"},
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	want := map[string]bool{"10.0.10.0/24": true, "192.168.1.50/32": true}
	if len(n.CIDRs) != len(want) {
		t.Fatalf("CIDRs = %v, want %d entries (masked and de-duplicated)", n.CIDRs, len(want))
	}
	for _, c := range n.CIDRs {
		if !want[c] {
			t.Errorf("unexpected CIDR %q", c)
		}
	}
}

func TestNetworkRejectsBadCIDR(t *testing.T) {
	st := newTestStore(t)
	_, err := st.CreateNetwork(context.Background(), NetworkInput{
		Name:  ptr("Broken"),
		CIDRs: &[]string{"not-an-address"},
	})
	if err == nil {
		t.Fatal("CreateNetwork accepted an invalid CIDR")
	}
}

func TestCannotDeleteLastNetwork(t *testing.T) {
	st := newTestStore(t)
	if err := st.DeleteNetwork(context.Background(), "n_default"); err == nil {
		t.Error("the only network was deleted, leaving nowhere to attribute clients")
	}
}

func TestRotateNetworkToken(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	before, err := st.GetNetwork(ctx, "n_default")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	after, err := st.RotateNetworkToken(ctx, "n_default")
	if err != nil {
		t.Fatalf("RotateNetworkToken: %v", err)
	}
	if after.Token == before.Token || after.Token == "" {
		t.Error("token was not rotated")
	}
	if _, err := st.NetworkByToken(ctx, before.Token); !errors.Is(err, ErrNotFound) {
		t.Error("the old token still resolves after rotation")
	}
	if id, err := st.NetworkByToken(ctx, after.Token); err != nil || id != "n_default" {
		t.Errorf("NetworkByToken(new) = (%q, %v), want n_default", id, err)
	}
}

func TestBuiltinFeedProtections(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if _, err := st.UpdateFeed(ctx, "urlhaus", FeedInput{URL: ptr("https://elsewhere.example/list")}); err == nil {
		t.Error("a built-in feed's URL was changed")
	}
	if err := st.DeleteFeed(ctx, "urlhaus"); err == nil {
		t.Error("a built-in feed was deleted")
	}
	if _, err := st.UpdateFeed(ctx, "urlhaus", FeedInput{Enabled: ptr(false)}); err != nil {
		t.Errorf("a built-in feed could not be disabled: %v", err)
	}
}

func TestFeedRejectsBadURL(t *testing.T) {
	st := newTestStore(t)
	for _, url := range []string{"ftp://example.org/list", "javascript:alert(1)", "https://"} {
		if _, err := st.CreateFeed(context.Background(), FeedInput{
			Name: ptr("Custom"), URL: ptr(url),
		}); err == nil {
			t.Errorf("CreateFeed accepted %q", url)
		}
	}
}

func TestFeedFormatValidation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	for _, format := range []string{"auto", "hosts", "domains", "adblock", "observatory"} {
		if _, err := st.CreateFeed(ctx, FeedInput{
			Name: ptr("Custom " + format), URL: ptr("https://example.org/list"), Format: ptr(format),
		}); err != nil {
			t.Errorf("CreateFeed rejected format %q: %v", format, err)
		}
	}
	for _, format := range []string{"json", "csv", "observatory-v2"} {
		if _, err := st.CreateFeed(ctx, FeedInput{
			Name: ptr("Custom"), URL: ptr("https://example.org/list"), Format: ptr(format),
		}); err == nil {
			t.Errorf("CreateFeed accepted unknown format %q", format)
		}
	}
}

func TestObservatoryFeedIsSeededDisabledAndBuiltin(t *testing.T) {
	// The Observatory is the only DNS Daddy-operated source in the catalog. It
	// is seeded so an operator can find and enable it, and seeded off so that a
	// default install still depends on nothing we run.
	st := newTestStore(t)
	feeds, err := st.ListFeeds(context.Background())
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	for _, f := range feeds {
		if f.ID != catalog.ObservatoryFeedID {
			continue
		}
		if f.Enabled {
			t.Error("the Threat Observatory feed was seeded enabled; it must be opt-in")
		}
		if !f.Builtin {
			t.Error("the Threat Observatory feed should be built-in")
		}
		if f.Format != "observatory" {
			t.Errorf("Observatory feed format = %q, want observatory", f.Format)
		}
		return
	}
	t.Fatal("the Threat Observatory feed was not seeded")
}

func TestQueryLogAndRollups(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	events := []QueryEvent{
		{Time: now, NetworkID: "n_default", Domain: "evil.com", QType: "A",
			Action: ActionBlocked, Category: "malware", Reason: "Domain is on a malware distribution list"},
		{Time: now, NetworkID: "n_default", Domain: "evil.com", QType: "A",
			Action: ActionBlocked, Category: "malware"},
		{Time: now, NetworkID: "n_default", Domain: "good.example", QType: "A", Action: ActionAllowed},
	}
	if err := st.InsertQueryBatch(ctx, events, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	totals, err := st.TotalsSince(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("TotalsSince: %v", err)
	}
	if totals.Queries != 3 || totals.Blocked != 2 {
		t.Errorf("totals = %+v, want 3 queries / 2 blocked", totals)
	}

	rows, next, err := st.ListQueries(ctx, QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(rows) != 3 {
		t.Errorf("got %d rows, want 3", len(rows))
	}
	if next != 0 {
		t.Errorf("nextCursor = %d, want 0 on the final page", next)
	}

	blockedOnly, _, err := st.ListQueries(ctx, QueryFilter{Action: ActionBlocked, Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries(blocked): %v", err)
	}
	if len(blockedOnly) != 2 {
		t.Errorf("blocked filter returned %d rows, want 2", len(blockedOnly))
	}

	top, err := st.TopBlockedDomains(ctx, now.AddDate(0, 0, -1), 10)
	if err != nil {
		t.Fatalf("TopBlockedDomains: %v", err)
	}
	if len(top) != 1 || top[0].Domain != "evil.com" || top[0].Count != 2 {
		t.Errorf("top blocked = %+v, want evil.com counted twice", top)
	}

	cats, err := st.ThreatsByCategory(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("ThreatsByCategory: %v", err)
	}
	if len(cats) != 1 || cats[0].Category != "malware" || cats[0].Count != 2 {
		t.Errorf("categories = %+v, want malware:2", cats)
	}
}

func TestRollupOnlyInsertSkipsQueryRows(t *testing.T) {
	// This is what a policy with query logging disabled produces: usable
	// counts, no record of who asked for what.
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: now, NetworkID: "n_default", Domain: "private.example", QType: "A", Action: ActionAllowed},
	}, false)
	if err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	rows, _, err := st.ListQueries(ctx, QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d stored rows, want 0 when persistence is off", len(rows))
	}

	totals, err := st.TotalsSince(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("TotalsSince: %v", err)
	}
	if totals.Queries != 1 {
		t.Errorf("totals.Queries = %d, want the query still counted", totals.Queries)
	}
}

func TestQueryLogPagination(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	var events []QueryEvent
	for i := 0; i < 25; i++ {
		events = append(events, QueryEvent{
			Time: now, NetworkID: "n_default", Domain: "example.test", QType: "A", Action: ActionAllowed,
		})
	}
	if err := st.InsertQueryBatch(ctx, events, true); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	first, cursor, err := st.ListQueries(ctx, QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(first) != 10 || cursor == 0 {
		t.Fatalf("page 1: %d rows, cursor %d — want 10 rows and a cursor", len(first), cursor)
	}

	second, _, err := st.ListQueries(ctx, QueryFilter{Limit: 10, Cursor: cursor})
	if err != nil {
		t.Fatalf("ListQueries(page 2): %v", err)
	}
	if len(second) != 10 {
		t.Fatalf("page 2 returned %d rows, want 10", len(second))
	}
	if second[0].ID >= first[len(first)-1].ID {
		t.Error("page 2 overlaps page 1")
	}
}

func TestPruneRespectsRetention(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	old := time.Now().AddDate(0, 0, -30).UTC()
	recent := time.Now().UTC()

	err := st.InsertQueryBatch(ctx, []QueryEvent{
		{Time: old, NetworkID: "n_default", Domain: "old.example", QType: "A", Action: ActionAllowed},
		{Time: recent, NetworkID: "n_default", Domain: "new.example", QType: "A", Action: ActionAllowed},
	}, true)
	if err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}

	removed, err := st.Prune(ctx, 7, 90)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Errorf("pruned %d rows, want 1", removed)
	}

	rows, _, err := st.ListQueries(ctx, QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListQueries: %v", err)
	}
	if len(rows) != 1 || rows[0].Domain != "new.example" {
		t.Errorf("rows after prune = %+v, want only new.example", rows)
	}

	// Statistics outlive the query log, so the dashboard keeps its history.
	totals, err := st.TotalsSince(ctx, old.Add(-time.Hour))
	if err != nil {
		t.Fatalf("TotalsSince: %v", err)
	}
	if totals.Queries != 2 {
		t.Errorf("rollup totals = %d, want 2 preserved across the prune", totals.Queries)
	}
}

func TestAPITokenLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	tok, err := st.CreateAPIToken(ctx, "control-centre")
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if tok.Secret == "" {
		t.Fatal("no secret returned at creation")
	}

	listed, err := st.ListAPITokens(ctx)
	if err != nil {
		t.Fatalf("ListAPITokens: %v", err)
	}
	if len(listed) != 1 || listed[0].Secret != "" {
		t.Error("listing tokens exposed a secret")
	}

	verified, err := st.VerifyAPIToken(ctx, tok.Secret)
	if err != nil {
		t.Fatalf("VerifyAPIToken: %v", err)
	}
	if verified.ID != tok.ID {
		t.Errorf("verified token ID = %q, want %q", verified.ID, tok.ID)
	}

	if _, err := st.VerifyAPIToken(ctx, "dnsd_wrong"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a bad token verified with %v, want ErrNotFound", err)
	}
	if _, err := st.VerifyAPIToken(ctx, "no-prefix"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a token without the prefix verified with %v", err)
	}

	if err := st.DeleteAPIToken(ctx, tok.ID); err != nil {
		t.Fatalf("DeleteAPIToken: %v", err)
	}
	if _, err := st.VerifyAPIToken(ctx, tok.Secret); !errors.Is(err, ErrNotFound) {
		t.Error("a revoked token still verifies")
	}
}

func TestClientNaming(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.SetClientName(ctx, "10.0.4.23", "laptop-07"); err != nil {
		t.Fatalf("SetClientName: %v", err)
	}
	clients, err := st.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 || clients[0].Name != "laptop-07" {
		t.Fatalf("clients = %+v", clients)
	}

	// An empty name clears the entry.
	if err := st.SetClientName(ctx, "10.0.4.23", ""); err != nil {
		t.Fatalf("SetClientName(clear): %v", err)
	}
	clients, _ = st.ListClients(ctx)
	if len(clients) != 0 {
		t.Errorf("clients = %+v, want empty after clearing", clients)
	}

	if err := st.SetClientName(ctx, "not-an-ip", "nope"); err == nil {
		t.Error("SetClientName accepted an invalid IP")
	}
}

func TestRecordFeedRefreshTracksLastSuccessSeparately(t *testing.T) {
	// A feed that has been failing since Tuesday has a refresh timestamp of a
	// minute ago and intelligence three days old. The dashboard needs both
	// numbers to say "could not be refreshed; still enforcing what we had".
	st := newTestStore(t)
	ctx := context.Background()

	name, url, category, format := "Test", "https://example.org/list.txt", "malware", "hosts"
	f, err := st.CreateFeed(ctx, FeedInput{Name: &name, URL: &url, Category: &category, Format: &format})
	if err != nil {
		t.Fatalf("CreateFeed: %v", err)
	}
	if f.LastSuccess != nil {
		t.Error("a brand new feed claims a successful download")
	}

	if err := st.RecordFeedRefresh(ctx, f.ID, FeedResult{Status: "ok", DomainCount: 10, ETag: `"v1"`}); err != nil {
		t.Fatalf("record success: %v", err)
	}
	good, err := st.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if good.LastSuccess == nil {
		t.Fatal("a successful refresh recorded no success time")
	}

	if err := st.RecordFeedRefresh(ctx, f.ID, FeedResult{Status: "error", Error: "HTTP 404 from https://example.org/list.txt"}); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	after, err := st.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if after.LastSuccess == nil || !after.LastSuccess.Equal(*good.LastSuccess) {
		t.Errorf("LastSuccess = %v after a failure, want the earlier %v", after.LastSuccess, good.LastSuccess)
	}
	if after.LastRefresh == nil || after.LastRefresh.Before(*good.LastSuccess) {
		t.Error("LastRefresh did not move on a failed attempt")
	}
	if after.LastError == "" {
		t.Error("the failure was not recorded")
	}

	// "Not modified" is a success: the provider confirmed the cached copy is
	// current, so the intelligence is not stale.
	if err := st.RecordFeedRefresh(ctx, f.ID, FeedResult{Status: "not-modified", ETag: `"v1"`}); err != nil {
		t.Fatalf("record not-modified: %v", err)
	}
	fresh, err := st.GetFeed(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if fresh.LastSuccess == nil || fresh.LastSuccess.Before(*good.LastSuccess) {
		t.Error("a not-modified response did not count as a successful refresh")
	}
	if fresh.LastError != "" {
		t.Errorf("LastError = %q after a not-modified response, want empty", fresh.LastError)
	}
	if fresh.DomainCount != 10 {
		t.Errorf("DomainCount = %d, want the previous 10 kept", fresh.DomainCount)
	}
}
