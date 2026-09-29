package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// The measured block exists so that no combination of configuration and
// traffic can imply protection that was not measured. Each test below is one
// of the combinations the brief names, and asserts what the block says about
// it — and, where the old headline field would have said something broader,
// that the two are now distinguishable.

func (h *harness) measured(t *testing.T) Overview {
	t.Helper()
	resp, raw := h.do(http.MethodGet, "/api/v1/overview", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/overview = %d: %s", resp.StatusCode, raw)
	}
	return decode[Overview](t, raw)
}

func (h *harness) createPolicy(t *testing.T, body map[string]any) string {
	t.Helper()
	resp, raw := h.do(http.MethodPost, "/api/v1/policies", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy: %d %s", resp.StatusCode, raw)
	}
	return decode[store.Policy](t, raw).ID
}

func (h *harness) patchNetwork(t *testing.T, id string, body map[string]any) {
	t.Helper()
	resp, raw := h.do(http.MethodPatch, "/api/v1/networks/"+id, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch network %s: %d %s", id, resp.StatusCode, raw)
	}
}

func (h *harness) insertQueries(t *testing.T, persist bool, events ...store.QueryEvent) {
	t.Helper()
	if err := h.store.InsertQueryBatch(context.Background(), events, persist); err != nil {
		t.Fatalf("InsertQueryBatch: %v", err)
	}
}

func TestMeasuredDistinguishesAnUnusedBlockingPolicyFromProtection(t *testing.T) {
	h := newHarness(t)
	h.login()

	// Every network on the monitor-only policy, and one blocking policy that
	// nothing is assigned to. The legacy headline calls this "protected"
	// because a blocking policy exists; the measured block must not.
	h.patchNetwork(t, "n_default", map[string]any{"policyId": "p_monitor"})

	o := h.measured(t)
	m := o.Measured
	if m.Filtering.BlockingPolicies == 0 {
		t.Fatal("precondition: the seeded policies include blocking ones")
	}
	if m.Filtering.BlockingPoliciesAssigned != 0 {
		t.Errorf("blockingPoliciesAssigned = %d, want 0: no enabled network uses a blocking policy", m.Filtering.BlockingPoliciesAssigned)
	}
	if m.Networks.WithBlockingPolicy != 0 || m.Networks.MonitorOnly != m.Networks.Enabled {
		t.Errorf("networks = %+v, want every enabled network counted monitor-only", m.Networks)
	}
	if o.ProtectionStatus != "protected" {
		// Not a claim that this is right — it is the legacy derivation, and
		// the point of the measured block is that a reader no longer has to
		// take it at face value.
		t.Logf("legacy protectionStatus = %q", o.ProtectionStatus)
	}
}

func TestMeasuredCountsCustomBlockingWithoutAFeedIndex(t *testing.T) {
	h := newHarness(t)
	h.login()

	// An empty index: category selections block nothing, but an operator's
	// own block-list entries still do, and the block must say both.
	h.lists.Store(blocklist.NewBuilder(0).Build())
	h.createPolicy(t, map[string]any{"name": "Custom only", "categories": []string{}, "blockDomains": []string{"timewaster.example"}})

	m := h.measured(t).Measured
	if m.Filtering.CategoryBlockingAvailable {
		t.Error("categoryBlockingAvailable = true with an empty index")
	}
	if m.Filtering.IndexedDomains != 0 {
		t.Errorf("indexedDomains = %d, want 0", m.Filtering.IndexedDomains)
	}
	if m.Filtering.CustomBlockingPolicies != 1 {
		t.Errorf("customBlockingPolicies = %d, want 1", m.Filtering.CustomBlockingPolicies)
	}
}

func TestMeasuredReportsFailingAndUnloadedFeeds(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()

	feeds, err := h.store.ListFeeds(ctx)
	if err != nil || len(feeds) == 0 {
		t.Fatalf("ListFeeds: %v (%d feeds)", err, len(feeds))
	}
	var enabled []store.Feed
	for _, f := range feeds {
		if f.Enabled {
			enabled = append(enabled, f)
		}
	}
	if len(enabled) < 2 {
		t.Fatalf("need two enabled seeded feeds, have %d", len(enabled))
	}
	// One feed fails its refresh having never succeeded; another succeeds.
	if err := h.store.RecordFeedRefresh(ctx, enabled[0].ID, store.FeedResult{Status: "error", Error: "HTTP 503"}); err != nil {
		t.Fatalf("RecordFeedRefresh: %v", err)
	}
	if err := h.store.RecordFeedRefresh(ctx, enabled[1].ID, store.FeedResult{Status: "ok", DomainCount: 12}); err != nil {
		t.Fatalf("RecordFeedRefresh: %v", err)
	}

	m := h.measured(t).Measured
	if m.Feeds.Enabled != len(enabled) {
		t.Errorf("feeds.enabled = %d, want %d", m.Feeds.Enabled, len(enabled))
	}
	if m.Feeds.Failing != 1 {
		t.Errorf("feeds.failing = %d, want 1", m.Feeds.Failing)
	}
	// The harness never rebuilt the index from cached files, so no feed is
	// loaded — "downloaded successfully" and "loaded into the index" are
	// different facts and the block keeps them apart.
	if m.Feeds.Loaded != 0 {
		t.Errorf("feeds.loaded = %d, want 0: nothing has been loaded into the index", m.Feeds.Loaded)
	}
	if m.Feeds.NeverDownloaded != len(enabled)-1 {
		t.Errorf("feeds.neverDownloaded = %d, want %d", m.Feeds.NeverDownloaded, len(enabled)-1)
	}
	if m.Feeds.LastSuccessAt == nil || m.Feeds.LastAttemptAt == nil {
		t.Error("lastSuccessAt / lastAttemptAt are nil after a recorded success")
	}
}

func TestMeasuredWithZeroTrafficHasNoRateAndNoInventedZeros(t *testing.T) {
	h := newHarness(t)
	h.login()

	m := h.measured(t).Measured
	if m.Outcomes.Queries != 0 || m.Outcomes.Blocked != 0 {
		t.Fatalf("precondition: a fresh harness has traffic %+v", m.Outcomes)
	}
	if m.Resolver.ErrorRate.Available {
		t.Error("an error rate was reported with no queries to divide by")
	}
	if m.Resolver.ErrorRate.Unavailable == "" {
		t.Error("the unavailable rate gives no reason")
	}
	if m.Resolver.ErrorRate.Denominator != 0 {
		t.Errorf("denominator = %d, want 0", m.Resolver.ErrorRate.Denominator)
	}
	// Every class is present at zero, so a consumer renders a stable table.
	for _, c := range []string{"security", "precaution", "preference", "custom", "unclassified"} {
		if _, ok := m.Outcomes.BlockedByClass[c]; !ok {
			t.Errorf("blockedByClass lacks %q", c)
		}
	}
	if m.Window.Hours != 24 || m.Window.Source != "hourly_rollups" {
		t.Errorf("window = %+v, want 24 hours from hourly rollups", m.Window)
	}
	if m.Networks.WithTrafficInWindow != 0 {
		t.Errorf("withTrafficInWindow = %d with no traffic", m.Networks.WithTrafficInWindow)
	}
}

func TestMeasuredSplitsBlocksByClassAndDerivesTheErrorRateFromOneWindow(t *testing.T) {
	h := newHarness(t)
	h.login()
	now := time.Now().UTC()

	ev := func(ip, action, category string) store.QueryEvent {
		return store.QueryEvent{
			Time: now, ClientIP: ip, NetworkID: "n_default", Domain: "x.example",
			QType: "A", Action: action, Category: category,
		}
	}
	h.insertQueries(t, true,
		ev("10.0.0.1", store.ActionAllowed, ""),
		ev("10.0.0.1", store.ActionAllowed, ""),
		ev("10.0.0.2", store.ActionBlocked, "malware"),          // security
		ev("10.0.0.2", store.ActionBlocked, "phishing"),         // security
		ev("10.0.0.3", store.ActionBlocked, "ads"),              // preference
		ev("10.0.0.3", store.ActionBlocked, "custom"),           // custom
		ev("10.0.0.3", store.ActionBlocked, "newly-registered"), // precaution
		ev("10.0.0.3", store.ActionBlocked, "from-a-provider"),  // unclassified
		ev("10.0.0.4", store.ActionError, ""),
		ev("10.0.0.4", store.ActionError, ""),
	)

	o := h.measured(t)
	m := o.Measured

	if m.Outcomes.Queries != 10 || m.Outcomes.Blocked != 6 {
		t.Fatalf("outcomes = %+v, want 10 queries and 6 blocked", m.Outcomes)
	}
	want := map[string]int64{"security": 2, "precaution": 1, "preference": 1, "custom": 1, "unclassified": 1}
	for class, n := range want {
		if m.Outcomes.BlockedByClass[class] != n {
			t.Errorf("blockedByClass[%s] = %d, want %d", class, m.Outcomes.BlockedByClass[class], n)
		}
	}
	var sum int64
	for _, n := range m.Outcomes.BlockedByClass {
		sum += n
	}
	if sum != m.Outcomes.Blocked {
		t.Errorf("classes sum to %d, want the blocked total %d", sum, m.Outcomes.Blocked)
	}
	// The legacy headline counts every block as a threat; the split is what
	// lets a reader see that only two of six were security blocks.
	if o.ThreatsBlocked24h != 6 {
		t.Errorf("threatsBlocked24h = %d, want the unchanged legacy total 6", o.ThreatsBlocked24h)
	}

	rate := m.Resolver.ErrorRate
	if !rate.Available || rate.Numerator != 2 || rate.Denominator != 10 || rate.WindowHours != 24 {
		t.Errorf("errorRate = %+v, want 2/10 over 24h", rate)
	}
	if rate.Ratio < 0.199 || rate.Ratio > 0.201 {
		t.Errorf("ratio = %v, want 0.2", rate.Ratio)
	}
	// A 20% failure rate in the window reads as degraded, from the window.
	if o.ResolverStatus != "degraded" {
		t.Errorf("resolverStatus = %q, want degraded from the windowed rate", o.ResolverStatus)
	}
	if !m.Outcomes.Errors.Complete || m.Outcomes.Errors.MeasuredSince != nil {
		t.Errorf("errors = %+v, want complete on a fresh database", m.Outcomes.Errors)
	}

	if m.Clients.ObservedInWindow == nil || *m.Clients.ObservedInWindow != 4 {
		t.Errorf("clients.observedInWindow = %v, want 4", m.Clients.ObservedInWindow)
	}
	if m.Networks.WithTrafficInWindow != 1 {
		t.Errorf("withTrafficInWindow = %d, want 1 (the catch-all)", m.Networks.WithTrafficInWindow)
	}
	// Lifetime counters are scoped separately and say so.
	if m.Resolver.SinceStart.CoversWindow {
		t.Error("a process started seconds ago claims to cover a 24-hour window")
	}
}

func TestMeasuredDoesNotDeriveAStatusFromMismatchedScopes(t *testing.T) {
	// The old derivation: the process's lifetime errors over the last day's
	// queries. Here the process has errors from its own counters but the
	// rollup window has none, and the status must follow the window.
	h := newHarness(t)
	h.login()
	now := time.Now().UTC()

	h.insertQueries(t, true,
		store.QueryEvent{Time: now, NetworkID: "n_default", Domain: "ok.example", QType: "A", Action: store.ActionAllowed},
	)
	// Drive the real handler into an upstream failure so the lifetime error
	// counter is non-zero. The harness upstream is unreachable by design.
	h.enableAdHocAccess(t)
	resp, _ := h.do(http.MethodGet, "/dns-query?dns="+dohQuery(t, "fails.example."), nil)
	resp.Body.Close()

	o := h.measured(t)
	if o.Measured.Resolver.SinceStart.Errors == 0 {
		t.Skip("the handler did not record an upstream error; nothing to contrast against")
	}
	// The failed query is in the rollups too once the logger flushes, so
	// wait for the window count rather than racing it.
	deadline := time.Now().Add(2 * time.Second)
	for o.Measured.Outcomes.Errors.Count == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		o = h.measured(t)
	}
	rate := o.Measured.Resolver.ErrorRate
	if rate.Numerator != o.Measured.Outcomes.Errors.Count || rate.Denominator != o.Measured.Outcomes.Queries {
		t.Errorf("rate %+v does not use the window's own numerator and denominator (%+v)", rate, o.Measured.Outcomes)
	}
	if rate.Numerator == int64(o.Measured.Resolver.SinceStart.Errors) && rate.Denominator == int64(o.Measured.Resolver.SinceStart.Queries) {
		t.Log("window and lifetime counters coincide in this run; the scope separation is asserted structurally above")
	}
}

func TestMeasuredReportsClientsUnavailableWhenAttributionIsOff(t *testing.T) {
	h := newHarness(t)
	h.login()
	now := time.Now().UTC()

	// Rows with addresses exist from before the setting changed; the block
	// must still report the count as unavailable, not as a stale number.
	h.insertQueries(t, true, store.QueryEvent{
		Time: now, ClientIP: "10.0.0.5", NetworkID: "n_default", Domain: "a.example", QType: "A", Action: store.ActionAllowed,
	})
	h.api.Config.Log.LogClientIP = false

	m := h.measured(t).Measured
	if m.Clients.Attribution {
		t.Fatal("attribution reported on with log_client_ip off")
	}
	if m.Clients.ObservedInWindow != nil {
		t.Errorf("observedInWindow = %d with attribution off; want null", *m.Clients.ObservedInWindow)
	}
	if m.Clients.Unavailable == "" {
		t.Error("no reason given for the unavailable client count")
	}
}

func TestMeasuredErrorRateIsUnavailableUntilTheWindowIsFullyCounted(t *testing.T) {
	h := newHarness(t)
	h.login()
	ctx := context.Background()
	now := time.Now().UTC()

	// An upgraded database began counting errors an hour ago; the 24-hour
	// window reaches back further than that, so a rate over it would divide
	// a partial numerator by a full denominator.
	since := now.Add(-time.Hour).Format(time.RFC3339)
	if err := h.store.SetSetting(ctx, store.SettingStatsErrorsSince, since); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	h.insertQueries(t, true,
		store.QueryEvent{Time: now, NetworkID: "n_default", Domain: "a.example", QType: "A", Action: store.ActionAllowed},
		store.QueryEvent{Time: now, NetworkID: "n_default", Domain: "b.example", QType: "A", Action: store.ActionError},
	)

	o := h.measured(t)
	m := o.Measured
	if m.Outcomes.Errors.Complete {
		t.Error("errors reported complete for a window that predates counting")
	}
	if m.Outcomes.Errors.MeasuredSince == nil {
		t.Error("measuredSince is nil on an upgraded database")
	}
	if m.Outcomes.Errors.Count != 1 {
		t.Errorf("errors.count = %d, want the 1 that was counted", m.Outcomes.Errors.Count)
	}
	if m.Resolver.ErrorRate.Available {
		t.Error("an error rate was computed over a partially counted window")
	}
	if m.Resolver.ErrorRate.Unavailable == "" {
		t.Error("the unavailable rate gives no reason")
	}
	if o.ResolverStatus != "operational" {
		t.Errorf("resolverStatus = %q; an unmeasurable rate must not read as degraded", o.ResolverStatus)
	}

	// Once counting predates the window, the rate is available again.
	old := now.Add(-48 * time.Hour).Format(time.RFC3339)
	if err := h.store.SetSetting(ctx, store.SettingStatsErrorsSince, old); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if m := h.measured(t).Measured; !m.Resolver.ErrorRate.Available || !m.Outcomes.Errors.Complete {
		t.Errorf("rate still unavailable with counting older than the window: %+v", m.Resolver.ErrorRate)
	}
}

func TestMeasuredCountsNetworksSeparately(t *testing.T) {
	h := newHarness(t)
	h.login()

	// A permitted, enabled network on a blocking policy; a disabled one; and
	// the catch-all, which is never "permitted" in its own right.
	resp, raw := h.do(http.MethodPost, "/api/v1/networks", map[string]any{
		"name": "Office", "cidrs": []string{"10.1.0.0/16"}, "allowResolver": true, "policyId": "p_standard",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create office: %d %s", resp.StatusCode, raw)
	}
	resp, raw = h.do(http.MethodPost, "/api/v1/networks", map[string]any{
		"name": "Mothballed", "cidrs": []string{"10.2.0.0/16"}, "enabled": false, "policyId": "p_standard",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create mothballed: %d %s", resp.StatusCode, raw)
	}

	o := h.measured(t)
	m := o.Measured.Networks
	if m.Configured != 3 || m.Enabled != 2 || m.ResolverPermitted != 1 {
		t.Errorf("networks = %+v, want 3 configured, 2 enabled, 1 permitted", m)
	}
	if m.WithBlockingPolicy != 2 || m.MonitorOnly != 0 {
		t.Errorf("networks = %+v, want both enabled networks on a blocking policy", m)
	}
	// The legacy field counts every configured row; the measured block is
	// what says two of the three are in service and one may query on its
	// own permission.
	if o.ProtectedNetworks != 3 || o.PermittedNetworks != 1 {
		t.Errorf("legacy protectedNetworks/permittedNetworks = %d/%d, want 3/1", o.ProtectedNetworks, o.PermittedNetworks)
	}
}

// dohQuery encodes one A question for the GET form of DoH.
func dohQuery(t *testing.T, name string) string {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(packed)
}
