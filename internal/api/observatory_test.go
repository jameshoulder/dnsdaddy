package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// One-click activation of the DNS Daddy Threat Observatory is two calls the
// dashboard makes back to back: enable the built-in feed row, then refresh
// that row immediately rather than waiting for the scheduler. Everything
// underneath is the ordinary feed machinery, and these tests are here to keep
// it that way — in particular to keep the card from ever calling a feed
// "Active" that has not successfully downloaded anything.

const observatoryFeed = "/api/v1/feeds/" + catalog.ObservatoryFeedID

// observatoryDocument is a minimal but complete feed document.
const observatoryDocument = `{
  "generated_at": "2026-08-26T09:15:00Z",
  "source": "dnsdaddy-threat-observatory",
  "indicators": [
    {"value": "c2.example", "type": "domain", "categories": ["c2"]},
    {"value": "phish.example", "type": "domain", "categories": ["phishing"]}
  ]
}`

// pointObservatoryAt repoints the built-in Observatory row at a test server.
//
// The row is built-in, so the API refuses to change its URL — which is the
// point of it being built-in — and the test writes straight to the store
// instead. Everything the test then exercises goes through the HTTP API.
func pointObservatoryAt(t *testing.T, h *harness, url string) {
	t.Helper()
	if _, err := h.store.DB().ExecContext(context.Background(),
		"UPDATE feeds SET url = ? WHERE id = ?", url, catalog.ObservatoryFeedID); err != nil {
		t.Fatalf("repoint observatory feed: %v", err)
	}
}

// observatoryRow reads the Observatory's row out of GET /api/v1/feeds.
func observatoryRow(t *testing.T, h *harness) map[string]any {
	t.Helper()
	resp, raw := h.do("GET", "/api/v1/feeds", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /feeds: status %d, body %s", resp.StatusCode, raw)
	}
	body := decode[map[string]any](t, raw)

	if id, _ := body["observatoryFeedId"].(string); id != catalog.ObservatoryFeedID {
		t.Fatalf("observatoryFeedId = %q, want %q; the card finds its row by this",
			body["observatoryFeedId"], catalog.ObservatoryFeedID)
	}

	feeds, ok := body["feeds"].([]any)
	if !ok {
		t.Fatal("feeds is not an array")
	}
	for _, f := range feeds {
		row, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if row["id"] == catalog.ObservatoryFeedID {
			return row
		}
	}
	t.Fatal("the Observatory feed is not in the feed list")
	return nil
}

// activate performs exactly what the card's Enable button does.
func activate(t *testing.T, h *harness) {
	t.Helper()
	resp, raw := h.do("PATCH", observatoryFeed, map[string]any{"enabled": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable: status %d, body %s", resp.StatusCode, raw)
	}
	resp, raw = h.do("POST", observatoryFeed+"/refresh", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("refresh: status %d, body %s", resp.StatusCode, raw)
	}
	waitForRefresh(t, h)
}

// waitForRefresh polls the feeds endpoint the way the dashboard does.
func waitForRefresh(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, raw := h.do("GET", "/api/v1/feeds", nil)
		body := decode[map[string]any](t, raw)
		if refreshing, _ := body["refreshing"].(bool); !refreshing {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the refresh never finished")
}

func TestObservatoryActivationEnablesAndRefreshesImmediately(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(observatoryDocument))
	}))
	defer srv.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, srv.URL)

	before := observatoryRow(t, h)
	if before["enabled"] != false {
		t.Fatal("the Observatory feed is not seeded disabled; activation must be a deliberate act")
	}

	activate(t, h)

	if hits.Load() == 0 {
		t.Fatal("enabling the feed did not download it; activation must not wait for the scheduler")
	}

	row := observatoryRow(t, h)
	if row["enabled"] != true {
		t.Error("the feed is not enabled after activation")
	}
	if row["lastError"] != "" {
		t.Errorf("lastError = %v, want empty", row["lastError"])
	}
	if row["lastSuccessAt"] == nil {
		t.Error("lastSuccessAt is null after a successful download; the card would not show Active")
	}
	if n, _ := row["indexedDomains"].(float64); n != 2 {
		t.Errorf("indexedDomains = %v, want 2 — the count must come from the feed, not a constant", row["indexedDomains"])
	}
}

func TestObservatoryActivationIndexesIndicatorCategories(t *testing.T) {
	// The card claims malware, phishing, C2 and cryptomining. What makes that
	// true is the ordinary index: each indicator lands under its own category,
	// where the ordinary policy machinery can act on it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(observatoryDocument))
	}))
	defer srv.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, srv.URL)
	activate(t, h)

	for domain, want := range map[string]string{"c2.example": "c2", "phish.example": "phishing"} {
		entry, ok := h.lists.Load().Lookup(domain)
		if !ok {
			t.Errorf("%s is not in the index after activation", domain)
			continue
		}
		if entry.Category != want {
			t.Errorf("%s category = %q, want %q", domain, entry.Category, want)
		}
		if entry.FeedID != catalog.ObservatoryFeedID {
			t.Errorf("%s came from feed %q, want the Observatory", domain, entry.FeedID)
		}
	}
}

func TestObservatoryActivationDoesNotTouchPolicies(t *testing.T) {
	// The Observatory supplies intelligence; policies decide what is enforced.
	// An operator who has deliberately switched cryptomining off must not find
	// it back on because they turned a feed on.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(observatoryDocument))
	}))
	defer srv.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, srv.URL)

	if _, err := h.store.UpdatePolicy(context.Background(), "p_standard", store.PolicyInput{
		Categories: &[]string{"malware"},
	}); err != nil {
		t.Fatalf("narrow the policy: %v", err)
	}
	before, err := h.store.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}

	activate(t, h)

	after, err := h.store.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("policy count changed from %d to %d", len(before), len(after))
	}
	for i := range before {
		if before[i].ID != after[i].ID {
			t.Fatalf("policy order changed: %q then %q", before[i].ID, after[i].ID)
		}
		if len(before[i].Categories) != len(after[i].Categories) {
			t.Fatalf("policy %q categories changed from %v to %v",
				before[i].ID, before[i].Categories, after[i].Categories)
		}
		for j := range before[i].Categories {
			if before[i].Categories[j] != after[i].Categories[j] {
				t.Errorf("policy %q categories changed from %v to %v",
					before[i].ID, before[i].Categories, after[i].Categories)
			}
		}
		if before[i].BlockMode != after[i].BlockMode {
			t.Errorf("policy %q block mode changed", before[i].ID)
		}
	}
}

func TestObservatoryFirstActivationFailureIsNotReportedAsActive(t *testing.T) {
	// The state the Observatory is actually in today: the endpoint 404s. The
	// feed is enabled and has been attempted, and nothing about that is
	// protection — the card must be able to tell the two apart.
	srv := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer srv.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, srv.URL)
	activate(t, h)

	row := observatoryRow(t, h)
	if row["enabled"] != true {
		t.Error("a failed first refresh disabled the feed; it should stay enabled and keep retrying")
	}
	if row["lastSuccessAt"] != nil {
		t.Error("lastSuccessAt is set after a 404; the card would falsely show Active")
	}
	if row["lastRefreshedAt"] == nil {
		t.Error("the attempt was not recorded")
	}
	err, _ := row["lastError"].(string)
	if err == "" {
		t.Fatal("no error was recorded against the feed")
	}
	if !strings.Contains(err, "404") {
		t.Errorf("lastError = %q, want it to name the HTTP status so the card can explain the failure", err)
	}
}

func TestObservatoryKeepsLastKnownGoodWhenARefreshFails(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(observatoryDocument))
	}))
	defer srv.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, srv.URL)
	activate(t, h)

	good := observatoryRow(t, h)
	if good["lastSuccessAt"] == nil {
		t.Fatal("setup: the first activation did not succeed")
	}

	fail.Store(true)
	resp, raw := h.do("POST", observatoryFeed+"/refresh", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("retry: status %d, body %s", resp.StatusCode, raw)
	}
	waitForRefresh(t, h)

	row := observatoryRow(t, h)
	if row["lastError"] == "" {
		t.Error("the failed refresh was not reported")
	}
	if row["lastSuccessAt"] != good["lastSuccessAt"] {
		t.Errorf("lastSuccessAt moved from %v to %v on a failed refresh; it is what dates the intelligence still being enforced",
			good["lastSuccessAt"], row["lastSuccessAt"])
	}
	if n, _ := row["indexedDomains"].(float64); n != 2 {
		t.Errorf("indexedDomains = %v, want 2; the last known good feed must keep being enforced", row["indexedDomains"])
	}
	if _, ok := h.lists.Load().Lookup("c2.example"); !ok {
		t.Error("the last known good intelligence stopped blocking when a refresh failed")
	}
}

func TestObservatoryFailureDoesNotMakeTheResolverLookUnhealthy(t *testing.T) {
	// A feed that cannot be downloaded is a feed problem. The resolver is
	// answering, the other feeds are loaded, and the dashboard must keep
	// saying so rather than turning red over one unavailable source.
	dead := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer dead.Close()
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 malware.example\n"))
	}))
	defer working.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, dead.URL)

	// An independent feed that does work, so "protected" is a claim about
	// something real rather than about the harness's pre-seeded index.
	resp, raw := h.do("POST", "/api/v1/feeds", map[string]any{
		"name": "Working feed", "url": working.URL, "category": "malware", "format": "hosts",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create feed: status %d, body %s", resp.StatusCode, raw)
	}
	other := decode[map[string]any](t, raw)
	resp, raw = h.do("POST", "/api/v1/feeds/"+other["id"].(string)+"/refresh", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("refresh working feed: status %d, body %s", resp.StatusCode, raw)
	}
	waitForRefresh(t, h)

	activate(t, h)

	if _, ok := h.lists.Load().Lookup("malware.example"); !ok {
		t.Fatal("setup: the working feed is not indexed")
	}

	_, raw = h.do("GET", "/api/v1/overview", nil)
	overview := decode[map[string]any](t, raw)
	if overview["protectionStatus"] != "protected" {
		t.Errorf("protectionStatus = %v, want protected; one failing feed must not condemn the whole dashboard",
			overview["protectionStatus"])
	}
	if overview["resolverStatus"] != "operational" {
		t.Errorf("resolverStatus = %v, want operational", overview["resolverStatus"])
	}

	_, raw = h.do("GET", "/api/v1/health", nil)
	health := decode[map[string]any](t, raw)
	if health["status"] != "ok" {
		t.Errorf("health status = %v, want ok", health["status"])
	}
}

func TestObservatoryDisableLeavesEveryOtherFeedAlone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(observatoryDocument))
	}))
	defer srv.Close()
	independent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0.0.0.0 independent.example\n"))
	}))
	defer independent.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, srv.URL)

	// A second, unrelated feed that must come through the disable untouched.
	resp, raw := h.do("POST", "/api/v1/feeds", map[string]any{
		"name": "Independent feed", "url": independent.URL, "category": "phishing", "format": "hosts",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create feed: status %d, body %s", resp.StatusCode, raw)
	}
	other := decode[map[string]any](t, raw)
	resp, raw = h.do("POST", "/api/v1/feeds/"+other["id"].(string)+"/refresh", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("refresh independent feed: status %d, body %s", resp.StatusCode, raw)
	}
	waitForRefresh(t, h)

	activate(t, h)

	before, err := h.store.ListFeeds(context.Background())
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}

	if _, ok := h.lists.Load().Lookup("c2.example"); !ok {
		t.Fatal("setup: the Observatory's indicators are not indexed")
	}

	resp, raw = h.do("PATCH", observatoryFeed, map[string]any{"enabled": false})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable: status %d, body %s", resp.StatusCode, raw)
	}

	// Disabling has to stop the traffic, not merely stop the downloads: the
	// index is rebuilt from the remaining feeds' caches rather than waiting up
	// to twelve hours for the next scheduled refresh. That rebuild is
	// asynchronous, so poll for it.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, ok := h.lists.Load().Lookup("c2.example"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the Observatory's domains were still being blocked after it was disabled")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// And the rebuild must be a rebuild, not a reset: the independent feed is
	// still blocking what it was blocking before.
	if _, ok := h.lists.Load().Lookup("independent.example"); !ok {
		t.Error("disabling the Observatory dropped an unrelated feed's domains from the index")
	}

	after, err := h.store.ListFeeds(context.Background())
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("the feed list changed length: %d then %d. Disabling must not delete the built-in row",
			len(before), len(after))
	}

	found := false
	for i := range after {
		if after[i].ID == catalog.ObservatoryFeedID {
			found = true
			if after[i].Enabled {
				t.Error("the Observatory feed is still enabled")
			}
			if after[i].URL != before[i].URL {
				t.Error("disabling changed the feed's URL")
			}
			continue
		}
		if after[i].Enabled != before[i].Enabled {
			t.Errorf("feed %q changed enabled state when the Observatory was disabled", after[i].ID)
		}
	}
	if !found {
		t.Error("the built-in Observatory row was deleted rather than disabled")
	}
}

func TestObservatoryEnabledStateSurvivesARestart(t *testing.T) {
	// Persistence is the ordinary feed row, and the seeder must not undo the
	// operator's choice on the next boot.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(observatoryDocument))
	}))
	defer srv.Close()

	h := newHarness(t)
	h.login()
	pointObservatoryAt(t, h, srv.URL)
	activate(t, h)

	if !reopenedObservatory(t, h).Enabled {
		t.Error("the Observatory was disabled again by a restart")
	}

	resp, raw := h.do("PATCH", observatoryFeed, map[string]any{"enabled": false})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable: status %d, body %s", resp.StatusCode, raw)
	}
	if reopenedObservatory(t, h).Enabled {
		t.Error("the Observatory was re-enabled by a restart; a deliberate opt-out must stick")
	}
}

func TestRefreshOneFeedRejectsDisabledAndUnknownFeeds(t *testing.T) {
	h := newHarness(t)
	h.login()

	// Seeded disabled, so this is the disabled case.
	resp, _ := h.do("POST", observatoryFeed+"/refresh", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("refreshing a disabled feed returned %d, want 409", resp.StatusCode)
	}

	resp, _ = h.do("POST", "/api/v1/feeds/no-such-feed/refresh", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("refreshing an unknown feed returned %d, want 404", resp.StatusCode)
	}
}

func TestFeedRowMatchesObservatoryCardContract(t *testing.T) {
	// The activation card decides between "Active", "Attention" and "not
	// downloaded yet" purely from these fields. A renamed tag would not break
	// the build or throw in the browser — the card would simply stop being
	// able to tell protection from a 404.
	h := newHarness(t)
	h.login()

	row := observatoryRow(t, h)
	requireKeys(t, "feed row", row,
		"id", "name", "url", "category", "format", "enabled", "builtin",
		"indexedDomains", "lastRefreshedAt", "lastSuccessAt", "lastStatus", "lastError")

	_, raw := h.do("GET", "/api/v1/feeds", nil)
	body := decode[map[string]any](t, raw)
	requireKeys(t, "feeds response", body,
		"feeds", "refreshing", "totalIndexedDomains", "observatoryFeedId")
}

// reopenedObservatory reads the Observatory row back from a freshly opened
// store, which re-runs the seeder exactly as a restart would.
func reopenedObservatory(t *testing.T, h *harness) store.Feed {
	t.Helper()
	f, err := h.reopen(t).GetFeed(context.Background(), catalog.ObservatoryFeedID)
	if err != nil {
		t.Fatalf("GetFeed after restart: %v", err)
	}
	return f
}
