package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"

	// Registers the built-in adapters, exactly as the daemon does.
	_ "github.com/jameshoulder/dnsdaddy/internal/apiprovider/adapters"
	"github.com/jameshoulder/dnsdaddy/internal/intel"
	"github.com/jameshoulder/dnsdaddy/internal/secrets"
)

// theCredential is deliberately long, distinctive and unlike anything else in
// a response body, so the leak scan below cannot produce a false negative by
// matching something the value happens to resemble.
const theCredential = "sk-live-DO-NOT-DISCLOSE-93f1c8a4e7b20d65"

// enableIntegrations wires the external-intelligence feature into a harness.
//
// The API is built before this runs, but every handler reads a.Providers and
// a.Intel at request time, so attaching them here exercises exactly the same
// code the daemon does.
func enableIntegrations(t *testing.T, h *harness, ceiling apiprovider.ReputationMode) {
	t.Helper()

	kr, err := secrets.Open(h.dir)
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	src := &intel.Source{Store: h.store, Keyring: kr, Log: slog.Default()}
	engine := apiprovider.NewEngine(apiprovider.Options{
		Mode:  ceiling,
		Log:   slog.Default(),
		Store: &intel.VerdictStore{Store: h.store},
	})

	// Started, so the asynchronous lookup path is live. Without workers
	// draining the queue nothing ever reaches the cache, and the tests that
	// assert what does and does not warm it would pass against anything.
	engine.Start(context.Background())
	t.Cleanup(engine.Stop)

	h.api.Providers = engine
	h.api.Intel = src
	h.api.Config.Integrations.Enabled = true
	h.api.Config.Integrations.ReputationMode = string(ceiling)
}

// createProvider adds a provider through the API and returns its ID.
func createProvider(t *testing.T, h *harness, body map[string]any) string {
	t.Helper()
	resp, raw := h.do("POST", "/api/v1/integrations/providers", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create provider: status %d, body %s", resp.StatusCode, raw)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if out.ID == "" {
		t.Fatal("create returned no id")
	}
	return out.ID
}

// The property the whole surface exists to preserve. A credential is accepted
// and never comes back — not from the list, not from the single-provider read,
// not from health, not from a test result, not from an error.
//
// This walks every route rather than the obvious ones because the failure mode
// is a handler somebody adds later that returns a struct with one more field
// than they meant. A test that only checked GET would not have noticed.
func TestNoIntegrationsResponseEverContainsTheCredential(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A hostile-but-plausible upstream: it echoes back everything it was
		// sent, including the credential header. A provider that copied a
		// response into a stored verdict verbatim would leak the key through
		// this, which is exactly the defect the redaction in InstanceConfig
		// exists to stop.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score":         0.1,
			"echoed_header": r.Header.Get("Authorization"),
			"echoed_query":  r.URL.RawQuery,
		})
	}))
	defer upstream.Close()

	id := createProvider(t, h, map[string]any{
		"name":    "Echo",
		"kind":    "customhttp",
		"enabled": true,
		"config": map[string]string{
			"url": upstream.URL + "/lookup?domain={subject}",
			// Query-string authentication, which is the shape most likely to
			// tempt an operator into pasting the key into the url setting
			// instead. Configured here so the credential really does travel in
			// the query string the echoing upstream reflects back.
			"auth_query": "apikey",
		},
		"capabilities": []string{"reputation"},
		"secret":       theCredential,
	})

	// Every route that can produce a body, in the order an operator would
	// reach them.
	calls := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/integrations/providers", nil},
		{"GET", "/api/v1/integrations/providers/" + id, nil},
		{"GET", "/api/v1/integrations/providers/" + id + "/health", nil},
		{"GET", "/api/v1/integrations/templates", nil},
		{"POST", "/api/v1/integrations/providers/" + id + "/test", nil},
		{"POST", "/api/v1/integrations/providers/test", map[string]any{
			"kind": "customhttp",
			"config": map[string]string{
				"url":        upstream.URL + "/lookup?domain={subject}",
				"auth_query": "apikey",
			},
			"secret": theCredential,
		}},
		{"PATCH", "/api/v1/integrations/providers/" + id, map[string]any{
			"secret": theCredential,
		}},
		{"POST", "/api/v1/integrations/providers/" + id + "/secret", map[string]any{
			"secret": theCredential,
		}},
		{"PUT", "/api/v1/integrations/reputation", map[string]any{"mode": "off"}},
	}

	for _, c := range calls {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			_, raw := h.do(c.method, c.path, c.body)
			if strings.Contains(string(raw), theCredential) {
				t.Fatalf("the credential appeared in the response body: %s", raw)
			}
			// The last four characters are the deliberate hint and are
			// expected; anything longer is a leak that the whole-string check
			// above would miss if the key were ever truncated for display.
			if tail := theCredential[len(theCredential)-8:]; strings.Contains(string(raw), tail) {
				t.Fatalf("eight characters of the credential appeared in the response: %s", raw)
			}
		})
	}
}

func TestAStoredCredentialIsReportedByHintOnly(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	id := createProvider(t, h, map[string]any{
		"name":   "VirusTotal",
		"kind":   "virustotal",
		"secret": theCredential,
	})

	_, raw := h.do("GET", "/api/v1/integrations/providers/"+id, nil)
	var got struct {
		SecretSet  bool   `json:"secretSet"`
		SecretHint string `json:"secretHint"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.SecretSet {
		t.Error("a provider with a stored credential does not report one")
	}
	want := theCredential[len(theCredential)-4:]
	if got.SecretHint != want {
		t.Errorf("hint = %q, want the last four characters %q", got.SecretHint, want)
	}
}

// A rotation must replace the credential, not add a second one, and the
// dashboard must be able to see that it landed.
func TestRotatingACredential(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	id := createProvider(t, h, map[string]any{
		"name": "VirusTotal", "kind": "virustotal", "secret": theCredential,
	})

	const rotated = "sk-live-ROTATED-11223344556677889900aa"
	resp, raw := h.do("POST", "/api/v1/integrations/providers/"+id+"/secret",
		map[string]any{"secret": rotated})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate: status %d, body %s", resp.StatusCode, raw)
	}

	row, err := h.store.GetAPIProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if row.SecretHint != rotated[len(rotated)-4:] {
		t.Errorf("hint = %q, want the new credential's tail", row.SecretHint)
	}
	if row.RotatedAt == nil {
		t.Error("no rotation timestamp was recorded")
	}

	// And the new credential is the one that actually opens.
	configs, err := h.api.Intel.LoadProviders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d providers", len(configs))
	}
	if configs[0].Secret != rotated {
		t.Error("the rotated credential is not the one that opens")
	}

	// Removing it leaves the provider configured but unauthenticated.
	resp, raw = h.do("DELETE", "/api/v1/integrations/providers/"+id+"/secret", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete secret: status %d, body %s", resp.StatusCode, raw)
	}
	row, err = h.store.GetAPIProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if row.SecretSet {
		t.Error("the credential survived a delete")
	}
}

// A secret sent to the update route must be refused, not silently ignored. An
// operator who believes they rotated a key they did not is worse off than one
// who got an error.
func TestUpdateRefusesASecretRatherThanIgnoringIt(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	id := createProvider(t, h, map[string]any{"name": "VT", "kind": "virustotal"})

	resp, raw := h.do("PATCH", "/api/v1/integrations/providers/"+id,
		map[string]any{"secret": theCredential})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "/secret") {
		t.Errorf("the error does not name the route to use: %s", raw)
	}

	row, err := h.store.GetAPIProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if row.SecretSet {
		t.Error("a credential was stored by the update route")
	}
}

// Changing the adapter under an existing row would reinterpret its settings as
// a different provider's — a URL becoming a base URL, a scoring path becoming
// nothing.
func TestKindCannotBeChanged(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	id := createProvider(t, h, map[string]any{"name": "VT", "kind": "virustotal"})
	resp, raw := h.do("PATCH", "/api/v1/integrations/providers/"+id,
		map[string]any{"kind": "safebrowsing"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", resp.StatusCode, raw)
	}
	row, err := h.store.GetAPIProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if row.Kind != "virustotal" {
		t.Errorf("kind became %q", row.Kind)
	}
}

func TestAnUnknownKindIsRefusedAtCreate(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	resp, raw := h.do("POST", "/api/v1/integrations/providers",
		map[string]any{"name": "Mystery", "kind": "not-an-adapter"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", resp.StatusCode, raw)
	}

	rows, err := h.store.ListAPIProviders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("a provider with no adapter was stored: %+v", rows)
	}
}

// The default deployment has no engine. Every route must say so in a way that
// names the setting to change, rather than 404ing or panicking on a nil
// dereference.
func TestIntegrationsRoutesAnswerWhenTheFeatureIsOff(t *testing.T) {
	h := newHarness(t)
	h.login()
	// Deliberately not calling enableIntegrations.

	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/integrations/providers"},
		{"POST", "/api/v1/integrations/providers"},
		{"GET", "/api/v1/integrations/providers/x"},
		{"PATCH", "/api/v1/integrations/providers/x"},
		{"DELETE", "/api/v1/integrations/providers/x"},
		{"POST", "/api/v1/integrations/providers/x/secret"},
		{"DELETE", "/api/v1/integrations/providers/x/secret"},
		{"POST", "/api/v1/integrations/providers/x/test"},
		{"GET", "/api/v1/integrations/providers/x/health"},
		{"POST", "/api/v1/integrations/providers/test"},
		{"PUT", "/api/v1/integrations/reputation"},
	} {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			resp, raw := h.do(c.method, c.path, map[string]any{})
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503; body %s", resp.StatusCode, raw)
			}
			if !strings.Contains(string(raw), "dnsdaddy.yaml") {
				t.Errorf("the error does not name the file to change: %s", raw)
			}
		})
	}

	// The template catalogue is the one exception: it describes what this
	// build can do, which is a useful answer even with the feature off, and it
	// touches neither the engine nor a credential.
	resp, _ := h.do("GET", "/api/v1/integrations/templates", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("templates: status %d, want 200", resp.StatusCode)
	}
}

// The security property of the mode ceiling: nothing reachable over the
// network can put a third party in front of DNS answers on a deployment whose
// configuration file did not already allow it.
func TestTheReputationModeCeilingCannotBeRaisedOverTheAPI(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	resp, raw := h.do("PUT", "/api/v1/integrations/reputation",
		map[string]any{"mode": "blocking"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "dnsdaddy.yaml") {
		t.Errorf("the refusal does not say where blocking mode is set: %s", raw)
	}
	if got := h.api.Providers.Mode(); got != apiprovider.ModeCacheOnly {
		t.Errorf("the live mode became %q despite the refusal", got)
	}

	// Turning it down is always allowed — that is the affordance an operator
	// needs during an incident.
	resp, raw = h.do("PUT", "/api/v1/integrations/reputation", map[string]any{"mode": "off"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200; body %s", resp.StatusCode, raw)
	}
	if got := h.api.Providers.Mode(); got != apiprovider.ModeOff {
		t.Errorf("the live mode is %q after switching off", got)
	}
}

// The choice has to survive a restart, and it has to stay under the ceiling
// after a restart even if the configuration file was lowered in between.
func TestTheStoredModeIsBoundedByTheConfiguredCeilingAtBoot(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeBlocking)

	resp, raw := h.do("PUT", "/api/v1/integrations/reputation",
		map[string]any{"mode": "blocking"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", resp.StatusCode, raw)
	}

	ctx := context.Background()
	if got := EffectiveReputationMode(ctx, h.store, "blocking"); got != apiprovider.ModeBlocking {
		t.Errorf("with a blocking ceiling the stored mode is %q", got)
	}
	// The operator edits dnsdaddy.yaml down to cache_only and restarts. The
	// stored "blocking" must not survive that.
	if got := EffectiveReputationMode(ctx, h.store, "cache_only"); got != apiprovider.ModeCacheOnly {
		t.Errorf("a lowered configuration file was overridden by the stored mode: %q", got)
	}
	if got := EffectiveReputationMode(ctx, h.store, "off"); got != apiprovider.ModeOff {
		t.Errorf("a disabled configuration file was overridden by the stored mode: %q", got)
	}
}

// Off is the default and must stay the default: a deployment that never
// touches this feature must not find blocking mode selectable.
func TestBlockingIsNotSelectableUnlessTheFileAllowsIt(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	_, raw := h.do("GET", "/api/v1/integrations/providers", nil)
	var out struct {
		Reputation struct {
			Mode       string   `json:"mode"`
			Ceiling    string   `json:"ceiling"`
			Selectable []string `json:"selectable"`
		} `json:"reputation"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for _, m := range out.Reputation.Selectable {
		if m == "blocking" {
			t.Fatalf("blocking is offered on a cache_only deployment: %v", out.Reputation.Selectable)
		}
	}
	if len(out.Reputation.Selectable) != 2 {
		t.Errorf("selectable = %v, want off and cache_only", out.Reputation.Selectable)
	}
}

// Test connection has to distinguish "the provider answered" from "the
// credential is wrong", because those need different things from the operator.
func TestConnectionTestReportsWhatActuallyHappened(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	var status int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":0.0}`))
	}))
	defer upstream.Close()

	id := createProvider(t, h, map[string]any{
		"name": "Local intel", "kind": "customhttp", "enabled": true,
		"config":       map[string]string{"url": upstream.URL + "/lookup?domain={subject}"},
		"capabilities": []string{"reputation"},
	})

	status = http.StatusOK
	_, raw := h.do("POST", "/api/v1/integrations/providers/"+id+"/test", nil)
	var ok struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &ok); err != nil {
		t.Fatal(err)
	}
	if !ok.OK {
		t.Errorf("a working provider tested as failing: %s", raw)
	}

	status = http.StatusUnauthorized
	_, raw = h.do("POST", "/api/v1/integrations/providers/"+id+"/test", nil)
	if err := json.Unmarshal(raw, &ok); err != nil {
		t.Fatal(err)
	}
	if ok.OK {
		t.Errorf("a rejected credential tested as working: %s", raw)
	}
	if !strings.Contains(ok.Error, "credential") {
		t.Errorf("the error does not tell the operator it is the credential: %q", ok.Error)
	}
}

// A test must not warm the cache. Otherwise a button meant to check a
// credential becomes a way to seed a verdict for a name of somebody's
// choosing, reachable by anybody who can reach the management API.
func TestAConnectionTestDoesNotSeedTheVerdictCache(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":1.0}`))
	}))
	defer upstream.Close()

	id := createProvider(t, h, map[string]any{
		"name": "Always malicious", "kind": "customhttp", "enabled": true,
		"config":       map[string]string{"url": upstream.URL + "/lookup?domain={subject}"},
		"capabilities": []string{"reputation"},
	})

	ctx := context.Background()
	if _, raw := h.do("POST", "/api/v1/integrations/providers/"+id+"/test", nil); raw == nil {
		t.Fatal("no response")
	}
	// Anything the test enqueued has landed by the time the queue is empty, so
	// the check below is not racing a lookup that has not finished.
	drainEngine(t, h)

	// In cache_only mode Consult answers only from the cache, so ok means a
	// verdict for this subject is stored. The connection test looks up exactly
	// this name, and must leave nothing behind.
	if _, ok := h.api.Providers.Consult(ctx, "p_standard", testSubject); ok {
		t.Errorf("the connection test seeded a cached verdict for %s", testSubject)
	}
	drainEngine(t, h)

	// The positive control: the same engine, the same mode, a name it did
	// resolve. Without this the assertion above would pass on an engine that
	// can never produce a cache hit at all.
	h.api.Providers.Consult(ctx, "p_standard", "seeded.example")
	drainEngine(t, h)
	if _, ok := h.api.Providers.Consult(ctx, "p_standard", "seeded.example"); !ok {
		t.Fatal("the engine cached nothing after a resolution, so this test proves nothing")
	}
}

// drainEngine waits until the engine has completed everything it was given.
func drainEngine(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := h.api.Providers.Stats()
		if s.QueueDepth == 0 && s.Completed+s.Dropped >= s.Enqueued {
			// One more scheduling slice, so a task taken off the queue but not
			// yet counted as complete is not mistaken for an empty engine.
			time.Sleep(20 * time.Millisecond)
			s = h.api.Providers.Stats()
			if s.QueueDepth == 0 && s.Completed+s.Dropped >= s.Enqueued {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the provider engine never drained its queue")
}

// The polled endpoint must not call the provider. A dashboard tab left open
// would otherwise spend an operator's quota all day.
func TestHealthMakesNoUpstreamCall(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":0.0}`))
	}))
	defer upstream.Close()

	id := createProvider(t, h, map[string]any{
		"name": "Local intel", "kind": "customhttp", "enabled": true,
		"config":       map[string]string{"url": upstream.URL + "/lookup?domain={subject}"},
		"capabilities": []string{"reputation"},
	})

	for i := 0; i < 5; i++ {
		resp, raw := h.do("GET", "/api/v1/integrations/providers/"+id+"/health", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health: status %d, body %s", resp.StatusCode, raw)
		}
	}
	if calls != 0 {
		t.Errorf("polling health made %d upstream calls", calls)
	}
}

// Every shipped adapter must declare what evidence exists that it works. The
// dashboard renders this on the card, and an adapter added without it would
// silently claim more than the project can support.
func TestEveryTemplateStatesItsVerification(t *testing.T) {
	h := newHarness(t)
	h.login()

	_, raw := h.do("GET", "/api/v1/integrations/templates", nil)
	var out struct {
		Templates []struct {
			Kind         string `json:"kind"`
			DisplayName  string `json:"displayName"`
			PrivacyNote  string `json:"privacyNote"`
			LiveVerified bool   `json:"liveVerified"`
			Verification string `json:"verification"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Templates) < 3 {
		t.Fatalf("only %d templates; the adapters are not registered", len(out.Templates))
	}
	for _, tpl := range out.Templates {
		if tpl.Verification == "" {
			t.Errorf("%s claims no verification evidence", tpl.Kind)
		}
		if tpl.PrivacyNote == "" {
			t.Errorf("%s does not say what leaves the network", tpl.Kind)
		}
		if tpl.LiveVerified {
			t.Errorf("%s claims verification against the live service, which nothing in "+
				"this repository establishes", tpl.Kind)
		}
	}
}

// A provider that cannot be built must appear with its reason, not vanish. An
// operator whose key is wrong has to see the row saying so.
func TestABrokenProviderIsListedWithItsReason(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeOff)

	// VirusTotal refuses to construct with no credential, which is the most
	// common half-finished configuration.
	id := createProvider(t, h, map[string]any{
		"name": "VirusTotal", "kind": "virustotal", "enabled": true,
	})

	_, raw := h.do("GET", "/api/v1/integrations/providers", nil)
	var out struct {
		Providers []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Providers) != 1 {
		t.Fatalf("got %d providers, want the broken one listed", len(out.Providers))
	}
	if out.Providers[0].ID != id {
		t.Fatalf("wrong provider: %+v", out.Providers[0])
	}
	if out.Providers[0].Status != "error" {
		t.Errorf("status = %q, want error", out.Providers[0].Status)
	}
	if out.Providers[0].Detail == "" {
		t.Error("a broken provider gives the operator no reason")
	}
}
