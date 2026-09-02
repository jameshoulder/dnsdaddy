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
	"github.com/jameshoulder/dnsdaddy/internal/store"
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

/* ---------- metrics ------------------------------------------------------ */

// A deployment with the feature off must not export intel series. A series
// that exists and reads zero tells an operator their providers answered
// nothing, when the truth is they have none — and that is a graph somebody
// would act on.
func TestNoIntelMetricsWhenTheFeatureIsOff(t *testing.T) {
	h := newHarness(t)
	h.login()

	resp, raw := h.do("GET", "/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: status %d", resp.StatusCode)
	}
	if strings.Contains(string(raw), "dnsdaddy_intel_") {
		t.Error("a deployment with no external providers exports intel metrics")
	}
	// And the rest of the metrics surface is unaffected.
	if !strings.Contains(string(raw), "dnsdaddy_queries_total") {
		t.Error("the ordinary metrics stopped being exported")
	}
}

func TestIntelMetricsAreExportedAndCarryNoSecret(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":0.2}`))
	}))
	defer upstream.Close()

	id := createProvider(t, h, map[string]any{
		"name": "Local intel", "kind": "customhttp", "enabled": true,
		"config": map[string]string{
			"url": upstream.URL + "/lookup?domain={subject}", "auth_query": "apikey",
		},
		"capabilities": []string{"reputation"},
		"secret":       theCredential,
	})

	resp, raw := h.do("GET", "/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics: status %d", resp.StatusCode)
	}
	body := string(raw)

	for _, want := range []string{
		"dnsdaddy_intel_reputation_mode 1",
		"dnsdaddy_intel_providers_total 1",
		"dnsdaddy_intel_lookups_dropped_total",
		"dnsdaddy_intel_provider_circuit_open{provider_id=\"" + id + "\"}",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output is missing %q", want)
		}
	}

	// The label is the provider's ID, not its free-text name, and no
	// credential is anywhere near a scrape.
	if strings.Contains(body, theCredential) {
		t.Error("the credential appeared in /metrics")
	}
	if strings.Contains(body, "Local intel") {
		t.Error("an operator-supplied provider name is used as a metric label")
	}
}

// The mode gauge is the alert worth having, so it must actually track the
// mode rather than being a constant.
func TestTheReputationModeGaugeTracksTheMode(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	_, raw := h.do("GET", "/metrics", nil)
	if !strings.Contains(string(raw), "dnsdaddy_intel_reputation_mode 1") {
		t.Fatalf("cache_only did not report 1:\n%s", raw)
	}

	if resp, body := h.do("PUT", "/api/v1/integrations/reputation",
		map[string]any{"mode": "off"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("set mode: %d %s", resp.StatusCode, body)
	}
	_, raw = h.do("GET", "/metrics", nil)
	if !strings.Contains(string(raw), "dnsdaddy_intel_reputation_mode 0") {
		t.Errorf("off did not report 0:\n%s", raw)
	}
}

/* ---------- end to end --------------------------------------------------- */

// The whole stack, in the order the daemon assembles it: a provider is
// configured through the API, its credential is sealed, the engine loads it,
// a verdict is fetched and cached, and the policy engine acts on it.
//
// Every layer below has its own tests. This one exists because they all pass
// against a system where two of them are not actually connected — which is the
// failure a feature spread across six packages actually has.
func TestAProviderConfiguredThroughTheAPIBlocksADomain(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	var sawCredential string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCredential = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "evil.example") {
			_, _ = w.Write([]byte(`{"score":0.98,"category":"malware"}`))
			return
		}
		_, _ = w.Write([]byte(`{"score":0.0}`))
	}))
	defer upstream.Close()

	createProvider(t, h, map[string]any{
		"name": "House intel", "kind": "customhttp", "enabled": true,
		"config": map[string]string{
			"url":         upstream.URL + "/lookup?domain={subject}",
			"score_field": "score",
		},
		"capabilities": []string{"reputation"},
		"secret":       theCredential,
	})

	// The policy engine has no consultant until one is attached — which is what
	// cmd/dnsdaddy does at boot, and what this stands in for.
	h.api.Engine.SetReputation(&intel.Consultant{Engine: h.api.Providers})
	t.Cleanup(func() { h.api.Engine.SetReputation(nil) })

	ctx := context.Background()

	// First evaluation: nothing cached, so cache_only answers immediately and
	// queues the lookup. It must NOT block — an unknown verdict never blocks.
	if d := h.api.Engine.Evaluate("p_standard", "evil.example"); d.Blocked {
		t.Fatalf("a cold cache blocked a domain: %+v", d)
	}
	drainEngine(t, h)

	// Second: the verdict is cached now.
	d := h.api.Engine.Evaluate("p_standard", "evil.example")
	if !d.Blocked {
		t.Fatalf("a cached malicious verdict did not block: %+v", d)
	}
	if d.Source == "" {
		t.Error("the block names no provider, so nobody can tell who decided")
	}
	if d.Category == "" {
		t.Error("the block has no category")
	}

	// A domain the provider says nothing about stays resolvable.
	h.api.Engine.Evaluate("p_standard", "ordinary.example")
	drainEngine(t, h)
	if d := h.api.Engine.Evaluate("p_standard", "ordinary.example"); d.Blocked {
		t.Errorf("a benign verdict blocked a domain: %+v", d)
	}

	// And the credential the API sealed is the one the provider presented.
	if !strings.Contains(sawCredential, theCredential) {
		t.Errorf("the provider authenticated with %q, not the stored credential", sawCredential)
	}

	// The verdict persisted, so a restart does not start from cold.
	verdicts, err := h.store.IntelVerdicts(ctx, "evil.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("got %d persisted verdicts, want 1", len(verdicts))
	}
	if verdicts[0].Disposition != store.DispositionMalicious {
		t.Errorf("persisted disposition = %q", verdicts[0].Disposition)
	}
	if strings.Contains(verdicts[0].Raw, theCredential) {
		t.Error("the credential was persisted inside the stored verdict")
	}
}

// Switching the mode off must stop the consultation on the next query, not the
// next restart — that is the affordance the ceiling exists to preserve.
func TestSwitchingReputationOffStopsBlockingImmediately(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":1.0}`))
	}))
	defer upstream.Close()

	createProvider(t, h, map[string]any{
		"name": "Always malicious", "kind": "customhttp", "enabled": true,
		"config":       map[string]string{"url": upstream.URL + "/lookup?domain={subject}"},
		"capabilities": []string{"reputation"},
	})
	h.api.Engine.SetReputation(&intel.Consultant{Engine: h.api.Providers})
	t.Cleanup(func() { h.api.Engine.SetReputation(nil) })

	h.api.Engine.Evaluate("p_standard", "bad.example")
	drainEngine(t, h)
	if d := h.api.Engine.Evaluate("p_standard", "bad.example"); !d.Blocked {
		t.Fatal("the provider is not blocking, so switching it off proves nothing")
	}

	resp, raw := h.do("PUT", "/api/v1/integrations/reputation", map[string]any{"mode": "off"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set mode off: %d %s", resp.StatusCode, raw)
	}

	if d := h.api.Engine.Evaluate("p_standard", "bad.example"); d.Blocked {
		t.Errorf("a cached verdict still blocked after reputation was switched off: %+v", d)
	}
}

// Deleting a provider must take its cached verdicts with it. Otherwise a
// domain goes on being blocked by a service the operator has removed, with no
// row anywhere explaining why.
func TestDeletingAProviderStopsItsVerdictsBlocking(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":1.0}`))
	}))
	defer upstream.Close()

	id := createProvider(t, h, map[string]any{
		"name": "Doomed", "kind": "customhttp", "enabled": true,
		"config":       map[string]string{"url": upstream.URL + "/lookup?domain={subject}"},
		"capabilities": []string{"reputation"},
	})
	h.api.Engine.SetReputation(&intel.Consultant{Engine: h.api.Providers})
	t.Cleanup(func() { h.api.Engine.SetReputation(nil) })

	h.api.Engine.Evaluate("p_standard", "bad.example")
	drainEngine(t, h)
	if d := h.api.Engine.Evaluate("p_standard", "bad.example"); !d.Blocked {
		t.Fatal("the provider is not blocking, so deleting it proves nothing")
	}

	if resp, raw := h.do("DELETE", "/api/v1/integrations/providers/"+id, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d %s", resp.StatusCode, raw)
	}

	if d := h.api.Engine.Evaluate("p_standard", "bad.example"); d.Blocked {
		t.Errorf("a deleted provider's verdict still blocks: %+v", d)
	}
	rows, err := h.store.IntelVerdicts(context.Background(), "bad.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("%d persisted verdicts survived the provider they came from", len(rows))
	}
}

// Verdicts must survive a restart. Without this intel_verdicts is a log rather
// than a cache: every restart begins cold and re-asks every provider for
// answers already sitting on disk — which on a metered API spends the
// operator's quota to learn nothing.
func TestVerdictsSurviveARestart(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":1.0}`))
	}))
	defer upstream.Close()

	createProvider(t, h, map[string]any{
		"name": "Always malicious", "kind": "customhttp", "enabled": true,
		"config":       map[string]string{"url": upstream.URL + "/lookup?domain={subject}"},
		"capabilities": []string{"reputation"},
	})

	ctx := context.Background()
	h.api.Providers.Consult(ctx, "p_standard", "bad.example")
	drainEngine(t, h)
	if _, ok := h.api.Providers.Consult(ctx, "p_standard", "bad.example"); !ok {
		t.Fatal("the verdict was never cached, so there is nothing to survive")
	}
	after := calls

	// A restart: a brand-new engine over the same database, assembled the way
	// cmd/dnsdaddy assembles it.
	source := h.api.Intel
	restarted := apiprovider.NewEngine(apiprovider.Options{
		Mode:  apiprovider.ModeCacheOnly,
		Store: &intel.VerdictStore{Store: h.store},
	})
	if err := restarted.Reload(ctx, source); err != nil {
		t.Fatal(err)
	}
	restarted.Start(ctx)
	t.Cleanup(restarted.Stop)

	loaded, err := restarted.WarmCache(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == 0 {
		t.Fatal("the restarted engine loaded no verdicts from disk")
	}

	// The verdict is there, from the cache, without another upstream call.
	v, ok := restarted.Consult(ctx, "p_standard", "bad.example")
	if !ok {
		t.Fatal("the restarted engine did not have the verdict")
	}
	if v.Disposition != apiprovider.DispositionMalicious {
		t.Errorf("restored disposition = %q", v.Disposition)
	}
	if calls != after {
		t.Errorf("the restarted engine made %d fresh upstream calls for a cached name", calls-after)
	}
}

// A verdict from a provider the operator has deleted must not come back at the
// next restart. The row is gone with the provider, but a warm-up that trusted
// its input rather than the instance list would be a second way for a removed
// service to go on influencing resolution.
func TestWarmingIgnoresVerdictsFromProvidersThatNoLongerExist(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	ctx := context.Background()
	// A verdict attributed to a provider that was never configured, written
	// straight to the store so the foreign key is the only thing that could
	// have stopped it — and it is a cache warm-up's job not to trust it.
	p := mustStoreProvider(t, h)
	if err := (&intel.VerdictStore{Store: h.store}).SaveVerdict(ctx, "ghost.example", p.ID,
		apiprovider.Verdict{Score: 1, Disposition: apiprovider.DispositionMalicious},
		time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// An engine that has never heard of that provider.
	engine := apiprovider.NewEngine(apiprovider.Options{
		Mode:  apiprovider.ModeCacheOnly,
		Store: &intel.VerdictStore{Store: h.store},
	})
	engine.Start(ctx)
	t.Cleanup(engine.Stop)

	loaded, err := engine.WarmCache(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 0 {
		t.Errorf("warmed %d verdicts from a provider the engine does not have", loaded)
	}
	if _, ok := engine.Consult(ctx, "p_standard", "ghost.example"); ok {
		t.Error("a verdict from an unknown provider reached the resolution path")
	}
}

// mustStoreProvider writes a provider row directly, bypassing the API.
func mustStoreProvider(t *testing.T, h *harness) store.APIProvider {
	t.Helper()
	p, err := h.store.CreateAPIProvider(context.Background(), store.APIProvider{
		Name: "Written directly", Kind: "customhttp", Enabled: true,
		Config: map[string]string{"url": "https://example.test/lookup?d={subject}"},
	})
	if err != nil {
		t.Fatalf("create provider row: %v", err)
	}
	return p
}

// Editing a provider must discard its cached verdicts. They were produced
// under the settings being replaced — a different endpoint, a different
// scoring field, a narrower scope — and keeping them would let a provider the
// operator has just reconfigured go on blocking names from its old one.
//
// This is the case where cache invalidation is actually observable: on delete
// the instance disappears and the outcome would be right either way, so only
// an edit isolates it.
func TestEditingAProviderDiscardsItsCachedVerdicts(t *testing.T) {
	h := newHarness(t)
	h.login()
	enableIntegrations(t, h, apiprovider.ModeCacheOnly)

	var score = "1.0"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score":` + score + `}`))
	}))
	defer upstream.Close()

	id := createProvider(t, h, map[string]any{
		"name": "Reconfigured", "kind": "customhttp", "enabled": true,
		"config":       map[string]string{"url": upstream.URL + "/lookup?domain={subject}"},
		"capabilities": []string{"reputation"},
	})

	ctx := context.Background()
	h.api.Providers.Consult(ctx, "p_standard", "bad.example")
	drainEngine(t, h)
	if v, ok := h.api.Providers.Consult(ctx, "p_standard", "bad.example"); !ok ||
		v.Disposition != apiprovider.DispositionMalicious {
		t.Fatal("the malicious verdict was never cached, so discarding it proves nothing")
	}

	// The operator points the provider somewhere that answers differently.
	score = "0.0"
	if resp, raw := h.do("PATCH", "/api/v1/integrations/providers/"+id,
		map[string]any{"name": "Reconfigured again"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("patch: %d %s", resp.StatusCode, raw)
	}

	// Immediately after the edit the cache is empty, so cache_only answers
	// "unknown" rather than serving the verdict from the old configuration.
	if v, ok := h.api.Providers.Consult(ctx, "p_standard", "bad.example"); ok &&
		v.Disposition == apiprovider.DispositionMalicious {
		t.Fatal("a verdict from the pre-edit configuration survived the edit")
	}

	// And the re-fetch under the new configuration lands.
	drainEngine(t, h)
	if v, ok := h.api.Providers.Consult(ctx, "p_standard", "bad.example"); ok &&
		v.Disposition == apiprovider.DispositionMalicious {
		t.Errorf("the provider still reports malicious after answering 0.0: %+v", v)
	}
}
