package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// This file serves Integrations → External APIs: the CRUD, credential
// rotation, connection testing and health for operator-configured threat
// intelligence providers.
//
// One rule governs every handler here, and it is the reason the file is
// separate rather than folded into handlers_config.go: a credential goes in
// and never comes out. There is no field, no query parameter, no error message
// and no debug path on this surface that returns a stored secret, and the
// tests in integrations_test.go assert that by probing every response body for
// the credential they planted. store.APIProvider cannot carry one — see its
// doc comment — so the only way a secret could reach a response is if a
// handler in this file went and fetched it, which none does.

// settingReputationMode is where the operator's mode choice is persisted.
//
// A saved choice overrides the legacy YAML initial value. No restart is needed.
const settingReputationMode = "integrations.reputation_mode"

// integrationsAvailable tolerates an unwired dependency in tests or a partial
// embedding; production always starts the idle engine, even with mode off.
func (a *API) integrationsAvailable(w http.ResponseWriter) bool {
	if a.Providers == nil || a.Intel == nil {
		writeError(w, http.StatusServiceUnavailable, "external API engine is unavailable; inspect server startup diagnostics")
		return false
	}
	return true
}

// All modes can be configured through the authenticated UI. Enabling sharing
// requires consent; blocking additionally requires an explicit latency warning.
func (a *API) reputationCeiling() apiprovider.ReputationMode { return apiprovider.ModeBlocking }

// --- listing ---------------------------------------------------------------

// providerView is one provider as the dashboard sees it.
//
// It embeds store.APIProvider, which carries secretSet and a four-character
// hint and nothing else about the credential, and adds live state the database
// does not hold.
type providerView struct {
	store.APIProvider
	// Status is one of ok, disabled, error — what the card's badge shows.
	Status string `json:"status"`
	// Detail explains a non-ok status in a sentence an operator can act on.
	Detail string `json:"detail,omitempty"`
	// DisplayName and the verification fields come from the adapter's
	// template, so a card can say what the provider is and what evidence
	// exists that the adapter works without a second request.
	DisplayName  string `json:"displayName,omitempty"`
	PrivacyNote  string `json:"privacyNote,omitempty"`
	DocsURL      string `json:"docsUrl,omitempty"`
	LiveVerified bool   `json:"liveVerified"`
	Verification string `json:"verification,omitempty"`
	// Stats are the resilient client's counters: calls, mean latency, error
	// rate, breaker state. Absent for a provider that never built.
	Stats    *apiprovider.Stats  `json:"stats,omitempty"`
	LastTest *providerTestRecord `json:"lastTest,omitempty"`
}

func (a *API) handleListProviders(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	rows, err := a.Store.ListAPIProviders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	live := make(map[string]*apiprovider.Instance, len(rows))
	for _, inst := range a.Providers.Instances() {
		live[inst.ID] = inst
	}

	out := make([]providerView, 0, len(rows))
	for _, row := range rows {
		v := a.viewOf(row, live[row.ID])
		v.LastTest = a.providerLastTest(r.Context(), row)
		out = append(out, v)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"providers": out,
		"engine":    a.Providers.Stats(),
		"settings":  a.integrationSettingsView(),
		"reputation": map[string]any{
			"mode":    a.Providers.Mode(),
			"ceiling": a.reputationCeiling(),

			"selectable": selectableModes(a.reputationCeiling()),
		},
	})
}

// selectableModes lists the modes the API will accept, given the ceiling.
func selectableModes(ceiling apiprovider.ReputationMode) []apiprovider.ReputationMode {
	all := []apiprovider.ReputationMode{
		apiprovider.ModeOff,
		apiprovider.ModeCacheOnly,
		apiprovider.ModeBlocking,
	}
	out := make([]apiprovider.ReputationMode, 0, len(all))
	for _, m := range all {
		if m.Rank() <= ceiling.Rank() {
			out = append(out, m)
		}
	}
	return out
}

// viewOf merges a database row with its live instance.
func (a *API) viewOf(row store.APIProvider, inst *apiprovider.Instance) providerView {
	v := providerView{APIProvider: row, Status: "ok"}

	if t, ok := apiprovider.TemplateFor(row.Kind); ok {
		v.DisplayName = t.DisplayName
		v.PrivacyNote = t.PrivacyNote
		v.DocsURL = t.DocsURL
		v.LiveVerified = t.LiveVerified
		v.Verification = t.Verification
	}

	switch {
	case !row.Enabled:
		v.Status = "disabled"
		v.Detail = "Switched off. No queries are sent to this provider."
	case inst == nil:
		// A row exists that the engine has not picked up. Almost always a
		// reload that has not happened yet; saying so beats an empty badge.
		v.Status = "error"
		v.Detail = "Not loaded. Save the provider again and inspect its validation result."
	case inst.Err != nil:
		v.Status = "error"
		// inst.Err comes from an adapter constructor or from the keyring, both
		// documented never to carry the credential and tested for it.
		v.Detail = inst.Err.Error()
	}

	if inst != nil && inst.Client != nil {
		s := inst.Client.Stats()
		v.Stats = &s
	}
	return v
}

func (a *API) handleGetProvider(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	row, err := a.Store.GetAPIProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var inst *apiprovider.Instance
	for _, i := range a.Providers.Instances() {
		if i.ID == row.ID {
			inst = i
			break
		}
	}
	v := a.viewOf(row, inst)
	v.LastTest = a.providerLastTest(r.Context(), row)
	writeJSON(w, http.StatusOK, v)
}

// --- create and update -----------------------------------------------------

// providerBody is the create and update payload.
//
// Secret is the one write-only field on this API. It is accepted here, sealed
// immediately, and never appears in any response: see the note at the top of
// this file, and openapi.yaml, where it is marked writeOnly so no generated
// client expects to read it back.
type providerBody struct {
	Name            *string            `json:"name"`
	Kind            *string            `json:"kind"`
	Enabled         *bool              `json:"enabled"`
	Capabilities    *[]string          `json:"capabilities"`
	Config          *map[string]string `json:"config"`
	TimeoutMS       *int               `json:"timeoutMs"`
	RatePerMinute   *int               `json:"ratePerMinute"`
	CacheTTLSeconds *int               `json:"cacheTtlSeconds"`
	PolicyScope     *[]string          `json:"policyScope"`
	Secret          *string            `json:"secret"`
	Consent         bool               `json:"consent"`
}

func (a *API) handleCreateProvider(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	var body providerBody
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Kind == nil || strings.TrimSpace(*body.Kind) == "" {
		writeError(w, http.StatusBadRequest, "kind is required")
		return
	}
	kind := strings.TrimSpace(*body.Kind)
	if !apiprovider.Known(kind) {
		writeError(w, http.StatusBadRequest, "no adapter for provider kind "+kind+" in this build")
		return
	}

	// A credential that cannot be sealed must stop the create, not produce a
	// provider that looks configured and silently has no key.
	if body.Secret != nil && strings.TrimSpace(*body.Secret) != "" && !a.canSealSecrets() {
		writeError(w, http.StatusServiceUnavailable, a.sealUnavailableReason())
		return
	}

	in := store.APIProvider{Kind: kind}
	if body.Name != nil {
		in.Name = *body.Name
	}
	if body.Enabled != nil {
		in.Enabled = *body.Enabled
	}
	if body.Capabilities != nil {
		in.Capabilities = *body.Capabilities
	}
	if body.Config != nil {
		in.Config = *body.Config
	}
	if body.TimeoutMS != nil {
		in.TimeoutMS = *body.TimeoutMS
	}
	if body.RatePerMinute != nil {
		in.RatePerMinute = *body.RatePerMinute
	}
	if body.CacheTTLSeconds != nil {
		in.CacheTTLSeconds = *body.CacheTTLSeconds
	}
	if body.PolicyScope != nil {
		in.PolicyScope = *body.PolicyScope
	}

	if err := validateProviderConfiguration(in, body.Secret); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Enabled && !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before this provider can receive domains")
		return
	}
	// A failed credential write must leave an inert draft, including after a
	// process restart. Enable only once all configuration has been saved.
	requestedEnabled := in.Enabled
	in.Enabled = false
	created, err := a.Store.CreateManagedAPIProvider(r.Context(), in)
	if err != nil {
		if errors.Is(err, store.ErrProviderLimit) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}

	if body.Secret != nil && strings.TrimSpace(*body.Secret) != "" {
		if err := a.Intel.SealFor(r.Context(), created.ID, *body.Secret); err != nil {
			// The row is already committed. Removing it would be the tidier
			// story, but it would also throw away the operator's configuration
			// because of a keyring problem they can fix — so the provider
			// stays, with no credential, and the error says which half failed.
			a.Log.Error("could not store provider credential",
				"provider_id", created.ID, "error", err.Error())
			writeError(w, http.StatusInternalServerError,
				"the provider was saved but its credential could not be encrypted: "+err.Error())
			return
		}
		created, err = a.Store.GetAPIProvider(r.Context(), created.ID)
		if err != nil {
			writeStoreError(w, err)
			return
		}
	}

	if requestedEnabled {
		created, err = a.Store.UpdateAPIProvider(r.Context(), created.ID, store.APIProviderUpdate{Enabled: &requestedEnabled})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "provider was saved as a disabled draft; enabling failed")
			return
		}
	}
	a.reloadProviders(r)
	writeJSON(w, http.StatusCreated, a.currentProviderView(r.Context(), created))
}

func (a *API) handleUpdateProvider(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	var body providerBody
	if !decodeBody(w, r, &body) {
		return
	}
	// Two fields are refused rather than ignored. Changing an adapter under a
	// row would reinterpret its settings as a different provider's, and a
	// silently dropped credential is worse than a rejected request — the
	// operator would believe they had rotated a key they had not.
	if body.Kind != nil {
		writeError(w, http.StatusBadRequest,
			"kind cannot be changed; delete the provider and add it again")
		return
	}
	if body.Secret != nil {
		writeError(w, http.StatusBadRequest,
			"use POST /api/v1/integrations/providers/{id}/secret to set or rotate the credential")
		return
	}

	id := r.PathValue("id")
	current, err := a.Store.GetAPIProvider(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	candidate := current
	if body.Name != nil {
		candidate.Name = *body.Name
	}
	if body.Enabled != nil {
		candidate.Enabled = *body.Enabled
	}
	if body.Config != nil {
		candidate.Config = *body.Config
	}
	if body.Capabilities != nil {
		candidate.Capabilities = *body.Capabilities
	}
	if body.TimeoutMS != nil {
		candidate.TimeoutMS = *body.TimeoutMS
	}
	if body.RatePerMinute != nil {
		candidate.RatePerMinute = *body.RatePerMinute
	}
	if body.CacheTTLSeconds != nil {
		candidate.CacheTTLSeconds = *body.CacheTTLSeconds
	}
	if body.PolicyScope != nil {
		candidate.PolicyScope = *body.PolicyScope
	}
	onlyDisable := body.Enabled != nil && !*body.Enabled && body.Name == nil && body.Config == nil && body.Capabilities == nil && body.PolicyScope == nil && body.TimeoutMS == nil && body.RatePerMinute == nil && body.CacheTTLSeconds == nil
	if !onlyDisable {
		if err := validateProviderConfiguration(candidate, nil); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if candidate.Enabled && ((body.Enabled != nil && *body.Enabled) || body.Config != nil || body.Capabilities != nil || body.PolicyScope != nil) && !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before enabling or changing what this provider receives")
		return
	}
	// Revoke the old generation and let any local result commit finish before
	// the transaction expires its durable cache. Late HTTP results are ignored.
	a.Providers.InvalidateProvider(id)
	updated, err := a.Store.UpdateAPIProvider(r.Context(), id, store.APIProviderUpdate{
		Name:            body.Name,
		Enabled:         body.Enabled,
		Capabilities:    body.Capabilities,
		Config:          body.Config,
		TimeoutMS:       body.TimeoutMS,
		RatePerMinute:   body.RatePerMinute,
		CacheTTLSeconds: body.CacheTTLSeconds,
		PolicyScope:     body.PolicyScope,
	})
	if err != nil {
		a.reloadProviders(r)
		writeStoreError(w, err)
		return
	}

	// Cached verdicts were produced under the old settings — a different
	// endpoint, a different scoring field, a narrower policy scope. Keeping
	// them would let a provider the operator has just reconfigured go on
	// blocking names from its previous configuration.
	a.reloadProviders(r)
	writeJSON(w, http.StatusOK, a.currentProviderView(r.Context(), updated))
}

func (a *API) handleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	id := r.PathValue("id")
	a.Providers.InvalidateProvider(id)
	if err := a.Store.DeleteAPIProvider(r.Context(), id); err != nil {
		a.reloadProviders(r)
		writeStoreError(w, err)
		return
	}
	a.reloadProviders(r)
	w.WriteHeader(http.StatusNoContent)
}

// --- credentials -----------------------------------------------------------

type secretBody struct {
	Secret string `json:"secret"`
}

// handleSetProviderSecret stores or rotates a credential.
//
// Separate from the update handler on purpose. A rotation is a distinct
// operator action with a distinct failure mode, it is the only request on this
// API whose body must never be logged, and giving it its own route means the
// audit question "what could have written a key" has one route to look at
// rather than two.
func (a *API) handleSetProviderSecret(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	var body secretBody
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.Secret) > 16384 || strings.ContainsAny(body.Secret, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "credential is too long")
		return
	}
	if strings.TrimSpace(body.Secret) == "" {
		writeError(w, http.StatusBadRequest,
			"secret is required; use DELETE to remove the stored credential")
		return
	}
	if !a.canSealSecrets() {
		writeError(w, http.StatusServiceUnavailable, a.sealUnavailableReason())
		return
	}

	id := r.PathValue("id")
	// Prove the provider exists before writing, so a typo in the ID fails as a
	// 404 rather than as a foreign-key error from SQLite.
	if _, err := a.Store.GetAPIProvider(r.Context(), id); err != nil {
		writeStoreError(w, err)
		return
	}
	a.Providers.InvalidateProvider(id)
	if err := a.Intel.SealFor(r.Context(), id, body.Secret); err != nil {
		a.reloadProviders(r)
		a.Log.Error("could not store provider credential", "provider_id", id, "error", err.Error())
		writeError(w, http.StatusInternalServerError,
			"the credential could not be encrypted: "+err.Error())
		return
	}

	// A rotation means every cached verdict was produced with the old key. In
	// practice they are still valid, but the operator's mental model of "I
	// rotated the key, everything is fresh from here" should be true.
	a.reloadProviders(r)

	row, err := a.Store.GetAPIProvider(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// The response carries secretSet and the four-character hint, which is
	// what the dashboard needs to confirm the rotation landed, and nothing
	// that would let anybody reconstruct the key.
	writeJSON(w, http.StatusOK, a.currentProviderView(r.Context(), row))
}

func (a *API) handleDeleteProviderSecret(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	id := r.PathValue("id")
	disabled := false
	a.Providers.InvalidateProvider(id)
	if _, err := a.Store.UpdateAPIProvider(r.Context(), id, store.APIProviderUpdate{Enabled: &disabled}); err != nil {
		a.reloadProviders(r)
		writeStoreError(w, err)
		return
	}
	if err := a.Store.DeleteProviderSecret(r.Context(), id); err != nil {
		a.reloadProviders(r)
		writeStoreError(w, err)
		return
	}
	a.reloadProviders(r)
	w.WriteHeader(http.StatusNoContent)
}

// canSealSecrets reports whether the keyring can encrypt.
func (a *API) canSealSecrets() bool {
	return a.Intel != nil && a.Intel.Keyring != nil && a.Intel.Keyring.Available()
}

// sealUnavailableReason explains a keyring that cannot encrypt, in terms of
// the file the operator has to fix.
func (a *API) sealUnavailableReason() string {
	msg := "credentials cannot be stored because the encryption key is unavailable"
	if a.Intel != nil && a.Intel.Keyring != nil {
		if err := a.Intel.Keyring.Err(); err != nil {
			return msg + ": " + err.Error()
		}
	}
	return msg + "; check that secrets.key in the data directory is readable and writable"
}

// --- templates -------------------------------------------------------------

// handleProviderTemplates serves the catalogue the add-provider wizard renders.
//
// Built from the adapter registry rather than from a list in JavaScript, so an
// adapter that is compiled in is offered and one that is not cannot be chosen.
func (a *API) handleProviderTemplates(w http.ResponseWriter, r *http.Request) {
	templates := apiprovider.Templates()
	writeJSON(w, http.StatusOK, map[string]any{
		"templates": templates,
		// Repeated here so the wizard can warn before the operator types a key
		// rather than after, and so this endpoint is useful on its own.
		"reputation": map[string]any{
			"ceiling":    a.reputationCeiling(),
			"selectable": selectableModes(a.reputationCeiling()),
		},
	})
}

// --- testing and health ----------------------------------------------------

// testTimeout bounds a connection test.
//
// Longer than any provider's own timeout, because a test is an operator
// waiting on a spinner and a slow first answer is more useful than a fast
// "timed out". Shorter than a browser gives up.
const testTimeout = 20 * time.Second

type testResult struct {
	TestedAt   time.Time `json:"testedAt"`
	OK         bool      `json:"ok"`
	LatencyMS  int64     `json:"latencyMs"`
	Error      string    `json:"error,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	ProviderID string    `json:"providerId,omitempty"`
}

// handleTestProvider makes one live call to a saved provider.
//
// This is the only handler on this surface that reaches the internet, and it
// does so only when an operator presses a button. It never touches the engine's
// instance list or its cache: a test that warmed the cache would let somebody
// seed a verdict for a name of their choosing through a button meant to check
// a credential.
func (a *API) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	var body struct {
		Consent bool `json:"consent"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before making a live provider test")
		return
	}
	id := r.PathValue("id")
	row, err := a.Store.GetAPIProvider(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	configs, err := a.Intel.LoadProviders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var cfg *apiprovider.ProviderConfig
	for i := range configs {
		if configs[i].ID == id {
			cfg = &configs[i]
			break
		}
	}
	if cfg == nil {
		writeStoreError(w, store.ErrNotFound)
		return
	}
	// A disabled provider is still testable: an operator configures, tests,
	// and only then switches it on.
	enabled := *cfg
	enabled.Enabled = true

	res := a.runProviderTest(r.Context(), enabled)
	res.ProviderID = row.ID
	res.TestedAt = time.Now().UTC()
	record := providerTestRecord{testResult: res, Fingerprint: providerFingerprint(row)}
	if encoded, err := json.Marshal(record); err == nil {
		if err := a.Store.SetSetting(r.Context(), "integrations.provider_test."+row.ID, string(encoded)); err != nil {
			writeError(w, http.StatusInternalServerError, "provider was tested but its result could not be saved")
			return
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// candidateBody is an unsaved provider the wizard wants to test.
type candidateBody struct {
	Consent       bool              `json:"consent"`
	Kind          string            `json:"kind"`
	Config        map[string]string `json:"config"`
	Secret        string            `json:"secret"`
	TimeoutMS     int               `json:"timeoutMs"`
	RatePerMinute int               `json:"ratePerMinute"`
}

// handleTestCandidate tests a provider that has not been saved.
//
// The wizard's "Test connection" before "Save", so an operator finds out a key
// is wrong while the form is still open. The credential arrives in the body,
// is used for one call, and is never written anywhere — not to the database,
// not to the log, not to the response.
func (a *API) handleTestCandidate(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	var body candidateBody
	if !decodeBody(w, r, &body) {
		return
	}
	if !apiprovider.Known(body.Kind) {
		writeError(w, http.StatusBadRequest, "no adapter for provider kind "+body.Kind+" in this build")
		return
	}
	if !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before making a live provider test")
		return
	}
	if err := validateProviderConfiguration(store.APIProvider{Name: "Candidate", Kind: body.Kind, Config: body.Config, TimeoutMS: body.TimeoutMS, RatePerMinute: body.RatePerMinute}, &body.Secret); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res := a.runProviderTest(r.Context(), apiprovider.ProviderConfig{
		ID:            "candidate",
		Name:          body.Kind,
		Kind:          body.Kind,
		Enabled:       true,
		Capabilities:  []string{string(apiprovider.CapReputation)},
		Settings:      body.Config,
		Secret:        body.Secret,
		TimeoutMS:     body.TimeoutMS,
		RatePerMinute: body.RatePerMinute,
		Transport:     a.Intel.Transport,
	})
	writeJSON(w, http.StatusOK, res)
}

// testSubject is the domain a connection test looks up when the adapter has no
// health check of its own.
//
// example.com, because it is reserved by RFC 2606 for exactly this, it is
// resolvable, and no provider will have anything interesting on file for it —
// so a test cannot be used to look up a name the operator would not otherwise
// have disclosed.
const testSubject = "example.com"

// runProviderTest builds one throwaway provider and calls it once.
func (a *API) runProviderTest(parent context.Context, cfg apiprovider.ProviderConfig) testResult {
	if a.Intel != nil {
		cfg.Transport = a.Intel.Transport
	}
	insts := apiprovider.BuildInstances([]apiprovider.ProviderConfig{cfg}, a.Log)
	if len(insts) == 0 || !insts[0].Usable() {
		msg := "the provider could not be built"
		if len(insts) > 0 && insts[0].Err != nil {
			msg = insts[0].Err.Error()
		}
		return testResult{Error: msg, TestedAt: time.Now().UTC()}
	}
	inst := insts[0]

	ctx, cancel := context.WithTimeout(parent, testTimeout)
	defer cancel()

	start := time.Now()
	err := probe(ctx, inst.Provider)
	latency := time.Since(start)

	res := testResult{LatencyMS: latency.Milliseconds(), TestedAt: time.Now().UTC()}
	switch {
	case err == nil:
		res.OK = true
		res.Detail = "The provider answered."
	case errors.Is(err, apiprovider.ErrUnauthorised):
		res.Error = "the provider rejected the credential"
	case errors.Is(err, apiprovider.ErrRateLimited):
		// A 429 can be emitted before authentication. It does not prove the
		// credential worked and must not be recorded as a verified connection.
		res.Error = "the provider rate-limited the test; its credential and response could not be verified"
	case errors.Is(err, apiprovider.ErrNoCredential):
		res.Error = "this provider needs a credential"
	default:
		// err comes from an adapter, which is documented never to carry the
		// credential and is tested for it in adapters_test.go.
		res.Error = err.Error()
	}
	return res
}

// probe asks a provider to prove it works, preferring its own health check.
func probe(ctx context.Context, p apiprovider.Provider) error {
	if hc, ok := p.(apiprovider.HealthChecker); ok {
		err := hc.CheckHealth(ctx)
		if !errors.Is(err, apiprovider.ErrNotSupported) {
			return err
		}
	}
	rep, ok := p.(apiprovider.ReputationProvider)
	if !ok {
		return errors.New("this provider has nothing to test")
	}
	_, err := rep.Reputation(ctx, apiprovider.DomainSubject(testSubject))
	return err
}

// handleProviderHealth reports a provider's live state without calling it.
//
// Deliberately free of network access: this is what a dashboard polls, and a
// polled endpoint that makes an upstream request would burn an operator's
// quota in the background for as long as a tab is open. Everything here comes
// from counters the resilient client already keeps.
func (a *API) handleProviderHealth(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	id := r.PathValue("id")
	row, err := a.Store.GetAPIProvider(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var inst *apiprovider.Instance
	for _, i := range a.Providers.Instances() {
		if i.ID == id {
			inst = i
			break
		}
	}
	v := a.viewOf(row, inst)
	body := map[string]any{
		"providerId": row.ID,
		"status":     v.Status,
		"detail":     v.Detail,
	}
	if v.Stats != nil {
		body["stats"] = v.Stats
	}
	writeJSON(w, http.StatusOK, body)
}

// --- reputation mode -------------------------------------------------------

type reputationBody struct {
	Mode             string `json:"mode"`
	Consent          bool   `json:"consent"`
	AcceptDNSLatency bool   `json:"acceptDnsLatency"`
}

// Retained for API compatibility. The richer settings endpoint also controls
// explicit investigation enrichment; neither requires editing a YAML file.
func (a *API) handleSetReputationMode(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	var body reputationBody
	if !decodeBody(w, r, &body) {
		return
	}
	mode := apiprovider.ReputationMode(strings.TrimSpace(body.Mode))
	if !mode.Valid() {
		writeError(w, http.StatusBadRequest, "mode must be one of off, cache_only, blocking")
		return
	}
	if mode != apiprovider.ModeOff && !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before external domain sharing is enabled")
		return
	}
	if mode == apiprovider.ModeBlocking && !body.AcceptDNSLatency {
		writeError(w, http.StatusBadRequest, "acceptDnsLatency is required for blocking reputation")
		return
	}
	if err := a.Store.SetIntegrationSettings(r.Context(), string(mode), a.Providers.EnrichmentEnabled()); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save integration settings")
		return
	}
	a.Providers.SetMode(mode)
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "ceiling": apiprovider.ModeBlocking, "selectable": selectableModes(apiprovider.ModeBlocking)})
}

// --- reload ----------------------------------------------------------------

// reloadProviders rebuilds the engine's instances after a write.
//
// Synchronous, unlike the blocklist reindex: the set is a handful of rows, the
// work is opening a few sealed credentials, and an operator who saves a
// provider and immediately presses Test must not race a background reload.
func (a *API) reloadProviders(r *http.Request) {
	if a.Providers == nil || a.Intel == nil {
		return
	}
	if err := a.Providers.Reload(r.Context(), a.Intel); err != nil {
		// A database read failure must not preserve an instance the operator
		// just disabled or reconfigured. Stop external requests until a later
		// reload succeeds; local DNS continues without API reputation.
		a.Providers.SetInstances(nil)
		a.Log.Warn("could not reload external providers after a write", "error", err.Error())
	}
}

// EffectiveReputationMode uses the last explicit UI choice. The configured
// value is an initial migration fallback; it cannot silently undo a saved mode.
func EffectiveReputationMode(ctx context.Context, st *store.Store, configured string) apiprovider.ReputationMode {
	if st != nil {
		if value, err := st.GetSetting(ctx, settingReputationMode); err == nil && value != "" {
			return apiprovider.ParseReputationMode(value)
		}
	}
	return apiprovider.ParseReputationMode(configured)
}
