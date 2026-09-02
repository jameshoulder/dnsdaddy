package api

import (
	"context"
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
// The effective mode is the lower of this and the ceiling in dnsdaddy.yaml.
// See reputationCeiling.
const settingReputationMode = "integrations.reputation_mode"

// integrationsAvailable reports whether the feature is wired up at all.
//
// A build with no engine — the default configuration, where integrations are
// switched off — answers 503 rather than 404. The distinction matters to a
// dashboard: 404 means "this resolver does not have this feature", 503 with a
// reason means "it has it, and here is the line to change in dnsdaddy.yaml".
func (a *API) integrationsAvailable(w http.ResponseWriter) bool {
	if a.Providers == nil || a.Intel == nil {
		writeError(w, http.StatusServiceUnavailable,
			"external API integrations are switched off; set integrations.enabled in dnsdaddy.yaml and restart")
		return false
	}
	return true
}

// reputationCeiling is the highest mode this deployment permits, from the
// configuration file.
func (a *API) reputationCeiling() apiprovider.ReputationMode {
	return apiprovider.ParseReputationMode(a.Config.Integrations.ReputationMode)
}

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
	Stats *apiprovider.Stats `json:"stats,omitempty"`
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
		out = append(out, a.viewOf(row, live[row.ID]))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"providers": out,
		"engine":    a.Providers.Stats(),
		"reputation": map[string]any{
			"mode":    a.Providers.Mode(),
			"ceiling": a.reputationCeiling(),
			// Selectable is what the dashboard may offer. Blocking mode is
			// deliberately absent unless the configuration file already allows
			// it: it is the only mode that puts a third party's latency in
			// front of a DNS answer, and that belongs to somebody who read the
			// documentation, not to a radio button.
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
		v.Detail = "Not loaded. Restart, or save the provider again to reload it."
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
	writeJSON(w, http.StatusOK, a.viewOf(row, inst))
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

	created, err := a.Store.CreateAPIProvider(r.Context(), in)
	if err != nil {
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

	a.reloadProviders(r)
	writeJSON(w, http.StatusCreated, a.viewOf(created, nil))
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
		writeStoreError(w, err)
		return
	}

	// Cached verdicts were produced under the old settings — a different
	// endpoint, a different scoring field, a narrower policy scope. Keeping
	// them would let a provider the operator has just reconfigured go on
	// blocking names from its previous configuration.
	a.Providers.InvalidateProvider(id)
	a.reloadProviders(r)
	writeJSON(w, http.StatusOK, a.viewOf(updated, nil))
}

func (a *API) handleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if err := a.Store.DeleteAPIProvider(r.Context(), id); err != nil {
		writeStoreError(w, err)
		return
	}
	a.Providers.InvalidateProvider(id)
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
	if err := a.Intel.SealFor(r.Context(), id, body.Secret); err != nil {
		a.Log.Error("could not store provider credential", "provider_id", id, "error", err.Error())
		writeError(w, http.StatusInternalServerError,
			"the credential could not be encrypted: "+err.Error())
		return
	}

	// A rotation means every cached verdict was produced with the old key. In
	// practice they are still valid, but the operator's mental model of "I
	// rotated the key, everything is fresh from here" should be true.
	a.Providers.InvalidateProvider(id)
	a.reloadProviders(r)

	row, err := a.Store.GetAPIProvider(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// The response carries secretSet and the four-character hint, which is
	// what the dashboard needs to confirm the rotation landed, and nothing
	// that would let anybody reconstruct the key.
	writeJSON(w, http.StatusOK, a.viewOf(row, nil))
}

func (a *API) handleDeleteProviderSecret(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	id := r.PathValue("id")
	if err := a.Store.DeleteProviderSecret(r.Context(), id); err != nil {
		writeStoreError(w, err)
		return
	}
	a.Providers.InvalidateProvider(id)
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
	OK         bool   `json:"ok"`
	LatencyMS  int64  `json:"latencyMs"`
	Error      string `json:"error,omitempty"`
	Detail     string `json:"detail,omitempty"`
	ProviderID string `json:"providerId,omitempty"`
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
	writeJSON(w, http.StatusOK, res)
}

// candidateBody is an unsaved provider the wizard wants to test.
type candidateBody struct {
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
	insts := apiprovider.BuildInstances([]apiprovider.ProviderConfig{cfg}, a.Log)
	if len(insts) == 0 || !insts[0].Usable() {
		msg := "the provider could not be built"
		if len(insts) > 0 && insts[0].Err != nil {
			msg = insts[0].Err.Error()
		}
		return testResult{Error: msg}
	}
	inst := insts[0]

	ctx, cancel := context.WithTimeout(parent, testTimeout)
	defer cancel()

	start := time.Now()
	err := probe(ctx, inst.Provider)
	latency := time.Since(start)

	res := testResult{LatencyMS: latency.Milliseconds()}
	switch {
	case err == nil:
		res.OK = true
		res.Detail = "The provider answered."
	case errors.Is(err, apiprovider.ErrUnauthorised):
		res.Error = "the provider rejected the credential"
	case errors.Is(err, apiprovider.ErrRateLimited):
		// Not a failure of the credential: the key worked well enough to be
		// counted against a quota.
		res.OK = true
		res.Detail = "The credential is accepted, but the provider is rate limiting. " +
			"Lower the requests-per-minute setting."
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
	Mode string `json:"mode"`
}

// handleSetReputationMode changes how much reach providers have over
// resolution, within the ceiling the configuration file sets.
//
// The ceiling is the point. An operator can turn reputation down or off from
// here at any time — which is what you want at three in the morning — but
// cannot raise it above what dnsdaddy.yaml already permits. So a deployment
// whose configuration says "cache_only" can never be talked into putting a
// third party in front of its DNS answers by anything reachable over the
// network, including a stolen session.
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
		writeError(w, http.StatusBadRequest,
			"mode must be one of off, cache_only, blocking")
		return
	}
	ceiling := a.reputationCeiling()
	if mode.Rank() > ceiling.Rank() {
		writeError(w, http.StatusForbidden,
			"this deployment allows at most "+string(ceiling)+" reputation. "+
				"Raise integrations.reputation_mode in dnsdaddy.yaml and restart; "+
				"see docs/external-apis.md for what blocking mode costs.")
		return
	}

	if err := a.Store.SetSetting(r.Context(), settingReputationMode, string(mode)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Providers.SetMode(mode)
	a.Log.Info("reputation mode changed", "mode", string(mode), "ceiling", string(ceiling))

	writeJSON(w, http.StatusOK, map[string]any{
		"mode":       mode,
		"ceiling":    ceiling,
		"selectable": selectableModes(ceiling),
	})
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
		// The write already succeeded and the old instances are still serving,
		// so this is a warning rather than a failed request. The list endpoint
		// will show the row as "not loaded" until the next successful reload.
		a.Log.Warn("could not reload external providers after a write", "error", err.Error())
	}
}

// EffectiveReputationMode resolves the boot mode: the operator's stored choice,
// bounded by the configuration file's ceiling.
//
// Exported because the composition root needs it before an API exists, and
// because putting the rule in one function is the only way both callers can be
// shown to agree.
func EffectiveReputationMode(ctx context.Context, st *store.Store, configured string) apiprovider.ReputationMode {
	ceiling := apiprovider.ParseReputationMode(configured)
	if st == nil {
		return ceiling
	}
	stored, err := st.GetSetting(ctx, settingReputationMode)
	if err != nil || strings.TrimSpace(stored) == "" {
		return ceiling
	}
	mode := apiprovider.ReputationMode(stored)
	if !mode.Valid() || mode.Rank() > ceiling.Rank() {
		// A stored value above the ceiling means the configuration file was
		// lowered since it was written. The file wins.
		return ceiling
	}
	return mode
}
