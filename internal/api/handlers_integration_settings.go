package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

const settingEnrichment = "integrations.enrichment"

const integrationPrivacyNotice = "Only providers you add and enable receive lookups. Enabling reputation can send queried domains on cache misses; enrichment sends the domains you explicitly investigate. Providers may retain these names and charge for requests. Test connection makes a live request using your credential and may query example.com."

// InitializeIntegrationSettings is the composition-root startup contract.
// Legacy disabled/ceiling gates are captured once before saved UI choices
// become authoritative. An uncertain startup never enables external sharing.
func InitializeIntegrationSettings(ctx context.Context, st *store.Store, legacyEnabled bool, legacyMode string, legacyEnrichment bool) (apiprovider.ReputationMode, bool, error) {
	if st == nil {
		return apiprovider.ModeOff, false, errors.New("integration preferences storage is unavailable")
	}
	mode, enrichment, err := st.InitializeIntegrationSettings(ctx, legacyEnabled, legacyMode, legacyEnrichment)
	if err != nil {
		return apiprovider.ModeOff, false, err
	}
	return apiprovider.ParseReputationMode(mode), enrichment, nil
}

type integrationSettingsBody struct {
	ReputationMode    *string `json:"reputationMode"`
	EnrichmentEnabled *bool   `json:"enrichmentEnabled"`
	Consent           bool    `json:"consent"`
	AcceptDNSLatency  bool    `json:"acceptDnsLatency"`
}

func (a *API) integrationSettingsView() map[string]any {
	available := a.Providers != nil && a.Intel != nil
	mode, enrichment := apiprovider.ModeOff, false
	if available {
		mode, enrichment = a.Providers.Mode(), a.Providers.EnrichmentEnabled()
	}
	return map[string]any{
		"available":           available,
		"encryptionAvailable": a.canSealSecrets(),
		"reputationMode":      mode,
		"enrichmentEnabled":   enrichment,
		"selectable":          selectableModes(apiprovider.ModeBlocking),
		"privacyNotice":       integrationPrivacyNotice,
		"restartRequired":     false,
		"providerLimit":       64,
	}
}

func (a *API) handleGetIntegrationSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.integrationSettingsView())
}

func (a *API) handleSetIntegrationSettings(w http.ResponseWriter, r *http.Request) {
	if !a.integrationsAvailable(w) {
		return
	}
	var body integrationSettingsBody
	if !decodeBody(w, r, &body) {
		return
	}
	mode, enrichment := a.Providers.Mode(), a.Providers.EnrichmentEnabled()
	if body.ReputationMode != nil {
		mode = apiprovider.ReputationMode(strings.TrimSpace(*body.ReputationMode))
	}
	if body.EnrichmentEnabled != nil {
		enrichment = *body.EnrichmentEnabled
	}
	if !mode.Valid() {
		writeError(w, http.StatusBadRequest, "reputationMode must be off, cache_only or blocking")
		return
	}
	if ((body.ReputationMode != nil && mode != apiprovider.ModeOff) || (body.EnrichmentEnabled != nil && enrichment)) && !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before external domain sharing is enabled")
		return
	}
	if body.ReputationMode != nil && mode == apiprovider.ModeBlocking && !body.AcceptDNSLatency {
		writeError(w, http.StatusBadRequest, "acceptDnsLatency is required: blocking reputation may delay DNS answers within the configured budget")
		return
	}
	if err := a.Store.SetIntegrationSettings(r.Context(), string(mode), enrichment); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save integration settings")
		return
	}
	a.Providers.SetMode(mode)
	a.Providers.SetEnrichment(enrichment)
	writeJSON(w, http.StatusOK, a.integrationSettingsView())
}

// EffectiveEnrichment lets an explicitly saved UI choice survive restart.
// configured is only the legacy initial value, never an invisible UI ceiling.
func EffectiveEnrichment(ctx context.Context, st *store.Store, configured bool) bool {
	if st != nil {
		if v, err := st.GetSetting(ctx, settingEnrichment); err == nil {
			switch v {
			case "true":
				return true
			case "false":
				return false
			}
		}
	}
	return configured
}
