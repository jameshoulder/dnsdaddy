package api

import (
	"net/http"
	"strings"

	"github.com/jameshoulder/dnsdaddy/internal/secrets"
	"github.com/jameshoulder/dnsdaddy/internal/webhook"
)

func (a *API) webhookAvailable(w http.ResponseWriter) bool {
	if a.Webhooks == nil {
		writeError(w, http.StatusServiceUnavailable, "webhook delivery is unavailable; inspect server startup diagnostics")
		return false
	}
	return true
}

func (a *API) handleGetWebhook(w http.ResponseWriter, r *http.Request) {
	if !a.webhookAvailable(w) {
		return
	}
	c, err := a.Store.GetWebhookConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webhook configuration could not be read")
		return
	}
	stats, err := a.Store.GetWebhookStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webhook delivery counters could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": c, "stats": stats, "privacyNotice": "Enabled notifications send finding domains, client IPs and detection summaries to your receiver. Selecting review events also sends review notes and actor labels. No prior events are sent when you enable delivery. Saving changes discards queued events and counts them as dropped."})
}

type webhookBody struct {
	Enabled      *bool     `json:"enabled"`
	URL          *string   `json:"url"`
	EventTypes   *[]string `json:"eventTypes"`
	AllowPrivate *bool     `json:"allowPrivate"`
	TimeoutMS    *int      `json:"timeoutMs"`
	MaxAttempts  *int      `json:"maxAttempts"`
	MaxQueue     *int      `json:"maxQueue"`
	Secret       *string   `json:"secret"`
	Consent      bool      `json:"consent"`
}

func (a *API) handleSetWebhook(w http.ResponseWriter, r *http.Request) {
	if !a.webhookAvailable(w) {
		return
	}
	var body webhookBody
	if !decodeBody(w, r, &body) {
		return
	}
	c, err := a.Store.GetWebhookConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webhook configuration could not be read")
		return
	}
	if body.Enabled != nil {
		c.Enabled = *body.Enabled
	}
	if body.URL != nil {
		c.URL = strings.TrimSpace(*body.URL)
	}
	if body.EventTypes != nil {
		c.EventTypes = *body.EventTypes
	}
	if body.AllowPrivate != nil {
		c.AllowPrivate = *body.AllowPrivate
	}
	if body.TimeoutMS != nil {
		c.TimeoutMS = *body.TimeoutMS
	}
	if body.MaxAttempts != nil {
		c.MaxAttempts = *body.MaxAttempts
	}
	if body.MaxQueue != nil {
		c.MaxQueue = *body.MaxQueue
	}
	if body.Secret != nil {
		c.SecretSet = true
	}
	if c.Enabled && !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before enabling or changing webhook delivery")
		return
	}
	if err := webhook.ValidateConfig(c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ciphertext []byte
	var keyID, hint string
	if body.Secret != nil {
		if len(*body.Secret) < 32 || len(*body.Secret) > 4096 {
			writeError(w, http.StatusBadRequest, "signing secret must contain between 32 and 4096 characters")
			return
		}
		if strings.Contains(c.URL, *body.Secret) {
			writeError(w, http.StatusBadRequest, "the signing secret must not appear in the URL")
			return
		}
		if !a.canSealSecrets() {
			writeError(w, http.StatusServiceUnavailable, a.sealUnavailableReason())
			return
		}
		ciphertext, err = a.Intel.Keyring.Seal([]byte(*body.Secret), webhook.SecretIdentity)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "webhook signing secret could not be encrypted")
			return
		}
		keyID = a.Intel.Keyring.KeyID()
		hint = secrets.Hint(*body.Secret)
	}
	if err := a.Store.SaveWebhookConfig(r.Context(), c, ciphertext, keyID, hint, body.Secret != nil); err != nil {
		writeError(w, http.StatusConflict, "webhook configuration could not be saved; reload and retry")
		return
	}
	a.Webhooks.Reload()
	a.handleGetWebhook(w, r)
}

func (a *API) handleDeleteWebhookSecret(w http.ResponseWriter, r *http.Request) {
	if !a.webhookAvailable(w) {
		return
	}
	c, err := a.Store.GetWebhookConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webhook configuration could not be read")
		return
	}
	c.Enabled = false
	if err := a.Store.SaveWebhookConfig(r.Context(), c, nil, "", "", true); err != nil {
		writeError(w, http.StatusConflict, "webhook configuration could not be saved; reload and retry")
		return
	}
	a.Webhooks.Reload()
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	if !a.webhookAvailable(w) {
		return
	}
	var body struct {
		Consent bool `json:"consent"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if !body.Consent {
		writeError(w, http.StatusBadRequest, "consent is required before sending a synthetic webhook test")
		return
	}
	writeJSON(w, http.StatusOK, a.Webhooks.Test(r.Context()))
}
