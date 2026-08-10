package api

import (
	"net/http"
	"net/url"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// --- networks --------------------------------------------------------------

func (a *API) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := a.Store.ListNetworks(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	activity, err := a.Store.NetworkActivitySince(r.Context(), timeNowMinus24h())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type row struct {
		store.Network
		Queries24h int64  `json:"queries24h"`
		Blocked24h int64  `json:"blocked24h"`
		Status     string `json:"status"`
	}

	out := make([]row, 0, len(networks))
	for _, n := range networks {
		act := activity[n.ID]
		status := "healthy"
		switch {
		case !n.Enabled:
			status = "disabled"
		case act.Queries == 0:
			// Not an error — a freshly added network legitimately has no
			// traffic yet — but it is the single most common sign that
			// somebody's firewall change did not take.
			status = "no-traffic"
		}
		out = append(out, row{
			Network:    n,
			Queries24h: act.Queries,
			Blocked24h: act.Blocked,
			Status:     status,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"networks": out})
}

func (a *API) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.GetNetwork(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

type networkBody struct {
	Name     *string   `json:"name"`
	Location *string   `json:"location"`
	PolicyID *string   `json:"policyId"`
	CIDRs    *[]string `json:"cidrs"`
	Enabled  *bool     `json:"enabled"`
}

func (b networkBody) toInput() store.NetworkInput {
	return store.NetworkInput{
		Name:     b.Name,
		Location: b.Location,
		PolicyID: b.PolicyID,
		CIDRs:    b.CIDRs,
		Enabled:  b.Enabled,
	}
}

func (a *API) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var body networkBody
	if !decodeBody(w, r, &body) {
		return
	}
	n, err := a.Store.CreateNetwork(r.Context(), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	writeJSON(w, http.StatusCreated, n)
}

func (a *API) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	var body networkBody
	if !decodeBody(w, r, &body) {
		return
	}
	n, err := a.Store.UpdateNetwork(r.Context(), r.PathValue("id"), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	writeJSON(w, http.StatusOK, n)
}

func (a *API) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteNetwork(r.Context(), r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.RotateNetworkToken(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	writeJSON(w, http.StatusOK, n)
}

// --- policies --------------------------------------------------------------

func (a *API) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := a.Store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

func (a *API) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := a.Store.GetPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type policyBody struct {
	Name         *string   `json:"name"`
	Description  *string   `json:"description"`
	Categories   *[]string `json:"categories"`
	BlockMode    *string   `json:"blockMode"`
	SafeSearch   *bool     `json:"safeSearch"`
	LogQueries   *bool     `json:"logQueries"`
	AllowDomains *[]string `json:"allowDomains"`
	BlockDomains *[]string `json:"blockDomains"`
}

func (b policyBody) toInput() store.PolicyInput {
	in := store.PolicyInput{
		Name:         b.Name,
		Description:  b.Description,
		Categories:   b.Categories,
		SafeSearch:   b.SafeSearch,
		LogQueries:   b.LogQueries,
		AllowDomains: b.AllowDomains,
		BlockDomains: b.BlockDomains,
	}
	if b.BlockMode != nil {
		m := store.BlockMode(*b.BlockMode)
		in.BlockMode = &m
	}
	return in
}

func (a *API) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var body policyBody
	if !decodeBody(w, r, &body) {
		return
	}
	p, err := a.Store.CreatePolicy(r.Context(), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	writeJSON(w, http.StatusCreated, p)
}

func (a *API) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var body policyBody
	if !decodeBody(w, r, &body) {
		return
	}
	p, err := a.Store.UpdatePolicy(r.Context(), r.PathValue("id"), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	// A policy change can flip a name from blocked to allowed. Purging the
	// cache makes that take effect on the next query rather than after a TTL,
	// which is what someone unblocking a supplier's website at 4pm expects.
	a.Resolver.Cache().Purge()
	writeJSON(w, http.StatusOK, p)
}

func (a *API) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeletePolicy(r.Context(), r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	w.WriteHeader(http.StatusNoContent)
}

type ruleBody struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Note   string `json:"note"`
}

func (a *API) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var body ruleBody
	if !decodeBody(w, r, &body) {
		return
	}
	if err := a.Store.AddPolicyRule(r.Context(), r.PathValue("id"), body.Kind, body.Domain, body.Note); err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	a.Resolver.Cache().Purge()

	p, err := a.Store.GetPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (a *API) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	domain, err := url.PathUnescape(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid domain in path")
		return
	}
	if err := a.Store.DeletePolicyRule(r.Context(), r.PathValue("id"), r.PathValue("kind"), domain); err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	a.Resolver.Cache().Purge()
	w.WriteHeader(http.StatusNoContent)
}

// --- feeds -----------------------------------------------------------------

func (a *API) handleListFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := a.Store.ListFeeds(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	indexed := a.Lists.Load().CountsByFeed()

	type row struct {
		store.Feed
		// IndexedDomains is what this feed contributes after de-duplication
		// against higher-priority feeds — usually lower than DomainCount, and
		// the number that actually matters.
		IndexedDomains int `json:"indexedDomains"`
	}
	out := make([]row, 0, len(feeds))
	for _, f := range feeds {
		out = append(out, row{Feed: f, IndexedDomains: indexed[f.ID]})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"feeds":               out,
		"refreshing":          a.Feeds.Refreshing(),
		"totalIndexedDomains": a.Lists.Load().Len(),
	})
}

type feedBody struct {
	Name     *string `json:"name"`
	URL      *string `json:"url"`
	Category *string `json:"category"`
	Format   *string `json:"format"`
	Enabled  *bool   `json:"enabled"`
}

func (b feedBody) toInput() store.FeedInput {
	return store.FeedInput{
		Name:     b.Name,
		URL:      b.URL,
		Category: b.Category,
		Format:   b.Format,
		Enabled:  b.Enabled,
	}
}

func (a *API) handleCreateFeed(w http.ResponseWriter, r *http.Request) {
	var body feedBody
	if !decodeBody(w, r, &body) {
		return
	}
	f, err := a.Store.CreateFeed(r.Context(), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, f)
}

func (a *API) handleUpdateFeed(w http.ResponseWriter, r *http.Request) {
	var body feedBody
	if !decodeBody(w, r, &body) {
		return
	}
	f, err := a.Store.UpdateFeed(r.Context(), r.PathValue("id"), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (a *API) handleDeleteFeed(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteFeed(r.Context(), r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleRefreshFeeds(w http.ResponseWriter, r *http.Request) {
	if a.Feeds.Refreshing() {
		writeError(w, http.StatusConflict, "a feed refresh is already running")
		return
	}
	// Downloading every feed takes longer than a browser will wait, so run it
	// in the background and let the dashboard poll the feeds endpoint.
	go func() {
		ctx := detachedContext()
		if err := a.Feeds.Refresh(ctx); err != nil {
			a.Log.Error("manual feed refresh failed", "error", err)
			return
		}
		// New blocklist contents invalidate cached answers via the generation
		// counter, so there is nothing else to do here.
		a.Log.Info("manual feed refresh complete", "domains", a.Lists.Load().Len())
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "refreshing"})
}

// --- clients ---------------------------------------------------------------

func (a *API) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := a.Store.ListClients(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if clients == nil {
		clients = []store.Client{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (a *API) handleSetClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if err := a.Store.SetClientName(r.Context(), body.IP, body.Name); err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	w.WriteHeader(http.StatusNoContent)
}

// --- API tokens ------------------------------------------------------------

func (a *API) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := a.Store.ListAPITokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tokens == nil {
		tokens = []store.APIToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (a *API) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	t, err := a.Store.CreateAPIToken(r.Context(), body.Name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// t.Secret is populated exactly once, here.
	writeJSON(w, http.StatusCreated, t)
}

func (a *API) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteAPIToken(r.Context(), r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- auth ------------------------------------------------------------------

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	key := clientKey(r)
	if !a.Auth.limiter.allow(key) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}
	if !a.Auth.CheckPassword(r.Context(), body.Password) {
		writeError(w, http.StatusUnauthorized, "incorrect password")
		return
	}

	a.Auth.limiter.reset(key)
	a.Auth.SetSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.Auth.ClearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

func (a *API) handleSession(w http.ResponseWriter, r *http.Request) {
	p, ok := a.Auth.authenticate(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": ok,
		"principal":     p.label,
	})
}

func (a *API) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if err := a.Auth.SetPassword(r.Context(), body.CurrentPassword, body.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

// --- helpers ---------------------------------------------------------------

// reloadEngine refreshes the policy engine's compiled snapshot after a write.
// A failure here is logged rather than returned: the write itself succeeded,
// and the next reload or restart will pick it up.
func (a *API) reloadEngine(r *http.Request) {
	if err := a.Engine.Reload(r.Context()); err != nil {
		a.Log.Error("reload policy engine", "error", err)
	}
}

func (a *API) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=300")
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// A static YAML document compiled into the binary by go:embed. There is
	// no request-derived data in it at all, so there is nothing to escape.
	if _, err := w.Write(openAPISpec); err != nil {
		a.Log.Debug("write openapi spec", "error", err)
	}
}
