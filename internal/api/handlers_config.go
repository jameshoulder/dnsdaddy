package api

import (
	"net/http"
	"net/url"

	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/clientacl"
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

	acl := a.ClientACL.Current()

	type row struct {
		store.Network
		Queries24h int64  `json:"queries24h"`
		Blocked24h int64  `json:"blocked24h"`
		Status     string `json:"status"`

		// PublicCIDRs are this network's ranges that are reachable from the
		// internet, so the dashboard can mark them without re-implementing
		// the classification the server enforces.
		PublicCIDRs []string `json:"publicCidrs"`
		// CanResolve is whether this network's clients can actually reach the
		// resolver right now, by any route. It is not the same field as
		// allowResolver: a network inside a broader permitted range resolves
		// without a permission of its own, and one whose permission has not
		// been reloaded would show the reverse.
		CanResolve bool `json:"canResolve"`
		// ResolvesVia names the wider range responsible when CanResolve is
		// true but allowResolver is false. Empty otherwise.
		ResolvesVia string `json:"resolvesVia,omitempty"`
	}

	shadows := map[string]string{}
	for _, sh := range acl.Shadowed() {
		shadows[sh.NetworkID] = sh.CoveredBy + " (" + sh.Source + ")"
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

		r := row{
			Network:     n,
			Queries24h:  act.Queries,
			Blocked24h:  act.Blocked,
			Status:      status,
			PublicCIDRs: []string{},
			ResolvesVia: shadows[n.ID],
		}
		for _, raw := range n.CIDRs {
			if p, err := clientacl.ParsePrefix(raw); err == nil && clientacl.PrefixIsPublic(p) {
				r.PublicCIDRs = append(r.PublicCIDRs, p.String())
			}
		}
		r.CanResolve = networkCanResolve(acl, n)
		out = append(out, r)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"networks": out,
		"clientAccess": map[string]any{
			"unrestricted":        acl.Unrestricted(),
			"allowPublicResolver": acl.AllowPublicResolver(),
			"bootstrapCidrs":      acl.Bootstrap(),
			"effectiveCidrs":      acl.Effective(),
		},
	})
}

// networkCanResolve reports whether every one of a network's ranges is
// admitted by the live ACL.
//
// Every range, not any: a network half of whose addresses are refused is not
// working, and reporting it green would recreate in the dashboard exactly the
// misleading health this whole line of work exists to remove.
func networkCanResolve(acl *clientacl.Set, n store.Network) bool {
	if !n.Enabled {
		return false
	}
	if acl.Unrestricted() {
		return true
	}
	if len(n.CIDRs) == 0 {
		// The catch-all has no range of its own; whether its clients are
		// admitted depends entirely on where they arrive from.
		return true
	}
	for _, raw := range n.CIDRs {
		p, err := clientacl.ParsePrefix(raw)
		if err != nil {
			return false
		}
		// Whole-prefix coverage, and the same calculation the diagnostics use.
		// Sampling the base address was wrong in a way that mattered: a
		// network of 10.0.0.0/8 against an ACL of 10.0.0.0/16 starts at a
		// permitted address while almost every client in it is refused, and
		// this column would have reported it green.
		if acl.Cover(p) != clientacl.CoverFull {
			return false
		}
	}
	return true
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

	// AllowResolver permits this network's addresses to query the resolver.
	// Omitted leaves the stored value alone, so a client that updates a name
	// cannot silently revoke access it never mentioned.
	AllowResolver *bool `json:"allowResolver"`

	// PublicAck affirms, in this request, that the publicly routable ranges
	// it results in may reach the resolver. Without it the write is refused
	// with 409 and the ranges in question.
	PublicAck *bool `json:"publicAck"`
}

func (b networkBody) toInput() store.NetworkInput {
	return store.NetworkInput{
		Name:          b.Name,
		Location:      b.Location,
		PolicyID:      b.PolicyID,
		CIDRs:         b.CIDRs,
		Enabled:       b.Enabled,
		AllowResolver: b.AllowResolver,
		PublicAck:     b.PublicAck,
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
	// Judged on what was actually stored, not on the request. A network
	// created unpermitted — the default — changes nothing about who is
	// admitted, and neither does a permitted one whose ranges the ACL already
	// covers, so a failed reload after either must not raise the standing "a
	// revocation may still be honoured" warning.
	_, warning := a.reloadNetworkAccess(r, n, false)
	writeNetwork(w, http.StatusCreated, n, warning)
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
	// n is the merged row the store committed, so this compares the ACL in
	// force against the result of the write rather than guessing from which
	// fields the request happened to mention.
	_, warning := a.reloadNetworkAccess(r, n, false)
	writeNetwork(w, http.StatusOK, n, warning)
}

func (a *API) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	// DeleteNetwork reads the row inside the transaction that removes it, so
	// what comes back is what was deleted rather than what happened to be
	// stored a moment earlier. A missing network is still reported by the
	// store, so the 404 stays where it was.
	deleted, err := a.Store.DeleteNetwork(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)

	// Deleting a network that permitted something is the worst of the three
	// failure cases: the permission is still being honoured and the row that
	// would have shown it is gone. Answering 204 and dropping the warning told
	// the caller the revocation had taken effect, which is a security-relevant
	// false success. So that case answers 200 with the warning, and the
	// controller records it too, so `dnsdaddy doctor` and /api/v1/diagnostics
	// keep reporting it until a reload succeeds — a warning in one HTTP
	// response is easy to miss, and this outlives the request that caused it.
	//
	// 200 is reserved for the meaning it was introduced for: client access may
	// not be in force. A deletion that provably cannot change who is admitted
	// — an unpermitted network, or one whose ranges the bootstrap list or
	// another permitted network still covers — stays 204, vacuously in force,
	// with the reload failure still logged. Widening 200 to cover a failure
	// that affects nobody would train the one caller who checks for it to stop
	// checking, which costs more than the notice is worth.
	affects, warning := a.reloadNetworkAccess(r, deleted, true)
	if affects && warning != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "deleted",
			"warning": warning,
		})
		return
	}
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
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Categories  *[]string `json:"categories"`
	BlockMode   *string   `json:"blockMode"`

	// Deprecated: stored but not enforced. See store.Policy.SafeSearch.
	SafeSearch *bool `json:"safeSearch"`

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
	loads := a.Feeds.FeedLoads()

	type row struct {
		store.Feed
		// IndexedDomains is what this feed contributes after de-duplication
		// against higher-priority feeds — usually lower than DomainCount, and
		// the number that actually matters.
		IndexedDomains int `json:"indexedDomains"`
		// Loaded reports whether this feed's cached copy is in the index that
		// is answering queries right now.
		//
		// This is the only field that can say whether a feed is protecting
		// anybody. lastSuccessAt records that a download once succeeded; it
		// cannot know that the file it produced later went missing or was
		// damaged, and a feed in that state is skipped at every rebuild while
		// the row still shows a healthy refresh. Anything that reports
		// protection reads this.
		Loaded bool `json:"loaded"`
		// LoadError says why the cached copy could not be used, when it could
		// not. Empty otherwise.
		LoadError string `json:"loadError"`
	}
	out := make([]row, 0, len(feeds))
	for _, f := range feeds {
		load := loads[f.ID]
		out = append(out, row{
			Feed:           f,
			IndexedDomains: indexed[f.ID],
			Loaded:         load.Loaded,
			LoadError:      load.Error,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"feeds":               out,
		"refreshing":          a.Feeds.Refreshing(),
		"totalIndexedDomains": a.Lists.Load().Len(),
		// Which of these rows is the Threat Observatory. The dashboard gives
		// it a dedicated activation card, and naming the ID here keeps the
		// catalog the single source of truth rather than hardcoding the slug
		// in JavaScript where nothing would notice it drifting.
		"observatoryFeedId": catalog.ObservatoryFeedID,
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
	// Read first, so the reindex below can be skipped when the request does
	// not actually change whether this feed contributes to the index.
	before, err := a.Store.GetFeed(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	f, err := a.Store.UpdateFeed(r.Context(), r.PathValue("id"), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if f.Enabled != before.Enabled {
		a.reindexFromCache(r)
	}
	writeJSON(w, http.StatusOK, f)
}

// reindexFromCache rebuilds the blocklist index from the cached feed files
// after a feed was switched on or off.
//
// Without this, disabling a feed does nothing to traffic until the next
// scheduled refresh — up to twelve hours of a feed the operator has just
// turned off still blocking domains. The rebuild is local: it reads the same
// cache directory a restart reads and touches no network, so a feed that has
// a cached copy starts contributing the moment it is enabled, and one that
// does not is simply skipped, exactly as at boot.
//
// It runs in the background because a rebuild over a few hundred thousand
// domains takes a second or two, and the write itself has already succeeded.
func (a *API) reindexFromCache(r *http.Request) {
	parent := r.Context()
	go func() {
		ctx, cancel := detachedContext(parent)
		defer cancel()
		if err := a.Feeds.LoadFromCache(ctx); err != nil {
			a.Log.Error("rebuild index after feed change", "error", err)
		}
	}()
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
	//
	// r must not be touched once this handler has returned, so the parent is
	// read here rather than inside the goroutine; detachedContext strips its
	// cancellation so the refresh outlives the response.
	parent := r.Context()
	go func() {
		ctx, cancel := detachedContext(parent)
		defer cancel()
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

// handleRefreshFeed refreshes a single feed rather than all of them.
//
// Enabling a feed and then waiting up to twelve hours for the scheduler, or
// several minutes for a full refresh of every third-party list, is the wrong
// answer to "did that work?". This runs the same download, validation, cache
// and index-rebuild path as a full refresh, scoped to one feed, so the answer
// arrives in seconds.
func (a *API) handleRefreshFeed(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, err := a.Store.GetFeed(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !f.Enabled {
		writeError(w, http.StatusConflict, "feed is disabled; enable it before refreshing")
		return
	}

	// The slot is claimed here, synchronously, so that a dashboard polling the
	// moment this response lands already sees refreshing = true.
	run, err := a.Feeds.BeginRefreshFeed(id)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	// As with a full refresh: r must not be touched once this handler returns,
	// so the parent context is read here and detached from the response.
	parent := r.Context()
	go func() {
		ctx, cancel := detachedContext(parent)
		defer cancel()
		if err := run(ctx); err != nil {
			a.Log.Warn("feed refresh failed", "feed", id, "error", err)
			return
		}
		a.Log.Info("feed refreshed", "feed", id, "domains", a.Lists.Load().Len())
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "refreshing", "feed": id})
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

// reloadNetworkAccess republishes the effective client ACL after a network
// write and returns a warning to hand back to the caller if it could not.
//
// Unlike a policy reload, a failure here is not merely late: it means a
// permission the operator just revoked is still being honoured, or one they
// just granted is not. The write is already committed, so failing the request
// would invite a retry that creates a second network — hence a successful
// response carrying an explicit warning rather than a 500. The condition also
// shows up in `dnsdaddy doctor` and at /api/v1/diagnostics, where the
// effective ACL is what is reported.
//
// removed marks a deletion, whose contribution is taken from the row the
// removing transaction returned rather than from the snapshot.
//
// The returned bool says whether the write could have changed who is admitted.
// The controller decides it under the same lock as the publish, so a
// concurrent reload cannot slip a snapshot in between the two: deciding it out
// here from Current() let a PATCH that had read a newly permitted network but
// not yet published it leave a DELETE of that network concluding it withdrew
// nothing. A rename, or a grant the ACL already covers, leaves the enforced
// ACL correct in every respect that matters, so it is reported to the caller
// but does not raise the standing warning that a revocation may not have taken.
func (a *API) reloadNetworkAccess(r *http.Request, n store.Network, removed bool) (bool, string) {
	if a.ClientACL == nil {
		return false, ""
	}

	var (
		affected bool
		err      error
	)
	if removed {
		affected, err = a.ClientACL.ReloadAfterDelete(r.Context(), store.ClientACLNetwork(n))
	} else {
		affected, err = a.ClientACL.ReloadAfterWrite(r.Context(), store.ClientACLNetwork(n))
	}
	if err == nil {
		return affected, ""
	}

	a.Log.Error("reload client access", "error", err, "affects_access", affected)
	if !affected {
		return false, "Saved, but the change could not be applied to the running resolver. Nothing " +
			"about who may use it has changed, so no client is affected; the label will " +
			"catch up on the next change."
	}
	// The controller records the failure too, so the diagnostics keep
	// reporting it after this response has been closed and forgotten.
	return true, "Saved, but the resolver's client access could not be reloaded, so this change is " +
		"not yet in force. Retry the change, or restart DNS Daddy."
}

// writeNetwork answers a network write, attaching a warning when the change is
// stored but not yet enforced.
func writeNetwork(w http.ResponseWriter, status int, n store.Network, warning string) {
	if warning == "" {
		writeJSON(w, status, n)
		return
	}
	writeJSON(w, status, struct {
		store.Network
		Warning string `json:"warning"`
	}{Network: n, Warning: warning})
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
