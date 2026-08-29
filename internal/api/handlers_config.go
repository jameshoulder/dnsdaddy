package api

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

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
		// Coverage is how much of this network the effective ACL admits right
		// now: "full", "partial" or "none". It is a question about addresses,
		// not about this row — a network inside a broader permitted range is
		// covered without a permission of its own, and a permission that has
		// not been reloaded is not covered despite one.
		//
		// Three states rather than a boolean because the middle one is real
		// and was being reported as the worst one: a 10.0.0.0/8 network
		// against a permitted 10.0.0.0/16 has its first 65k addresses served
		// and the rest refused, and calling that "refused" hides a working
		// half while calling it "allowed" hides a broken one.
		Coverage string `json:"coverage"`
		// ResolvesVia names the wider range or ranges responsible when the
		// network is fully covered without a permission of its own — plural,
		// because two of its CIDRs can be covered by two different grants.
		// Empty otherwise, which includes the case where nothing is refused at
		// all: an unrestricted ACL has no grants to name.
		ResolvesVia string `json:"resolvesVia,omitempty"`
	}

	// Every range responsible, not the last one seen. Shadowed() reports one
	// entry per covered CIDR, so a network with two ranges covered by two
	// different grants produced two entries and this kept whichever came last
	// — and the row then named one range as covering a network of which it
	// covers half.
	// Keyed by the range as well as the network, so an explanation can only be
	// attached to a range the row still has.
	//
	// The snapshot and the database are two different points in time — the
	// snapshot is what the resolver is enforcing, the row is what is stored —
	// and after a failed reload they disagree. Matching on the network alone
	// let a covering range for a CIDR the operator had just replaced be
	// reported against the CIDR that replaced it, so a 192.168.0.0/24 row
	// could be described as reachable inside 10.0.0.0/8.
	shadows := map[string]map[string]string{}
	for _, sh := range acl.Shadowed() {
		if shadows[sh.NetworkID] == nil {
			shadows[sh.NetworkID] = map[string]string{}
		}
		shadows[sh.NetworkID][sh.CIDR] = sh.CoveredBy + " (" + sh.Source + ")"
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
		}
		for _, raw := range n.CIDRs {
			if p, err := clientacl.ParsePrefix(raw); err == nil && clientacl.PrefixIsPublic(p) {
				r.PublicCIDRs = append(r.PublicCIDRs, p.String())
			}
		}
		// Empty for every private network, which is the common case. See
		// nonNilSlice: the dashboard should not have to guard a documented array.
		r.PublicCIDRs = nonNilSlice(r.PublicCIDRs)
		r.Coverage = networkCoverage(acl, n)
		// Only when the whole row is covered. Shadowed() reports a shadowed
		// *range*, so a network with two CIDRs of which one sits inside a wider
		// grant produced an entry — and the badge, which reads resolvesVia
		// before it reads coverage, then described a network with a refused
		// half as reachable through that wider range.
		if r.Coverage == coverageFull {
			var via []string
			for _, raw := range n.CIDRs {
				p, err := clientacl.ParsePrefix(raw)
				if err != nil {
					continue
				}
				v, ok := shadows[n.ID][p.String()]
				if ok && !slices.Contains(via, v) {
					via = append(via, v)
				}
			}
			r.ResolvesVia = strings.Join(via, ", ")
		}
		out = append(out, r)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"networks": out,
		"clientAccess": map[string]any{
			"unrestricted":        acl.Unrestricted(),
			"allowPublicResolver": acl.AllowPublicResolver(),
			"bootstrapCidrs":      acl.Bootstrap(),
			"effectiveCidrs":      acl.Effective(),
			// Computed from the grants rather than left to the client to
			// subtract one list from another: a range that is both permitted
			// in the dashboard and listed in configuration survives that
			// subtraction as nothing, and the network that permitted it would
			// be shown as contributing no ranges.
			"dashboardCidrs": acl.GrantedPrefixes(),
		},
	})
}

// networkCoverage reports how much of a network the effective ACL admits.
//
// It asks only about addresses. Whether the row is enabled, and whether it
// carries a permission of its own, decide what it *contributes* to the ACL —
// they do not decide what the ACL admits, because the ACL is a union with no
// deny rules. Disabling a network stops it granting anything and stops its
// policy applying; it does not refuse its addresses, and reporting that it
// does told operators a working range was being turned away.
//
// Partial is its own answer rather than a rounding of "not full". A network of
// 10.0.0.0/8 against a permitted 10.0.0.0/16 has 65k addresses served and the
// rest refused — the state that looks like intermittent breakage, and the one
// most worth naming.
func networkCoverage(acl *clientacl.Set, n store.Network) string {
	if acl.Unrestricted() {
		return coverageFull
	}
	if len(n.CIDRs) == 0 {
		// The catch-all has no ranges of its own, so there is nothing to
		// cover: whether its clients are admitted depends on where each one
		// arrives from.
		return coverageFull
	}

	// Tracked as two facts rather than as a minimum. Taking the least-covered
	// range calls a network with one fully permitted CIDR and one permitted by
	// nothing "none", and the badge then reports the whole thing refused while
	// half its clients are being served. What matters is whether any address
	// is admitted and whether any is refused, which are independent.
	anyAdmitted, anyRefused := false, false
	for _, raw := range n.CIDRs {
		p, err := clientacl.ParsePrefix(raw)
		if err != nil {
			// An unparseable range permits nothing, so it refuses this part of
			// the network without saying anything about the rest.
			anyRefused = true
			continue
		}
		// The same whole-prefix calculation the diagnostics use. Sampling the
		// base address was wrong in a way that mattered: a network of
		// 10.0.0.0/8 against an ACL of 10.0.0.0/16 starts at a permitted
		// address while almost every client in it is refused.
		switch acl.Cover(p) {
		case clientacl.CoverFull:
			anyAdmitted = true
		case clientacl.CoverPartial:
			anyAdmitted, anyRefused = true, true
		default:
			anyRefused = true
		}
	}
	switch {
	case anyAdmitted && anyRefused:
		return coveragePartial
	case anyAdmitted:
		return coverageFull
	default:
		return coverageNone
	}
}

const (
	coverageFull    = "full"
	coveragePartial = "partial"
	coverageNone    = "none"
)

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
	// Held across the commit and the reload: see API.networkWrites.
	a.networkWrites.Lock()
	defer a.networkWrites.Unlock()

	n, err := a.Store.CreateNetwork(r.Context(), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	writeNetwork(w, http.StatusCreated, n, a.reloadNetworkAccess(r))
}

func (a *API) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	var body networkBody
	if !decodeBody(w, r, &body) {
		return
	}
	a.networkWrites.Lock()
	defer a.networkWrites.Unlock()

	n, err := a.Store.UpdateNetwork(r.Context(), r.PathValue("id"), body.toInput())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)
	writeNetwork(w, http.StatusOK, n, a.reloadNetworkAccess(r))
}

func (a *API) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	a.networkWrites.Lock()
	defer a.networkWrites.Unlock()

	// DeleteNetwork removes the row inside a transaction that reads it first,
	// so the count check and the delete cannot disagree about what is there.
	if _, err := a.Store.DeleteNetwork(r.Context(), r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	a.reloadEngine(r)

	// Deletion is the failure case that matters most: whatever the network
	// permitted may still be honoured, and the row that would have shown it is
	// gone. Answering 204 and dropping the warning tells the caller the
	// revocation took effect, which is a security-relevant false success — so
	// a failed reload answers 200 with the warning instead. The controller
	// records it too, so `dnsdaddy doctor` and /api/v1/diagnostics keep
	// reporting it until a reload succeeds: a warning in one HTTP response is
	// easy to miss, and this outlives the request that caused it.
	warning := a.reloadNetworkAccess(r)
	if warning != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "deleted",
			"warning": warning,
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	// A rotation cannot change who is admitted — a token identifies a DoH or
	// DoT client by credential, not by source address — so it needs no ACL
	// reload. It takes the lock anyway, so that "every handler that writes a
	// network is serialised" holds without a reader having to work out which
	// columns decide admission.
	a.networkWrites.Lock()
	defer a.networkWrites.Unlock()

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
// permission the operator just revoked may still be honoured, or one they just
// granted may not be working. The write is already committed, so failing the
// request would invite a retry that creates a second network — hence a
// successful response carrying an explicit warning rather than a 500.
//
// The warning says what is known and no more. Earlier versions decided from
// the write whether client access could have changed, and said either "this is
// not yet in force" or "no client is affected"; both claims turned out to be
// unsupportable, because working out which one applies needs the reading of
// the stored state that has just failed. The condition also outlives this
// response, on the controller, so `dnsdaddy doctor` and /api/v1/diagnostics
// keep reporting it until a reload succeeds.
func (a *API) reloadNetworkAccess(r *http.Request) string {
	if a.ClientACL == nil {
		return ""
	}
	if err := a.ClientACL.Reload(r.Context()); err != nil {
		a.Log.Error("reload client access", "error", err)
		return "Saved, but DNS Daddy could not re-read its configuration, so it cannot confirm " +
			"that the client access it is enforcing matches what is stored. Retry the change, " +
			"or restart DNS Daddy."
	}
	return ""
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
