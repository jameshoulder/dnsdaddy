// Package policy decides what happens to a DNS question: which network the
// client belongs to, which policy that network carries, and whether the name
// should be answered or blocked.
//
// The engine keeps a compiled snapshot of every network and policy in memory
// and swaps it atomically when configuration changes, so the DNS hot path does
// no database work and never blocks on a write.
package policy

import (
	"context"
	"net/netip"
	"sort"
	"sync/atomic"

	"github.com/jameshoulder/dnsdaddy/internal/blocklist"
	"github.com/jameshoulder/dnsdaddy/internal/catalog"
	"github.com/jameshoulder/dnsdaddy/internal/domainutil"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Decision is the outcome of evaluating a question against a policy.
type Decision struct {
	Blocked bool
	// Reason is written to the query log in plain English, because the person
	// reading it is often relaying it to a user over the phone.
	Reason    string
	Category  string
	Source    string
	BlockMode store.BlockMode
	LogQuery  bool

	// Basis is the machine-readable form of why, for the decision record.
	// Nil for an ordinary allowed query.
	//
	// A pointer, not a value, and the benchmark is the reason. Decision is
	// returned by value on every query; carrying seven inline strings made it
	// 112 bytes larger to zero and copy, which measured as roughly 80ns → 90ns
	// on the miss path — a 12% regression on the one function every lookup
	// runs. As a pointer the miss path is unchanged and a decided query pays
	// one small allocation, on a path that already allocates a response.
	Basis *Basis
}

// Rule names which step of Evaluate reached the verdict.
//
// It exists because "Blocked by your custom block-list" is prose written for a
// person on the phone, and prose is a poor thing to key an explanation on. The
// rule is the stable identifier; the reason stays the sentence.
type Rule string

const (
	// RuleNone means no rule matched — an ordinary allowed query.
	RuleNone Rule = ""
	// RuleAllowList is the operator's own allow-list, which short-circuits
	// everything below it.
	RuleAllowList Rule = "allow_list"
	// RuleBlockList is the operator's own block-list.
	RuleBlockList Rule = "block_list"
	// RuleCategory is a match in the blocklist index, from a feed.
	RuleCategory Rule = "category"
	// RuleReputation is an external provider's verdict.
	RuleReputation Rule = "reputation"
)

// Basis is what decided, in machine terms, so the decision can be explained
// later from stored facts rather than re-derived from feeds that have since
// refreshed.
//
// Every field is a string already held by the compiled snapshot or the
// blocklist entry, so populating it copies pointers and lengths and allocates
// nothing. That is the reason it is a value on Decision rather than a pointer
// to something built on the hot path: an allowed query pays for a few nil
// string headers and no more.
//
// It is deliberately not evidence. Turning this into evidence rows happens off
// the resolution path, in internal/decisions.
type Basis struct {
	Rule Rule
	// PolicyID and PolicyName are the policy that was in force.
	PolicyID   string
	PolicyName string
	// FeedID and FeedName are set for RuleCategory: which list claimed the
	// domain. The ID matters because a feed can be renamed and an explanation
	// must still be able to point at the row.
	FeedID   string
	FeedName string
	// ProviderName is set for RuleReputation.
	ProviderName string
	// Category is the security category the rule assigned, where it assigned
	// one.
	Category string
}

// Decided reports whether any rule fired. An ordinary allowed query has no
// basis and nothing to record.
//
// A nil receiver is the common case and answers false, so callers do not need
// their own nil check before asking.
func (b *Basis) Decided() bool { return b != nil && b.Rule != RuleNone }

// Match identifies the network and policy a client resolved to.
type Match struct {
	NetworkID   string
	NetworkName string
	PolicyID    string
	PolicyName  string
}

// compiledPolicy is the query-time form of a store.Policy.
type compiledPolicy struct {
	id         string
	name       string
	categories map[string]bool
	allow      map[string]bool
	block      map[string]bool
	blockMode  store.BlockMode
	logQueries bool
}

// compiledNetwork pairs a network with its parsed CIDRs.
type compiledNetwork struct {
	id       string
	name     string
	policyID string
	prefixes []netip.Prefix
	enabled  bool
	// maxBits is the longest prefix length across this network's CIDRs.
	//
	// It orders snapshot.networks and nothing else. It used to decide
	// attribution, and that was the defect route fixes: a network is not a
	// prefix, and ranking whole networks by their narrowest CIDR let an
	// unrelated /32 promote a /8 over the /16 that actually contained the
	// client. Attribution now walks snapshot.routes, one entry per CIDR.
	maxBits int
}

// route is one CIDR of one enabled network: the unit longest-prefix matching
// works on.
//
// A client is attributed to the most specific prefix that contains it, and
// "most specific" is a property of a prefix rather than of a network. Two
// networks can each hold several CIDRs of different lengths, so the ranking has
// to happen per CIDR or it is not longest-prefix matching at all.
type route struct {
	prefix  netip.Prefix
	network *compiledNetwork
}

type snapshot struct {
	networks []compiledNetwork
	// routes is every CIDR of every enabled network, most specific first,
	// with a deterministic order among equal lengths. See sortRoutes.
	routes   []route
	policies map[string]*compiledPolicy
	// fallback is the network used for clients matching no CIDR.
	fallback      *compiledNetwork
	clients       map[string]string // IP -> friendly name
	defaultPolicy *compiledPolicy
}

// Reputation is the external-intelligence consultant, when one is configured.
//
// An interface rather than a concrete type so this package does not import
// internal/apiprovider: policy is the thing DNS resolution depends on, and it
// should not grow a dependency on HTTP clients, circuit breakers and provider
// registries to ask one question.
//
// Consult returns (verdict, true) only when a provider actually answered.
// Anything else — no providers, a cache miss, a failure, a timeout — is
// (unknown, false) and changes nothing.
type Reputation interface {
	Consult(ctx context.Context, policyID, domain string) (ReputationVerdict, bool)
}

// ReputationVerdict is what a provider concluded, in the terms this package
// needs. Deliberately smaller than apiprovider.Verdict: the policy engine has
// no use for a raw excerpt or a TTL, and a narrower type is a narrower
// coupling.
type ReputationVerdict struct {
	// Malicious is the only field that can change a decision. A score without
	// it is telemetry.
	Malicious bool
	Score     float64
	Category  string
	// ProviderName is written into the block reason, because an operator
	// looking at a blocked query needs to know which third party decided it.
	ProviderName string
}

// CachedReputation is the read-only face of a Reputation: what it already
// knows, without asking anyone.
//
// Optional. A consultant that implements it lets the policy preview say what
// an external provider has on file for a name without causing a lookup. One
// that does not is treated as having nothing on file, which makes the preview
// say "not evaluated" rather than guess.
type CachedReputation interface {
	ConsultCached(policyID, domain string) (ReputationVerdict, CacheState)
}

// CacheState says what a cache-only consultation found.
type CacheState int

const (
	// CacheNoProvider: no external provider applies to this policy, or
	// reputation is off. The live path would not consult anyone either.
	CacheNoProvider CacheState = iota
	// CacheMiss: a provider applies and has no usable cached verdict. The
	// live path would ask it, and the answer is unknown until it does.
	CacheMiss
	// CacheHit: every applicable provider had a fresh cached verdict, or one
	// of them had a malicious one, which is decisive on its own.
	CacheHit
)

// Preview is what the current configuration would decide for a question,
// reached without any side effect.
//
// The decision is produced by the same code the DNS handler runs, on the
// same compiled snapshot, so it cannot drift from what a real query would
// get. What it does not do is the one step of the live path that has a side
// effect: asking an external provider. External reports what the provider
// cache already held instead, and says plainly when the live outcome would
// depend on a lookup this preview did not perform.
type Preview struct {
	Decision Decision
	// PolicyID and PolicyName are the policy the question was evaluated
	// under, after falling back to the default for an unknown ID.
	PolicyID   string
	PolicyName string
	External   ExternalPreview
}

// ExternalPreview describes the external-provider step of a preview.
type ExternalPreview struct {
	// Configured reports that a reputation consultant is installed at all.
	Configured bool
	// Reached reports that evaluation got as far as the external step: no
	// local rule decided the question first. An allow-listed name never
	// reaches a provider, and the preview says so by leaving this false.
	Reached bool
	// State is what the cache held, when the step was reached.
	State CacheState
	// Evaluated reports that the external step produced an answer — a
	// cached verdict — rather than being skipped for want of one.
	Evaluated bool
	// ProviderName names the provider whose cached verdict decided, if one
	// did.
	ProviderName string
}

// Engine evaluates questions against the current configuration.
type Engine struct {
	snap  atomic.Pointer[snapshot]
	lists *blocklist.Holder
	store *store.Store

	// reputation is nil unless an operator has configured external providers
	// AND set a mode other than off. Nil is the overwhelmingly common case and
	// is checked with one nil comparison per query.
	reputation atomic.Pointer[Reputation]
}

// SetReputation installs or removes the external-intelligence consultant.
//
// Atomic, so it can be changed while the resolver is serving: an operator
// switching modes in the dashboard takes effect on the next query. Passing nil
// removes it, which is what happens when the mode goes back to off.
func (e *Engine) SetReputation(r Reputation) {
	if r == nil {
		e.reputation.Store(nil)
		return
	}
	e.reputation.Store(&r)
}

// NewEngine returns an engine reading blocklists from holder. Reload must be
// called before it will match anything.
func NewEngine(st *store.Store, holder *blocklist.Holder) *Engine {
	e := &Engine{lists: holder, store: st}
	e.snap.Store(&snapshot{policies: map[string]*compiledPolicy{}, clients: map[string]string{}})
	return e
}

// Reload rebuilds the compiled snapshot from the database. It is called at
// startup and after any configuration change through the API.
func (e *Engine) Reload(ctx context.Context) error {
	policies, err := e.store.ListPolicies(ctx)
	if err != nil {
		return err
	}
	networks, err := e.store.ListNetworks(ctx)
	if err != nil {
		return err
	}
	clients, err := e.store.ListClients(ctx)
	if err != nil {
		return err
	}

	snap := &snapshot{
		policies: make(map[string]*compiledPolicy, len(policies)),
		clients:  make(map[string]string, len(clients)),
	}

	for _, p := range policies {
		cp := &compiledPolicy{
			id:         p.ID,
			name:       p.Name,
			categories: toSet(p.Categories),
			allow:      toSet(p.AllowDomains),
			block:      toSet(p.BlockDomains),
			blockMode:  p.BlockMode,
			logQueries: p.LogQueries,
		}
		if !cp.blockMode.Valid() {
			cp.blockMode = store.BlockNXDOMAIN
		}
		snap.policies[p.ID] = cp
		if p.IsDefault {
			snap.defaultPolicy = cp
		}
	}

	for _, n := range networks {
		cn := compiledNetwork{
			id:       n.ID,
			name:     n.Name,
			policyID: n.PolicyID,
			enabled:  n.Enabled,
		}
		for _, c := range n.CIDRs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				continue // stored CIDRs are validated on write; skip anything stale
			}
			cn.prefixes = append(cn.prefixes, p)
			if p.Bits() > cn.maxBits {
				cn.maxBits = p.Bits()
			}
		}
		snap.networks = append(snap.networks, cn)
	}

	// The network order decides only which row is the catch-all below; it
	// does not decide attribution. ListNetworks returns rows by name, and the
	// stable sort keeps that order among equal lengths, so the choice of
	// fallback is the same on every reload.
	sort.SliceStable(snap.networks, func(i, j int) bool {
		return snap.networks[i].maxBits > snap.networks[j].maxBits
	})

	// A network with no CIDRs is the catch-all for unmatched clients. If more
	// than one exists we take the first by name for determinism.
	for i := range snap.networks {
		if len(snap.networks[i].prefixes) == 0 && snap.networks[i].enabled {
			snap.fallback = &snap.networks[i]
			break
		}
	}
	if snap.fallback == nil && len(snap.networks) > 0 {
		snap.fallback = &snap.networks[len(snap.networks)-1]
	}

	// The routing table: one entry per CIDR, most specific prefix first.
	//
	// Built after snap.networks is complete and sorted, because each route
	// points into that slice and an append after this point would move it.
	// Disabled networks contribute no routes at all: a client inside a
	// disabled network's range falls through to whatever else contains it,
	// exactly as it did before, and the query path no longer has to check the
	// flag per prefix.
	for i := range snap.networks {
		n := &snap.networks[i]
		if !n.enabled {
			continue
		}
		for _, p := range n.prefixes {
			snap.routes = append(snap.routes, route{prefix: p, network: n})
		}
	}
	sortRoutes(snap.routes)

	for _, c := range clients {
		snap.clients[c.IP] = c.Name
	}

	e.snap.Store(snap)
	return nil
}

// MatchClient resolves a client address to its network and policy.
//
// The client belongs to the network owning the most specific prefix that
// contains it. That is decided per CIDR, never per network: a network holding
// 10.0.0.0/8 and an unrelated 192.0.2.123/32 is not "a /32 network" when a
// client from 10.42.1.10 arrives, and a second network's 10.42.0.0/16 must win.
// Equal-length prefixes from different networks are broken by network name and
// then ID, so the answer is the same on every reload — see sortRoutes.
//
// A client inside no enabled prefix lands on the catch-all, whose policy is the
// deployment's default for unmatched clients.
func (e *Engine) MatchClient(addr netip.Addr) Match {
	snap := e.snap.Load()
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	for i := range snap.routes {
		r := &snap.routes[i]
		if prefixContains(r.prefix, addr) {
			return e.matchFor(snap, r.network)
		}
	}
	if snap.fallback != nil {
		return e.matchFor(snap, snap.fallback)
	}
	return Match{}
}

// sortRoutes orders a routing table most specific prefix first.
//
// Longest prefix first is the whole of the correctness argument: the first
// route that contains a client is then the most specific one that does. The
// remaining keys exist so that ties are decided the same way every time —
// two networks claiming the same range is a configuration an operator should
// fix, but until they do, attribution must not flip between reloads.
func sortRoutes(routes []route) {
	sort.SliceStable(routes, func(i, j int) bool {
		a, b := routes[i], routes[j]
		if a.prefix.Bits() != b.prefix.Bits() {
			return a.prefix.Bits() > b.prefix.Bits()
		}
		if a.network.name != b.network.name {
			return a.network.name < b.network.name
		}
		if a.network.id != b.network.id {
			return a.network.id < b.network.id
		}
		return a.prefix.String() < b.prefix.String()
	})
}

// MatchNetworkID resolves an explicitly identified network, used by DoH and DoT
// clients that present a per-network token rather than arriving from a known IP.
func (e *Engine) MatchNetworkID(id string) (Match, bool) {
	snap := e.snap.Load()
	for i := range snap.networks {
		if snap.networks[i].id == id {
			return e.matchFor(snap, &snap.networks[i]), true
		}
	}
	return Match{}, false
}

func (e *Engine) matchFor(snap *snapshot, n *compiledNetwork) Match {
	m := Match{NetworkID: n.id, NetworkName: n.name, PolicyID: n.policyID}
	if p := snap.policies[n.policyID]; p != nil {
		m.PolicyName = p.name
	}
	return m
}

// ClientName returns the operator-assigned name for an IP, if any.
func (e *Engine) ClientName(ip string) string {
	return e.snap.Load().clients[ip]
}

// Evaluate decides whether a question should be blocked under the given policy.
//
// Order matters and is deliberate:
//  1. the policy's allow list, so an operator can always override a bad entry
//     without waiting for a feed to be corrected;
//  2. the policy's own block list;
//  3. the shared threat-intelligence index, filtered to the categories this
//     policy actually enables.
func (e *Engine) Evaluate(policyID, domain string) Decision {
	return e.EvaluateContext(context.Background(), policyID, domain)
}

// EvaluateContext is Evaluate with a context, for the one step that can have
// one: an external reputation lookup in blocking mode.
//
// Evaluate keeps its signature because every other caller — tests, the
// dashboard's policy preview — has no context to give and needs none. The DNS
// handler has one and passes it, so a client that gave up cancels the wait
// rather than leaving it to run out its budget.
func (e *Engine) EvaluateContext(ctx context.Context, policyID, domain string) Decision {
	snap := e.snap.Load()
	p := snap.policyFor(policyID)
	if p == nil {
		return Decision{LogQuery: true, BlockMode: store.BlockNXDOMAIN}
	}

	var d Decision
	evaluateLocal(e.lists, p, domain, &d)
	if d.Basis.Decided() {
		return d
	}

	// External intelligence, last and only if configured.
	//
	// Last on purpose. Everything above is local: a map lookup against an
	// index already in memory, which is microseconds and cannot fail. Asking a
	// third party is the most expensive and least reliable thing this function
	// can do, so it happens only for names nothing local had an opinion about
	// — and a domain the operator explicitly allowed never reaches it at all,
	// which also means it is never disclosed.
	//
	// The nil check is the whole cost when no provider is configured, which is
	// the default and the overwhelmingly common case.
	if rep := e.reputation.Load(); rep != nil {
		if v, ok := (*rep).Consult(ctx, policyID, domain); ok && v.Malicious {
			applyReputation(&d, p, v)
		}
	}

	return d
}

// Preview evaluates a question exactly as EvaluateContext would, minus the
// one step with a side effect. See the Preview type.
//
// Nothing here writes: no query-log row, no decision record, no cache entry,
// no provider request. It reads the compiled snapshot and, when the external
// step is reached, the provider cache.
func (e *Engine) Preview(policyID, domain string) Preview {
	snap := e.snap.Load()
	p := snap.policyFor(policyID)
	if p == nil {
		return Preview{Decision: Decision{LogQuery: true, BlockMode: store.BlockNXDOMAIN}}
	}

	out := Preview{PolicyID: p.id, PolicyName: p.name}
	evaluateLocal(e.lists, p, domain, &out.Decision)
	rep := e.reputation.Load()
	out.External.Configured = rep != nil
	if out.Decision.Basis.Decided() || rep == nil {
		return out
	}

	out.External.Reached = true
	cached, ok := (*rep).(CachedReputation)
	if !ok {
		// A consultant that cannot be asked without a lookup. Treated as a
		// miss: the live path would ask, and this preview did not.
		out.External.State = CacheMiss
		return out
	}
	v, state := cached.ConsultCached(policyID, domain)
	out.External.State = state
	if state != CacheHit {
		return out
	}
	out.External.Evaluated = true
	out.External.ProviderName = v.ProviderName
	if v.Malicious {
		applyReputation(&out.Decision, p, v)
	}
	return out
}

// policyFor returns the named policy, or the default for an unknown ID.
func (s *snapshot) policyFor(id string) *compiledPolicy {
	if p := s.policies[id]; p != nil {
		return p
	}
	return s.defaultPolicy
}

// applyReputation turns a provider's malicious verdict into the decision.
func applyReputation(d *Decision, p *compiledPolicy, v ReputationVerdict) {
	d.Blocked = true
	d.Category = v.Category
	if d.Category == "" {
		d.Category = "malware"
	}
	d.Source = v.ProviderName
	d.Basis = &Basis{
		Rule: RuleReputation, Category: d.Category,
		ProviderName: v.ProviderName,
		PolicyID:     p.id, PolicyName: p.name,
	}
	// Named rather than generic. An operator looking at a blocked query has
	// to be able to tell a curated-feed block from a third-party API's
	// opinion, because only one of those is something they can inspect
	// offline.
	d.Reason = "Blocked by external threat intelligence (" + v.ProviderName + ")"
}

// evaluateLocal runs the three local rules and writes the decision they
// reached into d, with Basis set when one of them fired.
//
// Shared by the live path and the preview so the two cannot disagree. It
// allocates nothing on the miss path: see the note on Decision.Basis.
//
// It fills the caller's value rather than returning one because a Decision
// is several strings wide and this function is too large to inline: returning
// it by value put a copy on the miss path that the hot-path benchmark could
// see, and the miss path is nearly every query.
func evaluateLocal(lists *blocklist.Holder, p *compiledPolicy, domain string, d *Decision) {
	*d = Decision{BlockMode: p.blockMode, LogQuery: p.logQueries}

	if len(p.allow) > 0 && matchSuffix(p.allow, domain) {
		d.Reason = "Allowed by policy allow-list"
		d.Source = "allow-list"
		d.Basis = &Basis{Rule: RuleAllowList, PolicyID: p.id, PolicyName: p.name}
		return
	}

	if len(p.block) > 0 && matchSuffix(p.block, domain) {
		d.Blocked = true
		d.Reason = "Blocked by your custom block-list"
		d.Category = "custom"
		d.Source = "block-list"
		d.Basis = &Basis{
			Rule: RuleBlockList, Category: "custom",
			PolicyID: p.id, PolicyName: p.name,
		}
		return
	}

	if len(p.categories) > 0 {
		// LookupEnabled, not Lookup: a domain can be claimed under several
		// categories, and this policy blocks it if it enables any one of them.
		// Asking for the domain's primary category and comparing it here would
		// miss a C2 domain that a malware feed also lists.
		if entry, ok := lists.Load().LookupEnabled(domain, p.categories); ok {
			d.Blocked = true
			d.Category = entry.Category
			d.Source = entry.FeedName
			d.Reason = catalog.CategoryReason(entry.Category)
			d.Basis = &Basis{
				Rule: RuleCategory, Category: entry.Category,
				FeedID: entry.FeedID, FeedName: entry.FeedName,
				PolicyID: p.id, PolicyName: p.name,
			}
			return
		}
	}

}

// PolicyLogsQueries reports whether the named policy records per-query rows.
func (e *Engine) PolicyLogsQueries(policyID string) bool {
	snap := e.snap.Load()
	if p := snap.policies[policyID]; p != nil {
		return p.logQueries
	}
	if snap.defaultPolicy != nil {
		return snap.defaultPolicy.logQueries
	}
	return true
}

func matchSuffix(set map[string]bool, domain string) bool {
	found := false
	domainutil.Suffixes(domain, func(suffix string) bool {
		if set[suffix] {
			found = true
			return true
		}
		return false
	})
	return found
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]bool, len(items))
	for _, i := range items {
		if d := domainutil.Normalize(i); d != "" {
			out[d] = true
		} else {
			out[i] = true
		}
	}
	return out
}

// prefixContains reports whether p contains addr, tolerating the IPv4/IPv6
// mismatch that arises when a v4 client arrives over a dual-stack socket.
func prefixContains(p netip.Prefix, addr netip.Addr) bool {
	if p.Addr().Is4() && addr.Is4In6() {
		addr = addr.Unmap()
	}
	// netip.Prefix.Contains reports false for any address carrying a scope
	// zone, so a link-local client ("fe80::1%eth0") would match no network at
	// all and land on the catch-all. Strip it: the zone identifies the local
	// interface, not the address's place in a prefix.
	//
	// The limitation this leaves is honest — the same fe80:: address can exist
	// on two interfaces, so link-local attribution cannot distinguish them.
	addr = addr.WithZone("")
	if p.Addr().Is4() != addr.Is4() {
		return false
	}
	return p.Contains(addr)
}
