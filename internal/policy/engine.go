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
}

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
	// bits is the longest prefix length, used to prefer the most specific match.
	maxBits int
}

type snapshot struct {
	networks []compiledNetwork
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

	// Most specific prefix wins, so a /32 exception beats the /16 it sits in.
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

	for _, c := range clients {
		snap.clients[c.IP] = c.Name
	}

	e.snap.Store(snap)
	return nil
}

// MatchClient resolves a client address to its network and policy.
func (e *Engine) MatchClient(addr netip.Addr) Match {
	snap := e.snap.Load()
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	for i := range snap.networks {
		n := &snap.networks[i]
		if !n.enabled || len(n.prefixes) == 0 {
			continue
		}
		for _, p := range n.prefixes {
			if prefixContains(p, addr) {
				return e.matchFor(snap, n)
			}
		}
	}
	if snap.fallback != nil {
		return e.matchFor(snap, snap.fallback)
	}
	return Match{}
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
	p := snap.policies[policyID]
	if p == nil {
		p = snap.defaultPolicy
	}
	if p == nil {
		return Decision{LogQuery: true, BlockMode: store.BlockNXDOMAIN}
	}

	d := Decision{BlockMode: p.blockMode, LogQuery: p.logQueries}

	if len(p.allow) > 0 && matchSuffix(p.allow, domain) {
		d.Reason = "Allowed by policy allow-list"
		d.Source = "allow-list"
		return d
	}

	if len(p.block) > 0 && matchSuffix(p.block, domain) {
		d.Blocked = true
		d.Reason = "Blocked by your custom block-list"
		d.Category = "custom"
		d.Source = "block-list"
		return d
	}

	if len(p.categories) > 0 {
		// LookupEnabled, not Lookup: a domain can be claimed under several
		// categories, and this policy blocks it if it enables any one of them.
		// Asking for the domain's primary category and comparing it here would
		// miss a C2 domain that a malware feed also lists.
		if entry, ok := e.lists.Load().LookupEnabled(domain, p.categories); ok {
			d.Blocked = true
			d.Category = entry.Category
			d.Source = entry.FeedName
			d.Reason = catalog.CategoryReason(entry.Category)
			return d
		}
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
			d.Blocked = true
			d.Category = v.Category
			if d.Category == "" {
				d.Category = "malware"
			}
			d.Source = v.ProviderName
			// Named rather than generic. An operator looking at a blocked
			// query has to be able to tell a curated-feed block from a
			// third-party API's opinion, because only one of those is
			// something they can inspect offline.
			d.Reason = "Blocked by external threat intelligence (" + v.ProviderName + ")"
		}
	}

	return d
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
