package apiprovider

import (
	"fmt"
	"sort"
	"sync"
)

// Constructor builds a provider instance from an operator's configuration.
//
// Returning an error rather than a nil provider is the difference between "an
// operator misconfigured this" and a nil dereference three layers down at the
// first lookup.
type Constructor func(InstanceConfig) (Provider, error)

// Template describes a provider kind to the dashboard's add-provider wizard.
//
// It lives here rather than in the dashboard because the fields a provider
// needs are a property of the adapter, and a JavaScript copy of them is a copy
// that goes stale the first time an adapter changes.
type Template struct {
	Kind         string       `json:"kind"`
	DisplayName  string       `json:"displayName"`
	Summary      string       `json:"summary"`
	DocsURL      string       `json:"docsUrl,omitempty"`
	PrivacyNote  string       `json:"privacyNote"`
	Capabilities []Capability `json:"capabilities"`
	// LiveVerified reports whether this adapter has been exercised against the
	// vendor's real service, as opposed to against captured responses in CI.
	//
	// It is false for every adapter shipped so far, and the dashboard says so
	// on the card. Claiming otherwise would be the one lie an operator cannot
	// check: they would find out when a provider they trusted silently
	// answered "unknown" to everything because the response shape moved.
	LiveVerified bool `json:"liveVerified"`
	// Verification is the one-line evidence statement shown next to the badge.
	Verification string `json:"verification"`
	// SecretLabel is what the credential is called by this vendor — "API key",
	// "Personal access token" — so the form asks for the thing the operator is
	// looking at in their console.
	SecretLabel string `json:"secretLabel"`
	// SecretRequired is false for a provider that can work unauthenticated.
	SecretRequired bool `json:"secretRequired"`
	// Fields are the non-secret settings, in the order the form shows them.
	Fields []TemplateField `json:"fields"`
	// Defaults for the bounds, chosen per provider: a free tier with four
	// lookups a minute needs a different rate from a self-hosted service.
	DefaultTimeoutMS     int `json:"defaultTimeoutMs"`
	DefaultRatePerMinute int `json:"defaultRatePerMinute"`
	DefaultCacheTTLSecs  int `json:"defaultCacheTtlSeconds"`
}

// TemplateField is one non-secret setting in the wizard.
type TemplateField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

var (
	registryMu   sync.RWMutex
	constructors = map[string]Constructor{}
	templates    = map[string]Template{}
)

// Register adds an adapter to the registry.
//
// Called from adapter package init functions. Panics on a duplicate kind: two
// adapters answering to one name is a build-time mistake, and the alternative
// — last registration wins — decides which service an operator's stored
// credential is sent to by import order.
func Register(kind string, c Constructor, t Template) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := constructors[kind]; exists {
		panic("apiprovider: duplicate provider kind " + kind)
	}
	t.Kind = kind
	constructors[kind] = c
	templates[kind] = t
}

// New builds a provider instance of the given kind.
func New(kind string, cfg InstanceConfig) (Provider, error) {
	registryMu.RLock()
	c, ok := constructors[kind]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("apiprovider: no adapter registered for kind %q", kind)
	}
	return c(cfg)
}

// Known reports whether a kind has an adapter in this build.
func Known(kind string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := constructors[kind]
	return ok
}

// Templates returns every registered template, ordered by display name so the
// wizard's list does not depend on map iteration order.
func Templates() []Template {
	registryMu.RLock()
	defer registryMu.RUnlock()

	out := make([]Template, 0, len(templates))
	for _, t := range templates {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
	return out
}

// TemplateFor returns one kind's template.
func TemplateFor(kind string) (Template, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	t, ok := templates[kind]
	return t, ok
}

// Supports reports whether an instance implements a capability.
//
// A type assertion in one place rather than at every call site, so the set of
// interfaces and the set of capabilities cannot drift apart silently.
func Supports(p Provider, c Capability) bool {
	if p == nil {
		return false
	}
	switch c {
	case CapReputation:
		_, ok := p.(ReputationProvider)
		return ok
	case CapEnrichment:
		_, ok := p.(Enricher)
		return ok
	case CapFeed:
		_, ok := p.(FeedSource)
		return ok
	}
	return false
}
