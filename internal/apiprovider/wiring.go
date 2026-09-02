package apiprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// ProviderSource is the configuration the engine needs, as an interface so
// this package does not import internal/store.
type ProviderSource interface {
	// LoadProviders returns every configured provider, with the credential
	// already opened. This is deliberately the ONLY method that produces
	// plaintext credentials anywhere in the codebase, so there is exactly one
	// place to audit.
	LoadProviders(ctx context.Context) ([]ProviderConfig, error)
}

// ProviderConfig is one row plus its opened credential.
type ProviderConfig struct {
	ID           string
	Name         string
	Kind         string
	Enabled      bool
	Capabilities []string
	Settings     map[string]string
	Secret       string
	// SecretErr is why the credential could not be opened, when it could not.
	// Carried rather than swallowed: a provider whose key cannot be decrypted
	// must appear in the dashboard saying so, not vanish.
	SecretErr       error
	TimeoutMS       int
	RatePerMinute   int
	CacheTTLSeconds int
	PolicyScope     []string
}

// BuildInstances turns configuration into callable providers.
//
// A provider that cannot be built is returned in the list with its Err set
// rather than dropped. That is the whole reason this returns instances instead
// of only the working ones: an operator whose VirusTotal key is wrong needs to
// see "VirusTotal — credential rejected" in the dashboard, and a provider that
// silently disappears from the list is a configuration screen that lies about
// what is configured.
func sanitizeLogValue(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return v
}

func BuildInstances(configs []ProviderConfig, log *slog.Logger) []*Instance {
	if log == nil {
		log = slog.Default()
	}

	out := make([]*Instance, 0, len(configs))
	for _, cfg := range configs {
		inst := &Instance{
			ID:           cfg.ID,
			Name:         cfg.Name,
			Kind:         cfg.Kind,
			Capabilities: ParseCapabilities(cfg.Capabilities),
			PolicyScope:  cfg.PolicyScope,
			CacheTTL:     time.Duration(cfg.CacheTTLSeconds) * time.Second,
		}

		switch {
		case !cfg.Enabled:
			// Disabled is not an error, but it is not usable either. Err
			// carries the reason so the dashboard can distinguish "you turned
			// this off" from "this is broken".
			inst.Err = errDisabled
		case !Known(cfg.Kind):
			// A row written by a newer binary, or an adapter removed. Naming
			// the kind matters: "unknown provider" tells an operator nothing
			// about which row to look at.
			inst.Err = fmt.Errorf("no adapter for provider kind %q in this build", cfg.Kind)
		case cfg.SecretErr != nil:
			inst.Err = fmt.Errorf("%w: %v", ErrNoCredential, cfg.SecretErr)
		}

		if inst.Err != nil {
			out = append(out, inst)
			continue
		}

		client := NewClient(ClientOptions{
			ProviderID:    cfg.ID,
			Timeout:       time.Duration(cfg.TimeoutMS) * time.Millisecond,
			RatePerMinute: cfg.RatePerMinute,
		})
		inst.Client = client

		p, err := New(cfg.Kind, InstanceConfig{
			ID:       cfg.ID,
			Name:     cfg.Name,
			Settings: cfg.Settings,
			Secret:   cfg.Secret,
			Client:   client,
			CacheTTL: inst.CacheTTL,
		})
		if err != nil {
			inst.Err = err
			// Logged at info, not error: a misconfigured provider is an
			// operator's half-finished work, not an incident. It is already
			// visible in the dashboard, which is where they are looking.
			log.Info("external provider could not be built",
				"provider", sanitizeLogValue(cfg.Name),
				"provider_id", sanitizeLogValue(cfg.ID),
				"kind", sanitizeLogValue(cfg.Kind),
				// err comes from an adapter constructor, which is documented
				// never to carry the credential and tested for it.
				"error", sanitizeLogValue(err.Error()))
			out = append(out, inst)
			continue
		}
		inst.Provider = p
		out = append(out, inst)
	}
	return out
}

// errDisabled is the Err on a provider the operator switched off.
var errDisabled = errors.New("provider is disabled")

// ErrDisabled reports whether an instance's Err is "the operator turned this
// off", as opposed to a real failure. The dashboard renders the two
// differently and conflating them would show a working provider as broken.
func ErrDisabled(err error) bool { return errors.Is(err, errDisabled) }

// Reload rebuilds every instance from the source and installs them.
//
// Called at startup and after any provider write. Rebuilding wholesale rather
// than patching: the set is a handful of rows edited by hand in a dashboard,
// the cost is a few allocations, and a diffing path would be a second place
// for the instance list and the database to disagree.
func (e *Engine) Reload(ctx context.Context, src ProviderSource) error {
	if src == nil {
		e.SetInstances(nil)
		return nil
	}
	configs, err := src.LoadProviders(ctx)
	if err != nil {
		// The existing instances are left in place. A database hiccup should
		// not disable working providers, and the next reload will converge.
		return fmt.Errorf("load providers: %w", err)
	}
	e.SetInstances(BuildInstances(configs, e.log))
	return nil
}

// PolicyConsultant adapts the Engine to the interface internal/policy expects.
//
// A thin type rather than making Engine satisfy the interface directly,
// because the two have different vocabularies on purpose: policy wants a
// yes/no and a name, and the engine deals in scores and dispositions. Doing
// the translation here keeps apiprovider.Verdict out of the policy package.
type PolicyConsultant struct {
	Engine *Engine
	// Threshold is the score at or above which a suspicious verdict is
	// treated as malicious. One is the default, meaning "never" — only an
	// explicit malicious disposition blocks. An operator who wants to act on
	// suspicion sets it lower.
	Threshold float64
}

// ConsultResult mirrors policy.ReputationVerdict without importing it.
type ConsultResult struct {
	Malicious    bool
	Score        float64
	Category     string
	ProviderName string
}

// Consult answers the policy engine's question.
func (c PolicyConsultant) Consult(ctx context.Context, policyID, domain string) (ConsultResult, bool) {
	if c.Engine == nil {
		return ConsultResult{}, false
	}
	v, ok := c.Engine.Consult(ctx, policyID, domain)
	if !ok {
		return ConsultResult{}, false
	}

	threshold := c.Threshold
	if threshold <= 0 {
		threshold = 1
	}

	res := ConsultResult{
		Score:        v.Score,
		ProviderName: providerNameFor(c.Engine, domain),
	}
	if len(v.Categories) > 0 {
		res.Category = v.Categories[0]
	}

	switch v.Disposition {
	case DispositionMalicious:
		res.Malicious = true
	case DispositionSuspicious:
		// Only when the operator asked for it. A suspicious verdict blocking
		// by default would make every provider considerably more aggressive
		// than the vendor intends, and the false positives land on the
		// operator rather than on us.
		res.Malicious = v.Score >= threshold
	}
	return res, true
}

// providerNameFor finds a name for the block reason.
//
// Best-effort: the verdict does not carry which provider produced it, because
// Consult merges several. The first reputation-capable provider is the right
// answer in the overwhelmingly common single-provider case and an honest
// approximation otherwise — which is why the reason says "external threat
// intelligence" first and the name second.
func providerNameFor(e *Engine, _ string) string {
	for _, inst := range e.Instances() {
		if inst.HasCapability(CapReputation) {
			return inst.Name
		}
	}
	return "external provider"
}
