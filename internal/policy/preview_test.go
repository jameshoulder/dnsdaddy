package policy

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// cachedReputation is a consultant that can also be read without a lookup.
// Consult counts calls so a test can prove the preview never made one.
type cachedReputation struct {
	countingReputation
	cached      ReputationVerdict
	state       CacheState
	cachedCalls atomic.Int32
}

func (c *cachedReputation) ConsultCached(_, _ string) (ReputationVerdict, CacheState) {
	c.cachedCalls.Add(1)
	return c.cached, c.state
}

// The preview and the live path share one evaluation, so for every local
// rule they must reach the same answer — and the preview must reach it
// without a side effect.
func TestPreviewMatchesEvaluateForLocalRules(t *testing.T) {
	e, st, _ := newEngine(t, map[string]string{"evil.example": "malware", "adult.example": "adult"})
	ctx := context.Background()
	if _, err := st.UpdatePolicy(ctx, "p_standard", store.PolicyInput{
		AllowDomains: &[]string{"allowed.example"},
		BlockDomains: &[]string{"blocked.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	for _, domain := range []string{
		"evil.example", "login.evil.example", "adult.example", "allowed.example",
		"sub.allowed.example", "blocked.example", "unknown.example",
	} {
		live := e.Evaluate("p_standard", domain)
		pv := e.Preview("p_standard", domain)
		if pv.Decision.Blocked != live.Blocked || pv.Decision.Reason != live.Reason ||
			pv.Decision.Category != live.Category || pv.Decision.Source != live.Source {
			t.Errorf("%s: preview %+v differs from live %+v", domain, pv.Decision, live)
		}
		if (pv.Decision.Basis == nil) != (live.Basis == nil) {
			t.Errorf("%s: preview basis presence differs from live", domain)
		}
		if pv.PolicyID != "p_standard" || pv.PolicyName == "" {
			t.Errorf("%s: preview does not name the policy: %+v", domain, pv)
		}
		if pv.External.Configured || pv.External.Reached {
			t.Errorf("%s: no consultant is installed, yet external = %+v", domain, pv.External)
		}
	}

	// An unknown policy falls back to the default, as the live path does.
	if pv := e.Preview("p_nope", "evil.example"); !pv.Decision.Blocked || pv.PolicyID != "p_standard" {
		t.Errorf("unknown policy: preview = %+v, want the default policy's block", pv)
	}
}

func TestPreviewNeverCausesAProviderLookup(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	rep := &cachedReputation{state: CacheMiss}
	rep.verdict = ReputationVerdict{Malicious: true, ProviderName: "TestIntel"}
	rep.answer = true
	e.SetReputation(rep)

	pv := e.Preview("p_standard", "nothing-local-knows.example")

	if n := rep.calls.Load(); n != 0 {
		t.Fatalf("the preview consulted the provider %d time(s); it must never", n)
	}
	if rep.cachedCalls.Load() != 1 {
		t.Errorf("the preview read the cache %d times, want once", rep.cachedCalls.Load())
	}
	// A miss is reported as exactly that. The live path would ask and might
	// block; the preview does not guess either way.
	if pv.Decision.Blocked {
		t.Error("a cache miss was rendered as a block")
	}
	if !pv.External.Configured || !pv.External.Reached || pv.External.Evaluated || pv.External.State != CacheMiss {
		t.Errorf("external = %+v, want configured, reached, not evaluated, miss", pv.External)
	}
}

func TestPreviewUsesACachedVerdictExactlyAsTheLivePathWould(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	rep := &cachedReputation{
		state:  CacheHit,
		cached: ReputationVerdict{Malicious: true, Category: "phishing", ProviderName: "TestIntel"},
	}
	e.SetReputation(rep)

	pv := e.Preview("p_standard", "known-bad.example")
	if !pv.Decision.Blocked || pv.Decision.Basis == nil || pv.Decision.Basis.Rule != RuleReputation {
		t.Fatalf("a cached malicious verdict did not produce a reputation block: %+v", pv.Decision)
	}
	if pv.Decision.Category != "phishing" || pv.Decision.Source != "TestIntel" {
		t.Errorf("decision = %+v, want the provider's category and name", pv.Decision)
	}
	if !pv.External.Evaluated || pv.External.ProviderName != "TestIntel" {
		t.Errorf("external = %+v, want evaluated by TestIntel", pv.External)
	}
	if rep.calls.Load() != 0 {
		t.Error("a cached answer still caused a lookup")
	}

	// A cached benign verdict is an answer too: allowed, evaluated.
	rep.cached = ReputationVerdict{Malicious: false, ProviderName: "TestIntel"}
	pv = e.Preview("p_standard", "known-good.example")
	if pv.Decision.Blocked || !pv.External.Evaluated {
		t.Errorf("a cached benign verdict: %+v / %+v", pv.Decision, pv.External)
	}
}

func TestPreviewSaysWhenNoProviderAppliesToThePolicy(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	rep := &cachedReputation{state: CacheNoProvider}
	e.SetReputation(rep)

	pv := e.Preview("p_standard", "x.example")
	if !pv.External.Configured || !pv.External.Reached || pv.External.State != CacheNoProvider || pv.External.Evaluated {
		t.Errorf("external = %+v, want configured, reached, no provider for this policy", pv.External)
	}
}

func TestPreviewDoesNotReachTheProviderForALocallyDecidedName(t *testing.T) {
	// An allow-listed or locally blocked name is decided before the external
	// step and is never disclosed to a provider. The preview reports the
	// same: Reached stays false, and the cache is not even read.
	e, st, _ := newEngine(t, map[string]string{"evil.example": "malware"})
	ctx := context.Background()
	if _, err := st.UpdatePolicy(ctx, "p_standard", store.PolicyInput{AllowDomains: &[]string{"allowed.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	rep := &cachedReputation{state: CacheHit, cached: ReputationVerdict{Malicious: true, ProviderName: "TestIntel"}}
	e.SetReputation(rep)

	for _, domain := range []string{"allowed.example", "evil.example"} {
		pv := e.Preview("p_standard", domain)
		if pv.External.Reached {
			t.Errorf("%s: the external step was reached for a locally decided name", domain)
		}
	}
	if rep.cachedCalls.Load() != 0 || rep.calls.Load() != 0 {
		t.Errorf("the provider was touched (%d cached, %d live reads) for locally decided names",
			rep.cachedCalls.Load(), rep.calls.Load())
	}
}

// A consultant without the cached face is treated as a miss: the preview
// cannot ask it, so it says the live outcome is undetermined.
func TestPreviewTreatsAnUncacheableConsultantAsAMiss(t *testing.T) {
	e, _, _ := newEngine(t, nil)
	rep := &countingReputation{verdict: ReputationVerdict{Malicious: true}, answer: true}
	e.SetReputation(rep)

	pv := e.Preview("p_standard", "x.example")
	if rep.calls.Load() != 0 {
		t.Fatal("the preview consulted a consultant it cannot read without a lookup")
	}
	if pv.Decision.Blocked || !pv.External.Reached || pv.External.State != CacheMiss {
		t.Errorf("preview = %+v / %+v, want not blocked and reported as a miss", pv.Decision, pv.External)
	}
}
