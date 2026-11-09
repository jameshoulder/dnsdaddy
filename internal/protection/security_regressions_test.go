package protection

import "testing"

func TestSecuritySharedPrivateSuffixNotRebindingException(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowDomains = []string{"github.io"}
	if _, err := compile(cfg); err == nil {
		t.Fatal("known shared private suffix must not exempt unrelated tenants from rebinding protection")
	}
}

func TestSecurityNarrowPrivateDomainCanBeRebindingException(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowDomains = []string{"tenant.github.io"}
	if _, err := compile(cfg); err != nil {
		t.Fatalf("a specific tenant-controlled domain should remain eligible: %v", err)
	}
}

func TestSecurityUnknownInternalSuffixRemainsEligible(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowDomains = []string{"internal"}
	if _, err := compile(cfg); err != nil {
		t.Fatalf("unknown single-label internal name should remain eligible: %v", err)
	}
}
