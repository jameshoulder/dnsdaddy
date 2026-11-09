package protection

import "testing"

// TestSecuritySharedPrivateSuffixNotRebindingException blocks exemptions for a shared private public suffix.
func TestSecuritySharedPrivateSuffixNotRebindingException(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowDomains = []string{"github.io"}
	if _, err := compile(cfg); err == nil {
		t.Fatal("known shared private suffix must not exempt unrelated tenants from rebinding protection")
	}
}

// TestSecurityNarrowPrivateDomainCanBeRebindingException allows exceptions confined to a specific tenant-controlled domain.
func TestSecurityNarrowPrivateDomainCanBeRebindingException(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowDomains = []string{"tenant.github.io"}
	if _, err := compile(cfg); err != nil {
		t.Fatalf("a specific tenant-controlled domain should remain eligible: %v", err)
	}
}

// TestSecurityUnknownInternalSuffixRemainsEligible keeps deliberate internal names eligible for narrowly scoped exceptions.
func TestSecurityUnknownInternalSuffixRemainsEligible(t *testing.T) {
	cfg := Default()
	cfg.Rebinding.AllowDomains = []string{"internal"}
	if _, err := compile(cfg); err != nil {
		t.Fatalf("unknown single-label internal name should remain eligible: %v", err)
	}
}
