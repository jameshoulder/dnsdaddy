package store

import (
	"context"
	"testing"
)

func TestIntegrationPreferencesMigrationPreservesLegacyEffectiveGates(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		enabled              bool
		ceiling, saved, want string
		enrichment           bool
	}{
		{"disabled_old_blocking", false, "blocking", "blocking", "off", false},
		{"disabled_old_cache", false, "cache_only", "cache_only", "off", false},
		{"lowered_ceiling", true, "cache_only", "blocking", "cache_only", true},
		{"explicit_old_off", true, "blocking", "off", "off", false},
		{"old_cache_choice", true, "blocking", "cache_only", "cache_only", true},
		{"off_ceiling", true, "off", "blocking", "off", false},
		{"fresh_disabled", false, "off", "", "off", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newProviderStore(t)
			ctx := context.Background()
			if tc.saved != "" {
				if err := st.SetSetting(ctx, "integrations.reputation_mode", tc.saved); err != nil {
					t.Fatal(err)
				}
			}
			mode, enrichment, err := st.InitializeIntegrationSettings(ctx, tc.enabled, tc.ceiling, true)
			if err != nil || mode != tc.want || enrichment != tc.enrichment {
				t.Fatalf("migration = %s,%v,%v; want %s,%v", mode, enrichment, err, tc.want, tc.enrichment)
			}
			marker, err := st.GetSetting(ctx, IntegrationPreferencesVersionKey)
			if err != nil || marker != "1" {
				t.Fatalf("missing durable marker: %q %v", marker, err)
			}
			// Subsequent boots cannot reinterpret already migrated choices from
			// a different YAML initial value.
			mode, enrichment, err = st.InitializeIntegrationSettings(ctx, true, "blocking", true)
			if err != nil || mode != tc.want || enrichment != tc.enrichment {
				t.Fatal("migration was not idempotent")
			}
		})
	}
}

func TestExplicitIntegrationPreferencesSurviveDisabledLegacyConfiguration(t *testing.T) {
	path := t.TempDir() + "/restart.db"
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.SetIntegrationSettings(ctx, "blocking", true); err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mode, enrichment, err := st.InitializeIntegrationSettings(ctx, false, "off", false)
	if err != nil || mode != "blocking" || !enrichment {
		t.Fatalf("explicit new choice lost: %s,%v,%v", mode, enrichment, err)
	}
}

func TestIntegrationPreferencesMigrationFailureIsInertAndAtomic(t *testing.T) {
	st := newProviderStore(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, "integrations.reputation_mode", "blocking"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER reject_ui_preferences BEFORE INSERT ON settings WHEN NEW.key='integrations.ui_preferences_v1' BEGIN SELECT RAISE(ABORT,'fixture migration failure'); END`); err != nil {
		t.Fatal(err)
	}
	mode, enrichment, err := st.InitializeIntegrationSettings(ctx, false, "off", false)
	if err == nil || mode != "off" || enrichment {
		t.Fatalf("failure was not inert: %s,%v,%v", mode, enrichment, err)
	}
	saved, err := st.GetSetting(ctx, "integrations.reputation_mode")
	if err != nil || saved != "blocking" {
		t.Fatal("failed migration partially changed the old record")
	}
	if marker, _ := st.GetSetting(ctx, IntegrationPreferencesVersionKey); marker != "" {
		t.Fatal("failed migration left a marker")
	}
	if err := st.SetIntegrationSettings(ctx, "cache_only", true); err == nil {
		t.Fatal("fixture failed to refuse settings save")
	}
	saved, _ = st.GetSetting(ctx, "integrations.reputation_mode")
	if saved != "blocking" {
		t.Fatal("failed UI write partially changed the mode")
	}
}

func TestInvalidMarkedIntegrationPreferencesNeverGuessSharing(t *testing.T) {
	st := newProviderStore(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, IntegrationPreferencesVersionKey, "1"); err != nil {
		t.Fatal(err)
	}
	mode, enrichment, err := st.InitializeIntegrationSettings(ctx, true, "blocking", true)
	if err == nil || mode != "off" || enrichment {
		t.Fatal("invalid marked preferences fell back to external sharing")
	}
}
