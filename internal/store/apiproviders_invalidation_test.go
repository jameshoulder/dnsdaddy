package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type providerCacheMutation struct {
	name       string
	hadSecret  bool
	apply      func(context.Context, *Store, string) error
	assertDone func(*testing.T, *Store, string)
}

func providerCacheMutations() []providerCacheMutation {
	return []providerCacheMutation{
		{
			name: "endpoint change", hadSecret: true,
			apply: func(ctx context.Context, st *Store, id string) error {
				cfg := map[string]string{"url": "https://replacement.example/lookup"}
				_, err := st.UpdateAPIProvider(ctx, id, APIProviderUpdate{Config: &cfg})
				return err
			},
			assertDone: func(t *testing.T, st *Store, id string) {
				p, err := st.GetAPIProvider(context.Background(), id)
				if err != nil || p.Config["url"] != "https://replacement.example/lookup" {
					t.Fatalf("endpoint change did not survive restart: %+v, %v", p, err)
				}
			},
		},
		{
			name: "disable", hadSecret: true,
			apply: func(ctx context.Context, st *Store, id string) error {
				enabled := false
				_, err := st.UpdateAPIProvider(ctx, id, APIProviderUpdate{Enabled: &enabled})
				return err
			},
			assertDone: func(t *testing.T, st *Store, id string) {
				p, err := st.GetAPIProvider(context.Background(), id)
				if err != nil || p.Enabled {
					t.Fatalf("disable did not survive restart: %+v, %v", p, err)
				}
			},
		},
		{
			name: "install credential",
			apply: func(ctx context.Context, st *Store, id string) error {
				return st.SetProviderSecret(ctx, id, []byte("new-sealed-fixture"), "new-key", "hint")
			},
			assertDone: assertNewProviderSecret,
		},
		{
			name: "rotate credential", hadSecret: true,
			apply: func(ctx context.Context, st *Store, id string) error {
				return st.SetProviderSecret(ctx, id, []byte("new-sealed-fixture"), "new-key", "hint")
			},
			assertDone: assertNewProviderSecret,
		},
		{
			name: "delete credential", hadSecret: true,
			apply: func(ctx context.Context, st *Store, id string) error {
				return st.DeleteProviderSecret(ctx, id)
			},
			assertDone: func(t *testing.T, st *Store, id string) {
				if _, err := st.ProviderSecretCiphertext(context.Background(), id); !errors.Is(err, ErrNotFound) {
					t.Fatalf("credential revocation did not survive restart: %v", err)
				}
			},
		},
	}
}

func assertNewProviderSecret(t *testing.T, st *Store, id string) {
	t.Helper()
	ct, err := st.ProviderSecretCiphertext(context.Background(), id)
	if err != nil || string(ct) != "new-sealed-fixture" {
		t.Fatalf("credential change did not survive restart: %q, %v", ct, err)
	}
}

func seedInvalidationProvider(t *testing.T, st *Store, hadSecret bool) APIProvider {
	t.Helper()
	ctx := context.Background()
	p, err := st.CreateAPIProvider(ctx, APIProvider{
		Name: "Fixture provider", Kind: "customhttp", Enabled: true,
		Capabilities: []string{"reputation"}, Config: map[string]string{"url": "https://original.example/lookup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hadSecret {
		if err := st.SetProviderSecret(ctx, p.ID, []byte("old-sealed-fixture"), "old-key", "old"); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func seedInvalidationEvidence(t *testing.T, st *Store, id, subject string, expires time.Time) (IntelVerdict, IntelEnrichment) {
	t.Helper()
	ctx := context.Background()
	fetched := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	if err := st.PutIntelVerdict(ctx, IntelVerdict{
		Subject: subject, ProviderID: id, Score: .91, Disposition: DispositionMalicious,
		Categories: []string{"fixture"}, Raw: `{"original":"provider evidence"}`,
		FetchedAt: fetched, ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutIntelEnrichment(ctx, IntelEnrichment{
		Subject: subject, ProviderID: id, Data: map[string]string{"source": "original enrichment"},
		FetchedAt: fetched, ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	v, err := st.IntelVerdict(ctx, subject, id)
	if err != nil {
		t.Fatal(err)
	}
	return v, invalidationEnrichment(t, st, id, subject)
}

func invalidationEnrichment(t *testing.T, st *Store, id, subject string) IntelEnrichment {
	t.Helper()
	rows, err := st.IntelEnrichments(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ProviderID == id {
			return row
		}
	}
	t.Fatalf("original enrichment disappeared for %s", id)
	return IntelEnrichment{}
}

func TestProviderCacheInvalidationSurvivesRestartAndPreservesEvidence(t *testing.T) {
	for _, mutation := range providerCacheMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "provider-cache.db")
			st, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if st != nil {
					_ = st.Close()
				}
			})
			target := seedInvalidationProvider(t, st, mutation.hadSecret)
			other := seedInvalidationProvider(t, st, true)
			expires := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
			original, originalEnrichment := seedInvalidationEvidence(t, st, target.ID, "retired.example", expires)
			unrelated, unrelatedEnrichment := seedInvalidationEvidence(t, st, other.ID, "retired.example", expires)
			alreadyExpired, alreadyExpiredEnrichment := seedInvalidationEvidence(t, st, target.ID, "old.example", expires.Add(-2*time.Hour))
			fresh, err := st.FreshIntelVerdicts(ctx, time.Now(), 100)
			if err != nil || len(fresh) != 2 {
				t.Fatalf("positive control: got %d fresh entries, %v", len(fresh), err)
			}
			before := time.Now().UTC().Truncate(time.Millisecond)
			if err := mutation.apply(ctx, st, target.ID); err != nil {
				t.Fatal(err)
			}
			after := time.Now().UTC()
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			mutation.assertDone(t, st, target.ID)
			fresh, err = st.FreshIntelVerdicts(ctx, time.Now(), 100)
			if err != nil || len(fresh) != 1 || fresh[0].ProviderID != other.ID {
				t.Fatalf("restart would restore an invalidated verdict, or lost unrelated cache: %+v, %v", fresh, err)
			}
			retired, err := st.IntelVerdict(ctx, original.Subject, target.ID)
			if err != nil {
				t.Fatal(err)
			}
			if retired.ExpiresAt.Before(before) || retired.ExpiresAt.After(after) || retired.Fresh(time.Now()) {
				t.Fatalf("cache did not expire at its configuration change: %v", retired.ExpiresAt)
			}
			retired.ExpiresAt = original.ExpiresAt
			if !reflect.DeepEqual(retired, original) {
				t.Fatalf("expiry changed original verdict evidence: got %+v, want %+v", retired, original)
			}
			enrichment := invalidationEnrichment(t, st, target.ID, original.Subject)
			if enrichment.ExpiresAt.Before(before) || enrichment.ExpiresAt.After(after) {
				t.Fatalf("enrichment did not expire at its configuration change: %v", enrichment.ExpiresAt)
			}
			enrichment.ExpiresAt = originalEnrichment.ExpiresAt
			if !reflect.DeepEqual(enrichment, originalEnrichment) {
				t.Fatal("expiry changed original enrichment evidence")
			}
			for _, expected := range []IntelVerdict{unrelated, alreadyExpired} {
				got, err := st.IntelVerdict(ctx, expected.Subject, expected.ProviderID)
				if err != nil || !reflect.DeepEqual(got, expected) {
					t.Fatalf("unrelated or already expired verdict changed: %+v, %v", got, err)
				}
			}
			for _, expected := range []IntelEnrichment{unrelatedEnrichment, alreadyExpiredEnrichment} {
				got := invalidationEnrichment(t, st, expected.ProviderID, expected.Subject)
				if !reflect.DeepEqual(got, expected) {
					t.Fatalf("unrelated or already expired enrichment changed: %+v", got)
				}
			}
		})
	}
}

func TestProviderCacheInvalidationFailureRollsBackMutation(t *testing.T) {
	for _, mutation := range providerCacheMutations() {
		t.Run(mutation.name, func(t *testing.T) {
			ctx := context.Background()
			st := newProviderStore(t)
			target := seedInvalidationProvider(t, st, mutation.hadSecret)
			original, originalEnrichment := seedInvalidationEvidence(t, st, target.ID, "retired.example", time.Now().Add(time.Hour))
			providerBefore, err := st.GetAPIProvider(ctx, target.ID)
			if err != nil {
				t.Fatal(err)
			}
			// Reject the second cache write: the first expiry and the provider or
			// credential mutation must both roll back, not merely the failing row.
			if _, err := st.db.ExecContext(ctx, `CREATE TRIGGER test_refuse_cache_expiry
				BEFORE UPDATE OF expires_at ON intel_enrichment BEGIN
				SELECT RAISE(ABORT, 'injected cache expiry failure'); END`); err != nil {
				t.Fatal(err)
			}
			if err := mutation.apply(ctx, st, target.ID); err == nil {
				t.Fatal("mutation succeeded despite cache invalidation failure")
			}
			providerAfter, err := st.GetAPIProvider(ctx, target.ID)
			if err != nil || !reflect.DeepEqual(providerAfter, providerBefore) {
				t.Fatalf("failed invalidation changed provider metadata: %+v, %v", providerAfter, err)
			}
			ct, err := st.ProviderSecretCiphertext(ctx, target.ID)
			if mutation.hadSecret {
				if err != nil || string(ct) != "old-sealed-fixture" {
					t.Fatalf("failed invalidation changed credential: %q, %v", ct, err)
				}
			} else if !errors.Is(err, ErrNotFound) {
				t.Fatalf("failed invalidation installed a credential: %v", err)
			}
			verdict, err := st.IntelVerdict(ctx, original.Subject, target.ID)
			if err != nil || !reflect.DeepEqual(verdict, original) {
				t.Fatalf("failed mutation changed cached verdict: %+v, %v", verdict, err)
			}
			if got := invalidationEnrichment(t, st, target.ID, original.Subject); !reflect.DeepEqual(got, originalEnrichment) {
				t.Fatalf("failed mutation changed enrichment: %+v", got)
			}
		})
	}
}
