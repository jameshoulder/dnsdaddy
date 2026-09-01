// Package intel joins the external-intelligence pieces together.
//
// It exists so that none of them has to know about the others. internal/store
// is persistence, internal/secrets is cryptography, internal/apiprovider is
// domain logic and internal/policy is the resolver's decision path — and a
// dependency edge between any two of those would be the wrong shape. This
// package is the one place that imports all four, and it is deliberately thin:
// it translates types and opens credentials, and does nothing else.
//
// The single most important thing in here is Source.LoadProviders. It is the
// only function in the entire codebase that produces a plaintext credential,
// which means there is exactly one place to audit for "where could a key
// escape".
package intel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/policy"
	"github.com/jameshoulder/dnsdaddy/internal/secrets"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Source loads provider configuration and opens the sealed credentials.
type Source struct {
	Store   *store.Store
	Keyring *secrets.Keyring
	Log     *slog.Logger
}

// LoadProviders implements apiprovider.ProviderSource.
//
// A credential that cannot be opened is reported on the provider rather than
// dropping it: an operator whose secrets.key is missing must see every
// provider saying "credential could not be opened", not an empty list that
// looks like nothing was ever configured.
func (s *Source) LoadProviders(ctx context.Context) ([]apiprovider.ProviderConfig, error) {
	rows, err := s.Store.ListAPIProviders(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]apiprovider.ProviderConfig, 0, len(rows))
	for _, row := range rows {
		cfg := apiprovider.ProviderConfig{
			ID:              row.ID,
			Name:            row.Name,
			Kind:            row.Kind,
			Enabled:         row.Enabled,
			Capabilities:    row.Capabilities,
			Settings:        row.Config,
			TimeoutMS:       row.TimeoutMS,
			RatePerMinute:   row.RatePerMinute,
			CacheTTLSeconds: row.CacheTTLSeconds,
			PolicyScope:     row.PolicyScope,
		}
		if row.SecretSet {
			secret, err := s.openSecret(ctx, row.ID)
			if err != nil {
				cfg.SecretErr = err
			} else {
				cfg.Secret = secret
			}
		}
		out = append(out, cfg)
	}
	return out, nil
}

// openSecret decrypts one provider's credential.
//
// Kept separate and unexported so the plaintext has the shortest possible
// life: it exists inside LoadProviders' loop, goes straight into the
// InstanceConfig handed to an adapter, and is never returned, logged or
// stored anywhere else.
func (s *Source) openSecret(ctx context.Context, providerID string) (string, error) {
	if s.Keyring == nil || !s.Keyring.Available() {
		if s.Keyring != nil && s.Keyring.Err() != nil {
			return "", s.Keyring.Err()
		}
		return "", secrets.ErrNoKey
	}
	ciphertext, err := s.Store.ProviderSecretCiphertext(ctx, providerID)
	if err != nil {
		return "", err
	}
	plain, err := s.Keyring.Open(ciphertext, providerID)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SealFor encrypts a credential for a provider and stores it.
//
// The mirror of openSecret and the only other function that touches
// plaintext. The caller — an API handler with the operator's input — passes it
// straight through; nothing in between holds it.
func (s *Source) SealFor(ctx context.Context, providerID, secret string) error {
	if s.Keyring == nil || !s.Keyring.Available() {
		if s.Keyring != nil && s.Keyring.Err() != nil {
			return fmt.Errorf("cannot store a credential: %w", s.Keyring.Err())
		}
		return fmt.Errorf("cannot store a credential: %w", secrets.ErrNoKey)
	}
	sealed, err := s.Keyring.Seal([]byte(secret), providerID)
	if err != nil {
		return err
	}
	return s.Store.SetProviderSecret(ctx, providerID, sealed, s.Keyring.KeyID(), secrets.Hint(secret))
}

// VerdictStore persists verdicts and enrichment for the engine.
type VerdictStore struct {
	Store *store.Store
}

// SaveVerdict implements apiprovider.VerdictStore.
func (v *VerdictStore) SaveVerdict(ctx context.Context, subject, providerID string, verdict apiprovider.Verdict, expires time.Time) error {
	return v.Store.PutIntelVerdict(ctx, store.IntelVerdict{
		Subject:     subject,
		ProviderID:  providerID,
		Score:       verdict.Score,
		Disposition: store.Disposition(verdict.Disposition),
		Categories:  verdict.Categories,
		Raw:         verdict.Raw,
		FetchedAt:   time.Now().UTC(),
		ExpiresAt:   expires,
	})
}

// LoadVerdict implements apiprovider.VerdictStore.
func (v *VerdictStore) LoadVerdict(ctx context.Context, subject, providerID string) (apiprovider.Verdict, time.Time, error) {
	row, err := v.Store.IntelVerdict(ctx, subject, providerID)
	if err != nil {
		return apiprovider.Verdict{}, time.Time{}, err
	}
	return apiprovider.Verdict{
		Score:       row.Score,
		Disposition: apiprovider.Disposition(row.Disposition),
		Categories:  row.Categories,
		Raw:         row.Raw,
	}, row.ExpiresAt, nil
}

// SaveEnrichment implements apiprovider.VerdictStore.
func (v *VerdictStore) SaveEnrichment(ctx context.Context, subject, providerID string, e apiprovider.Enrichment, expires time.Time) error {
	return v.Store.PutIntelEnrichment(ctx, store.IntelEnrichment{
		Subject:    subject,
		ProviderID: providerID,
		Data:       e.Data,
		FetchedAt:  time.Now().UTC(),
		ExpiresAt:  expires,
	})
}

// Consultant adapts the engine to what internal/policy asks for.
//
// The translation is one struct copy, and it is here rather than in either
// package because both would otherwise need the other's vocabulary: policy
// would need to know what a Disposition is, or apiprovider would need to know
// what a policy Decision looks like.
type Consultant struct {
	Engine *apiprovider.Engine
	// Threshold is the score at or above which a merely suspicious verdict is
	// treated as a block. Defaults to 1 — never — so only an explicit
	// malicious verdict blocks unless an operator asks otherwise.
	Threshold float64
}

// Consult implements policy.Reputation.
func (c *Consultant) Consult(ctx context.Context, policyID, domain string) (policy.ReputationVerdict, bool) {
	if c == nil || c.Engine == nil {
		return policy.ReputationVerdict{}, false
	}
	res, ok := apiprovider.PolicyConsultant{Engine: c.Engine, Threshold: c.Threshold}.
		Consult(ctx, policyID, domain)
	if !ok {
		return policy.ReputationVerdict{}, false
	}
	return policy.ReputationVerdict{
		Malicious:    res.Malicious,
		Score:        res.Score,
		Category:     res.Category,
		ProviderName: res.ProviderName,
	}, true
}

// Compile-time proof that the adapters satisfy what they claim to. Without
// these, a signature drifting is a runtime nil interface three layers away
// from the change that caused it.
var (
	_ apiprovider.ProviderSource = (*Source)(nil)
	_ apiprovider.VerdictStore   = (*VerdictStore)(nil)
	_ policy.Reputation          = (*Consultant)(nil)
)
