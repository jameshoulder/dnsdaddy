package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newProviderStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestProviderCRUD(t *testing.T) {
	ctx := context.Background()
	st := newProviderStore(t)

	created, err := st.CreateAPIProvider(ctx, APIProvider{
		Name:         "VirusTotal",
		Kind:         "virustotal",
		Enabled:      true,
		Capabilities: []string{"reputation"},
		Config:       map[string]string{"endpoint": "https://example.test/api"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("no id was assigned")
	}

	got, err := st.GetAPIProvider(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "VirusTotal" || got.Kind != "virustotal" || !got.Enabled {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if got.Config["endpoint"] != "https://example.test/api" {
		t.Errorf("config did not survive: %+v", got.Config)
	}
	if got.SecretSet {
		t.Error("a provider with no credential reports one is set")
	}

	name := "VT (production)"
	enabled := false
	updated, err := st.UpdateAPIProvider(ctx, created.ID, APIProviderUpdate{
		Name: &name, Enabled: &enabled,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != name || updated.Enabled {
		t.Errorf("update did not apply: %+v", updated)
	}
	// Unmentioned fields survive.
	if len(updated.Capabilities) != 1 || updated.Capabilities[0] != "reputation" {
		t.Errorf("a field nobody mentioned was changed: %+v", updated.Capabilities)
	}

	if err := st.DeleteAPIProvider(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetAPIProvider(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete returned %v, want ErrNotFound", err)
	}
	if err := st.DeleteAPIProvider(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice returned %v, want ErrNotFound", err)
	}
}

// The bounds arrive from a dashboard form. An operator who types something
// absurd should get a working provider, not an error — but must not be able to
// make one hold a worker for five minutes.
func TestProviderBoundsAreClamped(t *testing.T) {
	ctx := context.Background()
	st := newProviderStore(t)

	p, err := st.CreateAPIProvider(ctx, APIProvider{
		Name: "hostile", Kind: "customhttp",
		TimeoutMS: 300000, RatePerMinute: 1 << 30, CacheTTLSeconds: 1 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.TimeoutMS != maxProviderTimeoutMS {
		t.Errorf("timeout %d, want it clamped to %d", p.TimeoutMS, maxProviderTimeoutMS)
	}
	if p.RatePerMinute != maxProviderRatePerMinute {
		t.Errorf("rate %d, want it clamped to %d", p.RatePerMinute, maxProviderRatePerMinute)
	}
	if p.CacheTTLSeconds != maxProviderCacheTTLSecond {
		t.Errorf("ttl %d, want it clamped to %d", p.CacheTTLSeconds, maxProviderCacheTTLSecond)
	}

	// Zero means "use the default", not "no timeout at all".
	d, err := st.CreateAPIProvider(ctx, APIProvider{Name: "defaults", Kind: "customhttp"})
	if err != nil {
		t.Fatal(err)
	}
	if d.TimeoutMS != DefaultProviderTimeoutMS || d.RatePerMinute != DefaultProviderRate {
		t.Errorf("defaults not applied: timeout=%d rate=%d", d.TimeoutMS, d.RatePerMinute)
	}
}

func TestProviderRequiresNameAndKind(t *testing.T) {
	ctx := context.Background()
	st := newProviderStore(t)

	if _, err := st.CreateAPIProvider(ctx, APIProvider{Kind: "virustotal"}); !errors.Is(err, ErrProviderNameRequired) {
		t.Errorf("nameless provider: %v", err)
	}
	if _, err := st.CreateAPIProvider(ctx, APIProvider{Name: "x"}); !errors.Is(err, ErrProviderKindRequired) {
		t.Errorf("kindless provider: %v", err)
	}
	// Whitespace is not a name.
	if _, err := st.CreateAPIProvider(ctx, APIProvider{Name: "   ", Kind: "virustotal"}); !errors.Is(err, ErrProviderNameRequired) {
		t.Errorf("whitespace name: %v", err)
	}
}

// The whole point of the two-table split: reading a provider can never produce
// a credential, whatever the caller does with the result.
func TestProviderStructCarriesNoCredential(t *testing.T) {
	ctx := context.Background()
	st := newProviderStore(t)

	p, err := st.CreateAPIProvider(ctx, APIProvider{Name: "vt", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	const ciphertext = "\x01\x02sealed-bytes-not-a-real-credential"
	if err := st.SetProviderSecret(ctx, p.ID, []byte(ciphertext), "kdeadbeef", "abcd"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	got, err := st.GetAPIProvider(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SecretSet {
		t.Error("a stored credential is not reported as set")
	}
	if got.SecretHint != "abcd" {
		t.Errorf("hint is %q, want %q", got.SecretHint, "abcd")
	}
	if got.RotatedAt != nil {
		t.Error("a first write reports itself as a rotation")
	}

	// There is no field on the struct that could hold it. Checked by encoding
	// the whole thing, which is what an accidental disclosure would go
	// through — a log line, a JSON response, a debug dump.
	if containsBytes(t, got, ciphertext) {
		t.Error("the provider struct serialises its ciphertext")
	}

	// Rotation records itself.
	if err := st.SetProviderSecret(ctx, p.ID, []byte("second"), "kdeadbeef", "wxyz"); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetAPIProvider(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RotatedAt == nil {
		t.Error("a rotation did not record when it happened")
	}
	if got.SecretHint != "wxyz" {
		t.Errorf("hint after rotation is %q, want %q", got.SecretHint, "wxyz")
	}
	ct, err := st.ProviderSecretCiphertext(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) != "second" {
		t.Errorf("rotation did not replace the ciphertext: %q", ct)
	}
}

func TestEmptyCiphertextIsRefused(t *testing.T) {
	ctx := context.Background()
	st := newProviderStore(t)
	p, err := st.CreateAPIProvider(ctx, APIProvider{Name: "vt", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	// An empty ciphertext is what a failed seal looks like. Storing it would
	// leave a provider that reports a credential is set and has none.
	if err := st.SetProviderSecret(ctx, p.ID, nil, "k1", ""); err == nil {
		t.Error("an empty credential was stored")
	}
}

// Deleting a provider must take its credential and cached answers with it.
// A ciphertext outliving the row it belonged to is a credential nobody can see
// in the UI and nobody will think to remove.
func TestDeletingAProviderRemovesItsSecretAndCache(t *testing.T) {
	ctx := context.Background()
	st := newProviderStore(t)

	p, err := st.CreateAPIProvider(ctx, APIProvider{Name: "vt", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProviderSecret(ctx, p.ID, []byte("sealed"), "k1", "abcd"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.PutIntelVerdict(ctx, IntelVerdict{
		Subject: "evil.example", ProviderID: p.ID, Score: 0.9,
		Disposition: DispositionMalicious, FetchedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutIntelEnrichment(ctx, IntelEnrichment{
		Subject: "evil.example", ProviderID: p.ID,
		Data: map[string]string{"registrar": "Example Registrar"}, FetchedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteAPIProvider(ctx, p.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := st.ProviderSecretCiphertext(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the credential outlived its provider: %v", err)
	}
	vs, err := st.IntelVerdicts(ctx, "evil.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Errorf("%d cached verdicts outlived their provider", len(vs))
	}
	es, err := st.IntelEnrichments(ctx, "evil.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 0 {
		t.Errorf("%d cached enrichments outlived their provider", len(es))
	}
}

// containsBytes marshals v the two ways an accidental disclosure actually
// happens — JSON encoding into a response, and %+v into a log line — and
// reports whether needle appears in either.
func containsBytes(t *testing.T, v any, needle string) bool {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return strings.Contains(string(encoded), needle) ||
		strings.Contains(fmt.Sprintf("%+v", v), needle)
}
