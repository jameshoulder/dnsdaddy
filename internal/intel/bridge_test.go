package intel

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	// Registers the built-in adapters, exactly as the composition root does.
	// Without them BuildInstances cannot tell a broken provider from an
	// unknown one, and the tests below would be asserting the wrong failure.
	_ "github.com/jameshoulder/dnsdaddy/internal/apiprovider/adapters"
	"github.com/jameshoulder/dnsdaddy/internal/secrets"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

func newSource(t *testing.T) *Source {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	kr, err := secrets.Open(dir)
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	return &Source{Store: st, Keyring: kr}
}

// mustProvider creates a provider row. The intel tables reference it by
// foreign key, so a verdict cannot exist without one.
func mustProvider(t *testing.T, s *Source) store.APIProvider {
	t.Helper()
	p, err := s.Store.CreateAPIProvider(context.Background(), store.APIProvider{
		Name: "Test Provider", Kind: "custom_http", Enabled: true,
		Config: map[string]string{"url": "https://example.test/lookup"},
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	return p
}

const testSecret = "vt-live-key-8f3a2b1c9d0e"

// The round trip an operator's credential actually takes: typed into the
// dashboard, sealed, written to SQLite, read back at startup, handed to an
// adapter. If any link loses or corrupts it, every provider silently stops
// authenticating.
func TestACredentialSurvivesTheRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)

	p, err := s.Store.CreateAPIProvider(ctx, store.APIProvider{
		Name: "VirusTotal", Kind: "virustotal", Enabled: true,
		Capabilities: []string{"reputation"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SealFor(ctx, p.ID, testSecret); err != nil {
		t.Fatalf("seal: %v", err)
	}

	configs, err := s.LoadProviders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d providers, want 1", len(configs))
	}
	if configs[0].SecretErr != nil {
		t.Fatalf("secret could not be opened: %v", configs[0].SecretErr)
	}
	if configs[0].Secret != testSecret {
		t.Errorf("credential came back as %q", configs[0].Secret)
	}
}

// What is written to disk must not be the credential. This is the entire
// promise of "encrypted at rest": somebody with a copy of the database file
// and no key file has nothing.
func TestTheStoredBytesAreNotThePlaintext(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)

	p, err := s.Store.CreateAPIProvider(ctx, store.APIProvider{Name: "VT", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SealFor(ctx, p.ID, testSecret); err != nil {
		t.Fatal(err)
	}

	sealed, err := s.Store.ProviderSecretCiphertext(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(testSecret)) {
		t.Fatal("the credential is sitting in the database in plaintext")
	}
	if len(sealed) == 0 {
		t.Fatal("nothing was stored")
	}

	// The hint is the only part an operator ever sees again, and it must be a
	// tail short enough to be useless on its own.
	got, err := s.Store.GetAPIProvider(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SecretSet {
		t.Error("a provider with a stored credential reports none")
	}
	if got.SecretHint == "" {
		t.Error("no hint was recorded; an operator cannot tell which key is installed")
	}
	if len(got.SecretHint) >= len(testSecret) {
		t.Errorf("hint %q is as long as the credential", got.SecretHint)
	}
}

// A credential sealed for one provider must not open as another. Without the
// provider ID as additional authenticated data, moving a row's ciphertext to a
// different provider — a database edit, a restore, a bug in an update path —
// would hand that provider somebody else's key.
func TestACredentialDoesNotOpenUnderAnotherProvidersIdentity(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)

	a, err := s.Store.CreateAPIProvider(ctx, store.APIProvider{Name: "A", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Store.CreateAPIProvider(ctx, store.APIProvider{Name: "B", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SealFor(ctx, a.ID, testSecret); err != nil {
		t.Fatal(err)
	}

	sealed, err := s.Store.ProviderSecretCiphertext(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Transplant A's ciphertext onto B, exactly as a hand-edited database
	// would.
	if err := s.Store.SetProviderSecret(ctx, b.ID, sealed, s.Keyring.KeyID(), "xxxx"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.openSecret(ctx, b.ID); err == nil {
		t.Fatal("a transplanted credential opened under the wrong provider")
	}
}

// A key file that is missing or unreadable must not make providers disappear.
// An operator who restored a database without its key needs to see every
// provider saying so, not a configuration page that looks empty.
func TestAProviderWithAnUnopenableCredentialStillAppears(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)

	p, err := s.Store.CreateAPIProvider(ctx, store.APIProvider{
		Name: "VirusTotal", Kind: "virustotal", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SealFor(ctx, p.ID, testSecret); err != nil {
		t.Fatal(err)
	}

	// A different key: the same situation as a lost secrets.key.
	other, err := secrets.OpenWithKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.Keyring = other

	configs, err := s.LoadProviders(ctx)
	if err != nil {
		t.Fatalf("LoadProviders failed outright: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d providers, want the broken one to still be listed", len(configs))
	}
	if configs[0].SecretErr == nil {
		t.Fatal("a credential opened under the wrong key")
	}
	if configs[0].Secret != "" {
		t.Errorf("a failed decryption still produced a credential: %q", configs[0].Secret)
	}

	// And the instance built from it must be unusable and say why, rather than
	// being handed to an adapter with an empty key.
	insts := apiprovider.BuildInstances(configs, nil)
	if len(insts) != 1 {
		t.Fatalf("got %d instances", len(insts))
	}
	if insts[0].Usable() {
		t.Fatal("a provider with no openable credential was marked usable")
	}
	if !errors.Is(insts[0].Err, apiprovider.ErrNoCredential) {
		t.Errorf("Err = %v, want it to name the missing credential", insts[0].Err)
	}
}

// Storing a credential with no key must fail loudly. Falling back to plaintext
// would be the worst possible outcome and is the failure mode worth a test of
// its own.
func TestSealingWithoutAKeyFails(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)
	p, err := s.Store.CreateAPIProvider(ctx, store.APIProvider{Name: "X", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	s.Keyring = nil

	if err := s.SealFor(ctx, p.ID, testSecret); err == nil {
		t.Fatal("a credential was accepted with no encryption key")
	}
	if _, err := s.Store.ProviderSecretCiphertext(ctx, p.ID); err == nil {
		t.Fatal("something was written despite the failure")
	}
}

func TestVerdictRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)
	vs := &VerdictStore{Store: s.Store}
	p := mustProvider(t, s)

	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	in := apiprovider.Verdict{
		Score:       0.9,
		Disposition: apiprovider.DispositionMalicious,
		Categories:  []string{"malware", "phishing"},
		Raw:         `{"engines":9}`,
	}
	if err := vs.SaveVerdict(ctx, "bad.example", p.ID, in, expires); err != nil {
		t.Fatal(err)
	}

	fresh, err := vs.FreshVerdicts(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 1 {
		t.Fatalf("got %d fresh verdicts, want 1", len(fresh))
	}
	out := fresh[0]
	if out.Subject != "bad.example" || out.ProviderID != p.ID {
		t.Errorf("verdict came back for the wrong subject or provider: %+v", out)
	}
	if out.Verdict.Disposition != apiprovider.DispositionMalicious {
		t.Errorf("disposition = %q", out.Verdict.Disposition)
	}
	if out.Verdict.Score != 0.9 {
		t.Errorf("score = %v", out.Verdict.Score)
	}
	if len(out.Verdict.Categories) != 2 || out.Verdict.Categories[0] != "malware" {
		t.Errorf("categories = %v", out.Verdict.Categories)
	}
	if !out.ExpiresAt.Equal(expires) {
		t.Errorf("expiry = %s, want %s", out.ExpiresAt, expires)
	}
}

// An expired verdict must not be warmed back into memory. It is the whole
// reason the row carries an expiry: a stale verdict blocking a name is worse
// than no verdict, because nobody would stand behind the evidence today.
func TestExpiredVerdictsAreNotReturnedForWarming(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)
	vs := &VerdictStore{Store: s.Store}
	p := mustProvider(t, s)

	if err := vs.SaveVerdict(ctx, "stale.example", p.ID,
		apiprovider.Verdict{Score: 1, Disposition: apiprovider.DispositionMalicious},
		time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := vs.SaveVerdict(ctx, "fresh.example", p.ID,
		apiprovider.Verdict{Score: 1, Disposition: apiprovider.DispositionMalicious},
		time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	fresh, err := vs.FreshVerdicts(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 1 {
		t.Fatalf("got %d verdicts, want only the unexpired one: %+v", len(fresh), fresh)
	}
	if fresh[0].Subject != "fresh.example" {
		t.Errorf("warming offered %q, want only the unexpired verdict", fresh[0].Subject)
	}
}

func TestEnrichmentRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newSource(t)
	vs := &VerdictStore{Store: s.Store}
	p := mustProvider(t, s)

	err := vs.SaveEnrichment(ctx, "example.com", p.ID,
		apiprovider.Enrichment{Data: map[string]string{"registrar": "Example Registrar"}},
		time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.Store.IntelEnrichments(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Data["registrar"] != "Example Registrar" {
		t.Fatalf("enrichment did not survive: %+v", rows)
	}
}

// The consultant must not answer when there is nothing behind it. A nil engine
// reaching the policy path as a non-answer is the difference between "no
// providers configured" and a panic in the resolver.
func TestAConsultantWithNoEngineDoesNotAnswer(t *testing.T) {
	var c *Consultant
	if _, ok := c.Consult(context.Background(), "p_standard", "example.com"); ok {
		t.Error("a nil consultant answered")
	}
	c = &Consultant{}
	if _, ok := c.Consult(context.Background(), "p_standard", "example.com"); ok {
		t.Error("a consultant with no engine answered")
	}
}
