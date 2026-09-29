package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigAuditPersistsActualChangesAndHidesSecrets(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.EnsureAuditSchema(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateAPIProvider(ctx, APIProvider{Name: "Public provider label", Kind: "customhttp", Config: map[string]string{"endpoint": "https://api.example/?key=never-disclose-this"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProviderSecret(ctx, p.ID, []byte("sealed-secret-do-not-disclose"), "key-id", "hide"); err != nil {
		t.Fatal(err)
	}
	before, err := st.CaptureConfig(ctx, AuditScope{Kind: "provider", ID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.BeginConfigChange(ctx, "session:admin", "patch", "provider/"+p.ID)
	if err != nil {
		t.Fatal(err)
	}
	newName := "Renamed provider"
	cfg := map[string]string{"endpoint": "https://api.example/?key=another-secret-value"}
	if _, err := st.UpdateAPIProvider(ctx, p.ID, APIProviderUpdate{Name: &newName, Config: &cfg}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetProviderSecret(ctx, p.ID, []byte("rotated-secret-do-not-disclose"), "key-id", "hide"); err != nil {
		t.Fatal(err)
	}
	after, err := st.CaptureConfig(ctx, AuditScope{Kind: "provider", ID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	diff := DiffConfig(before, after)
	if len(diff) != 3 {
		t.Fatalf("expected exact name, config, credential changes: %+v", diff)
	}
	if err := st.CompleteConfigChange(ctx, id, "complete", 200, diff, ""); err != nil {
		t.Fatal(err)
	}
	events, more, err := st.ListConfigChanges(ctx, 0, 50)
	if err != nil || more || len(events) != 1 {
		t.Fatalf("list: %+v %v %v", events, more, err)
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"never-disclose-this", "another-secret-value", "sealed-secret-do-not-disclose", "rotated-secret-do-not-disclose"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret in audit: %s", secret)
		}
	}
	if !strings.Contains(string(raw), "Renamed provider") || !strings.Contains(string(raw), "[redacted]") {
		t.Fatal("missing real change or redaction")
	}
}

func TestConfigAuditCursorDoesNotLoseRowsWithNewWrites(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.EnsureAuditSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := st.BeginConfigChange(ctx, "session:admin", "patch", "policy/test"); err != nil {
			t.Fatal(err)
		}
	}
	first, more, err := st.ListConfigChanges(ctx, 0, 2)
	if err != nil || !more || len(first) != 2 {
		t.Fatalf("first page: %v", err)
	}
	if _, err := st.BeginConfigChange(ctx, "session:admin", "post", "policy/new"); err != nil {
		t.Fatal(err)
	}
	second, more, err := st.ListConfigChanges(ctx, first[1].ID, 2)
	if err != nil || !more || len(second) != 2 {
		t.Fatalf("second page: %v", err)
	}
	last, more, err := st.ListConfigChanges(ctx, second[1].ID, 2)
	if err != nil || more || len(last) != 1 {
		t.Fatalf("last page: %v", err)
	}
	if first[0].ID != 5 || first[1].ID != 4 || second[0].ID != 3 || second[1].ID != 2 || last[0].ID != 1 {
		t.Fatal("cursor skipped or duplicated a row")
	}
	if _, _, err := st.ListConfigChanges(ctx, -1, 50); err == nil {
		t.Fatal("accepted negative cursor")
	}
}

func TestConfigAuditIgnoresOperationalFeedTimestamps(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	before, err := st.CaptureConfig(ctx, AuditScope{Kind: "feed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec("UPDATE feeds SET last_refreshed_at=999999,domain_count=1234,last_status='success',last_error='',updated_at=999999"); err != nil {
		t.Fatal(err)
	}
	after, err := st.CaptureConfig(ctx, AuditScope{Kind: "feed"})
	if err != nil {
		t.Fatal(err)
	}
	if got := DiffConfig(before, after); len(got) != 0 {
		t.Fatalf("attributed background refresh to operator: %+v", got)
	}
}

func TestConfigAuditSecretSettingsHaveNoHashOrValue(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	scope := AuditScope{Kind: "settings", ID: "admin_password_hash"}
	if err := st.SetSetting(ctx, scope.ID, "old-secret-hash"); err != nil {
		t.Fatal(err)
	}
	before, err := st.CaptureConfig(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, scope.ID, "new-secret-hash"); err != nil {
		t.Fatal(err)
	}
	after, err := st.CaptureConfig(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	diff := DiffConfig(before, after)
	raw, _ := json.Marshal(diff)
	if strings.Contains(string(raw), "secret-hash") || len(diff) != 1 || !diff[0].Redacted {
		t.Fatalf("password history leak: %s", raw)
	}
}

func TestConfigAuditDetectsBinaryCredentialChangesWithoutUTF8Loss(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	p, err := st.CreateAPIProvider(ctx, APIProvider{Name: "Binary credential", Kind: "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProviderSecret(ctx, p.ID, []byte{0xff}, "kfixture", ""); err != nil {
		t.Fatal(err)
	}
	before, err := st.CaptureConfig(ctx, AuditScope{Kind: "provider", ID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProviderSecret(ctx, p.ID, []byte{0xfe}, "kfixture", ""); err != nil {
		t.Fatal(err)
	}
	after, err := st.CaptureConfig(ctx, AuditScope{Kind: "provider", ID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	changes := DiffConfig(before, after)
	if len(changes) != 1 || !changes[0].Redacted {
		t.Fatalf("binary credential change disappeared: %+v", changes)
	}
}

func TestConfigAuditComparesEffectiveRuleIdentityNotRowNumber(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	policies, err := st.ListPolicies(ctx)
	if err != nil || len(policies) == 0 {
		t.Fatal(err)
	}
	id := policies[0].ID
	if _, err := st.DB().Exec("INSERT INTO policy_rules(id,policy_id,kind,domain,note,created_at) VALUES(100,?,'block','example.test','operator note',0)", id); err != nil {
		t.Fatal(err)
	}
	before, err := st.CaptureConfig(ctx, AuditScope{Kind: "policy", ID: id})
	if err != nil {
		t.Fatal(err)
	}
	// Rebuilding an equivalent rule must not look like an effective policy
	// edit simply because SQLite assigned it a different row number.
	if _, err := st.DB().Exec("UPDATE policy_rules SET id=101 WHERE id=100"); err != nil {
		t.Fatal(err)
	}
	after, err := st.CaptureConfig(ctx, AuditScope{Kind: "policy", ID: id})
	if err != nil {
		t.Fatal(err)
	}
	if changes := DiffConfig(before, after); len(changes) != 0 {
		t.Fatalf("row renumbering looked like a policy change: %+v", changes)
	}
}
