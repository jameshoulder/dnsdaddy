package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/secrets"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

const fixtureSigningSecret = "fixture-signing-secret-0123456789abcdef"

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func setupWebhook(t *testing.T, enabled bool, maxQueue int) (*store.Store, *secrets.Keyring, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dnsdaddy.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	kr, err := secrets.OpenWithKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := kr.Seal([]byte(fixtureSigningSecret), SecretIdentity)
	if err != nil {
		t.Fatal(err)
	}
	c, err := st.GetWebhookConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.Enabled, c.URL, c.SecretSet, c.MaxQueue = enabled, "https://receiver.example/events", true, maxQueue
	if err := st.SaveWebhookConfig(context.Background(), c, ciphertext, kr.KeyID(), "cdef", true); err != nil {
		t.Fatal(err)
	}
	return st, kr, path
}

func addFindings(t *testing.T, st *store.Store, ids ...string) {
	t.Helper()
	var rows []store.Finding
	for _, id := range ids {
		rows = append(rows, store.Finding{ID: id, Time: time.Now(), EventType: "dns.beaconing", Severity: "medium", Domain: "test.example", ClientIP: "10.0.0.2", Detector: "fixture", Title: "Fixture finding", Detail: `{"synthetic":true}`})
	}
	if err := st.InsertFindings(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
}

func waitStats(t *testing.T, st *store.Store, predicate func(store.WebhookStats) bool) store.WebhookStats {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		stats, err := st.GetWebhookStats(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if predicate(stats) {
			return stats
		}
		time.Sleep(10 * time.Millisecond)
	}
	stats, _ := st.GetWebhookStats(context.Background())
	t.Fatalf("webhook outcome did not arrive: %+v", stats)
	return stats
}

func TestDisabledWebhookCapturesNothing(t *testing.T) {
	st, _, _ := setupWebhook(t, false, 2)
	addFindings(t, st, "before-opt-in")
	stats, err := st.GetWebhookStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.QueueDepth != 0 || stats.Queued != 0 {
		t.Fatalf("disabled outbox captured events: %+v", stats)
	}
	c, _ := st.GetWebhookConfig(context.Background())
	c.Enabled = true
	if err := st.SaveWebhookConfig(context.Background(), c, nil, "", "", false); err != nil {
		t.Fatal(err)
	}
	stats, _ = st.GetWebhookStats(context.Background())
	if stats.QueueDepth != 0 {
		t.Fatal("enabling backfilled historical events")
	}
	addFindings(t, st, "after-opt-in")
	stats, _ = st.GetWebhookStats(context.Background())
	if stats.QueueDepth != 1 {
		t.Fatalf("new enabled event missing: %+v", stats)
	}
}

func TestBoundedOutboxSurvivesRestartAndLeasesAttempts(t *testing.T) {
	st, _, path := setupWebhook(t, true, 2)
	addFindings(t, st, "one", "two", "three")
	stats, err := st.GetWebhookStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.QueueDepth != 2 || stats.Queued != 2 || stats.Dropped != 1 {
		t.Fatalf("capacity accounting: %+v", stats)
	}
	now := time.Now()
	first, err := st.ClaimWebhookDelivery(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Attempts != 1 {
		t.Fatal("attempt was not persisted before delivery")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	stats, err = restored.GetWebhookStats(context.Background())
	if err != nil || stats.QueueDepth != 2 || stats.Dropped != 1 {
		t.Fatalf("restart lost outbox/counters: %+v %v", stats, err)
	}
	// The unclaimed row comes first; after its terminal outcome the crashed
	// row becomes available once its lease expires with the same event identity.
	second, err := restored.ClaimWebhookDelivery(context.Background(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.EventID == first.EventID {
		t.Fatal("crash lease was not respected")
	}
	if err := restored.FinishWebhookDelivery(context.Background(), second, true, time.Time{}, 204, ""); err != nil {
		t.Fatal(err)
	}
	retry, err := restored.ClaimWebhookDelivery(context.Background(), now.Add(31*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if retry.EventID != first.EventID || retry.Attempts != 2 || string(retry.Payload) != string(first.Payload) {
		t.Fatalf("retry identity/evidence changed: %+v", retry)
	}
}

func TestDeliverySignsExactBodyAndRetriesBoundedly(t *testing.T) {
	st, kr, _ := setupWebhook(t, true, 10)
	var calls atomic.Int32
	transport := fixtureTransport(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
		}
		if req.URL.Hostname() != "receiver.example" {
			t.Errorf("unexpected receiver %s", req.URL.Hostname())
		}
		timestamp := req.Header.Get("X-DNSDaddy-Timestamp")
		seconds, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || time.Since(time.Unix(seconds, 0)) > 5*time.Second {
			t.Errorf("invalid signing timestamp %q", timestamp)
		}
		mac := hmac.New(sha256.New, []byte(fixtureSigningSecret))
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(body)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(req.Header.Get("X-DNSDaddy-Signature"))) {
			t.Error("signature does not bind timestamp and raw body")
		}
		if strings.Contains(string(body), fixtureSigningSecret) || strings.Contains(req.URL.String(), fixtureSigningSecret) {
			t.Error("plaintext secret leaked")
		}
		var event map[string]any
		if err := json.Unmarshal(body, &event); err != nil {
			t.Error(err)
		}
		if event["id"] != req.Header.Get("X-DNSDaddy-Event-ID") {
			t.Error("deduplication identity differs from payload")
		}
		status := http.StatusNoContent
		if calls.Add(1) == 1 {
			status = http.StatusTooManyRequests
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ignored"))}, nil
	})
	service := New(Options{Store: st, Keyring: kr, Transport: transport})
	service.Start(context.Background())
	defer service.Stop()
	addFindings(t, st, "retry-fixture")
	service.Reload()
	stats := waitStats(t, st, func(s store.WebhookStats) bool { return s.Delivered == 1 })
	if calls.Load() != 2 || stats.Retried != 1 || stats.QueueDepth != 0 || stats.Failed != 0 {
		t.Fatalf("retry result/counters: %d %+v", calls.Load(), stats)
	}
}

func TestRedirectIsTerminalAndNeverFollowed(t *testing.T) {
	st, kr, _ := setupWebhook(t, true, 10)
	var calls atomic.Int32
	transport := fixtureTransport(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://other.example/steal"}}, Body: io.NopCloser(strings.NewReader("ignored"))}, nil
	})
	service := New(Options{Store: st, Keyring: kr, Transport: transport})
	service.Start(context.Background())
	defer service.Stop()
	addFindings(t, st, "redirect-fixture")
	service.Reload()
	stats := waitStats(t, st, func(s store.WebhookStats) bool { return s.Failed == 1 })
	if calls.Load() != 1 || stats.Retried != 0 || !strings.Contains(stats.LastError, "redirect") {
		t.Fatalf("redirect was not terminal: %d %+v", calls.Load(), stats)
	}
}

func TestChangingReceiverDropsOldEventsAndPreservesEncryptedSecret(t *testing.T) {
	st, kr, _ := setupWebhook(t, true, 10)
	addFindings(t, st, "old-receiver-event")
	encrypted, err := st.WebhookSecretCiphertext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), fixtureSigningSecret) {
		t.Fatal("credential persisted in plaintext")
	}
	if _, err := kr.Open(encrypted, "other-identity"); err == nil {
		t.Fatal("ciphertext not bound to receiver identity")
	}
	c, _ := st.GetWebhookConfig(context.Background())
	c.URL = "https://replacement.example/events"
	if err := st.SaveWebhookConfig(context.Background(), c, nil, "", "", false); err != nil {
		t.Fatal(err)
	}
	stats, _ := st.GetWebhookStats(context.Background())
	if stats.QueueDepth != 0 || stats.Dropped != 1 {
		t.Fatalf("old receiver payloads survived change: %+v", stats)
	}
	after, _ := st.WebhookSecretCiphertext(context.Background())
	if string(after) != string(encrypted) {
		t.Fatal("unchanged secret did not survive config update")
	}
}

func TestSavedDisabledEndpointCanBeTestedWithSyntheticPayloadOnly(t *testing.T) {
	st, kr, _ := setupWebhook(t, false, 10)
	var calls atomic.Int32
	service := New(Options{Store: st, Keyring: kr, Transport: fixtureTransport(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		body, _ := io.ReadAll(req.Body)
		if !strings.Contains(string(body), `"synthetic":true`) || !strings.Contains(string(body), `"type":"webhook.test"`) {
			t.Errorf("test payload was not synthetic: %s", body)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})})
	defer service.Stop()
	result := service.Test(context.Background())
	if !result.OK || calls.Load() != 1 {
		t.Fatalf("test failed: %+v", result)
	}
	stats, _ := st.GetWebhookStats(context.Background())
	if stats.Queued != 0 || stats.Delivered != 0 {
		t.Fatalf("connection test polluted production metrics: %+v", stats)
	}
}

func TestWebhookConfigRejectsUnboundedAndUnsafeDestinations(t *testing.T) {
	base := store.WebhookConfig{URL: "https://receiver.example/events", Enabled: true, SecretSet: true, EventTypes: []string{"finding.created"}, TimeoutMS: 5000, MaxAttempts: 5, MaxQueue: 500}
	for _, u := range []string{"http://receiver.example/events", "https://127.0.0.1/events", "https://[::ffff:169.254.169.254]/", "https://user:password@receiver.example/", "https://receiver.example/?token=secret", "https://[fd00:ec2::254]/"} {
		c := base
		c.URL = u
		c.AllowPrivate = true
		if ValidateConfig(c) == nil {
			t.Errorf("accepted unsafe endpoint %s", u)
		}
	}
	c := base
	c.MaxQueue = 1001
	if ValidateConfig(c) == nil {
		t.Fatal("unbounded outbox accepted")
	}
	c = base
	c.MaxAttempts = 9
	if ValidateConfig(c) == nil {
		t.Fatal("unbounded retry accepted")
	}
	c = base
	c.TimeoutMS = 15001
	if ValidateConfig(c) == nil {
		t.Fatal("unbounded timeout accepted")
	}
	for attempt := 0; attempt < 100; attempt++ {
		if d := RetryDelay(attempt); d < 2*time.Second || d > 5*time.Minute {
			t.Fatalf("unbounded retry delay %s", d)
		}
	}
}
