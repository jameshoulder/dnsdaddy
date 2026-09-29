// Package webhook delivers explicitly enabled notifications from a bounded,
// durable SQLite outbox. Finding append transactions only enqueue; a single
// background worker owns network I/O, retry deadlines and delivery counters.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/apiprovider"
	"github.com/jameshoulder/dnsdaddy/internal/secrets"
	"github.com/jameshoulder/dnsdaddy/internal/store"
)

const SecretIdentity = "webhook:default"

type Options struct {
	Store   *store.Store
	Keyring *secrets.Keyring
	Log     *slog.Logger
	// Transport is a trusted fixture seam. Production leaves it nil, using
	// verified TLS and destination checks on each resolved connection.
	Transport http.RoundTripper
}

type Service struct {
	store            *store.Store
	keyring          *secrets.Keyring
	log              *slog.Logger
	transport        http.RoundTripper
	publicTransport  *http.Transport
	privateTransport *http.Transport
	wake             chan struct{}
	mu               sync.Mutex
	cancel           context.CancelFunc
	requestCancel    context.CancelFunc
	wg               sync.WaitGroup
}

func New(o Options) *Service {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Service{store: o.Store, keyring: o.Keyring, log: o.Log, transport: o.Transport,
		publicTransport: apiprovider.NewTransport(false), privateTransport: apiprovider.NewTransport(true), wake: make(chan struct{}, 1)}
}

func (s *Service) Start(parent context.Context) {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go s.run(ctx)
}

func (s *Service) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.requestCancel != nil {
		s.requestCancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.publicTransport.CloseIdleConnections()
	s.privateTransport.CloseIdleConnections()
}

// Reload cancels an in-flight request where possible and wakes the worker. A
// receiver may already have accepted that request; sent data cannot be recalled.
func (s *Service) Reload() {
	s.mu.Lock()
	if s.requestCancel != nil {
		s.requestCancel()
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func ValidateConfig(c store.WebhookConfig) error {
	if c.URL != "" {
		if err := apiprovider.ValidateEndpoint(c.URL, c.AllowPrivate); err != nil {
			return err
		}
		u, err := url.Parse(c.URL)
		if err != nil || u.RawQuery != "" {
			return errors.New("webhook URL must not contain a query string; authenticate using the signing secret")
		}
	}
	if c.Enabled && (c.URL == "" || !c.SecretSet) {
		return errors.New("an HTTPS endpoint and signing secret are required before enabling webhooks")
	}
	if c.TimeoutMS < 100 || c.TimeoutMS > 15000 {
		return errors.New("webhook timeoutMs must be between 100 and 15000")
	}
	if c.MaxAttempts < 1 || c.MaxAttempts > 8 {
		return errors.New("webhook maxAttempts must be between 1 and 8")
	}
	if c.MaxQueue < 1 || c.MaxQueue > 1000 {
		return errors.New("webhook maxQueue must be between 1 and 1000")
	}
	if len(c.EventTypes) == 0 || len(c.EventTypes) > 2 {
		return errors.New("choose one or both supported webhook event types")
	}
	seen := map[string]bool{}
	for _, kind := range c.EventTypes {
		if kind != "finding.created" && kind != "finding.reviewed" {
			return errors.New("webhook event type must be finding.created or finding.reviewed")
		}
		if seen[kind] {
			return errors.New("duplicate webhook event type")
		}
		seen[kind] = true
	}
	return nil
}

func (s *Service) run(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
		for i := 0; i < 50; i++ {
			if ctx.Err() != nil {
				return
			}
			c, err := s.store.GetWebhookConfig(ctx)
			if err != nil || !c.Enabled || ValidateConfig(c) != nil {
				break
			}
			d, err := s.store.ClaimWebhookDelivery(ctx, time.Now())
			if errors.Is(err, store.ErrNotFound) {
				break
			}
			if err != nil {
				s.log.Warn("webhook outbox could not be read")
				break
			}
			if d.ConfigVersion != c.Version || d.Attempts > c.MaxAttempts {
				_ = s.store.FinishWebhookDelivery(ctx, d, false, time.Time{}, 0, "delivery expired or configuration changed")
				continue
			}
			callCtx, cancel := context.WithCancel(ctx)
			s.mu.Lock()
			s.requestCancel = cancel
			s.mu.Unlock()
			// Recheck after installing cancellation. This closes the window where
			// a settings update completed just before this request began.
			latest, readErr := s.store.GetWebhookConfig(callCtx)
			if readErr != nil || !latest.Enabled || latest.Version != c.Version {
				cancel()
				continue
			}
			result := s.deliver(callCtx, c, d.EventID, d.Payload)
			cancel()
			s.mu.Lock()
			s.requestCancel = nil
			s.mu.Unlock()
			var retryAt time.Time
			if !result.OK && result.retryable && d.Attempts < c.MaxAttempts {
				retryAt = time.Now().Add(RetryDelay(d.Attempts))
			}
			if err := s.store.FinishWebhookDelivery(ctx, d, result.OK, retryAt, result.HTTPStatus, result.Error); err != nil && ctx.Err() == nil {
				s.log.Warn("webhook outcome could not be persisted; delivery may be retried")
			}
		}
	}
}

// RetryDelay is bounded exponential backoff: 2, 4, 8 ... up to 5 minutes.
func RetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	delay := time.Second * time.Duration(1<<attempt)
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}

type Result struct {
	OK         bool   `json:"ok"`
	LatencyMS  int64  `json:"latencyMs"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Error      string `json:"error,omitempty"`
	retryable  bool
}

// Test sends only a synthetic payload after an explicit management POST. It
// works while delivery is disabled, before the operator enables real events.
func (s *Service) Test(ctx context.Context) Result {
	c, err := s.store.GetWebhookConfig(ctx)
	if err != nil {
		return Result{Error: "webhook configuration is unavailable"}
	}
	if c.URL == "" || !c.SecretSet {
		return Result{Error: "save an endpoint and signing secret before testing"}
	}
	if err := ValidateConfig(c); err != nil {
		return Result{Error: err.Error()}
	}
	id := store.NewID("webhook_test")
	payload, _ := json.Marshal(map[string]any{"id": id, "type": "webhook.test", "occurredAt": time.Now().UTC(), "data": map[string]any{"message": "DNS Daddy webhook connection test", "synthetic": true}})
	return s.deliver(ctx, c, id, payload)
}

func (s *Service) deliver(parent context.Context, c store.WebhookConfig, eventID string, payload []byte) Result {
	start := time.Now()
	result := s.send(parent, c, eventID, payload)
	result.LatencyMS = time.Since(start).Milliseconds()
	return result
}

func (s *Service) send(parent context.Context, c store.WebhookConfig, eventID string, payload []byte) Result {
	if len(payload) > 32768 {
		return Result{Error: "webhook payload exceeds 32 KiB"}
	}
	if err := apiprovider.ValidateEndpoint(c.URL, c.AllowPrivate); err != nil {
		return Result{Error: "webhook destination is not permitted"}
	}
	if s.keyring == nil || !s.keyring.Available() {
		return Result{Error: "webhook signing key is unavailable"}
	}
	ciphertext, err := s.store.WebhookSecretForVersion(parent, c.Version)
	if err != nil {
		return Result{Error: "webhook signing key could not be read"}
	}
	secret, err := s.keyring.Open(ciphertext, SecretIdentity)
	if err != nil {
		return Result{Error: "webhook signing key could not be decrypted"}
	}
	defer clear(secret)
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.TimeoutMS)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(payload))
	if err != nil {
		return Result{Error: "webhook endpoint is invalid"}
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(payload)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DNSDaddy-webhook/1")
	req.Header.Set("X-DNSDaddy-Event-ID", eventID)
	req.Header.Set("X-DNSDaddy-Timestamp", timestamp)
	req.Header.Set("X-DNSDaddy-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	var transport http.RoundTripper = s.publicTransport
	if c.AllowPrivate {
		transport = s.privateTransport
	}
	if s.transport != nil {
		transport = s.transport
	}
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Error: "webhook request failed (network, TLS, timeout or destination restriction)", retryable: true}
	}
	defer resp.Body.Close()
	// Ignore hostile response text, including a receiver echoing the request.
	// Even draining for connection reuse has a bound and the request deadline.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return Result{OK: true, HTTPStatus: resp.StatusCode, Detail: "The receiver accepted the signed event."}
	}
	retry := resp.StatusCode == 408 || resp.StatusCode == 425 || resp.StatusCode == 429 || resp.StatusCode >= 500
	detail := fmt.Sprintf("receiver returned HTTP %d", resp.StatusCode)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		detail = "receiver returned a redirect; redirects are never followed"
	}
	return Result{HTTPStatus: resp.StatusCode, Error: strings.TrimSpace(detail), retryable: retry}
}
