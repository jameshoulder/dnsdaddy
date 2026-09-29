package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"time"
)

//go:embed webhook_schema.sql
var webhookSchema string

// InitWebhooks installs the bounded outbox and atomic event-capture triggers.
// Call during Store.Open after the core schema/migrations, before serving.
func (s *Store) InitWebhooks(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, webhookSchema)
	return err
}

type WebhookConfig struct {
	Enabled      bool      `json:"enabled"`
	URL          string    `json:"url"`
	EventTypes   []string  `json:"eventTypes"`
	AllowPrivate bool      `json:"allowPrivate"`
	TimeoutMS    int       `json:"timeoutMs"`
	MaxAttempts  int       `json:"maxAttempts"`
	MaxQueue     int       `json:"maxQueue"`
	SecretSet    bool      `json:"secretSet"`
	SecretHint   string    `json:"secretHint"`
	Version      int64     `json:"version"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func (s *Store) GetWebhookConfig(ctx context.Context) (WebhookConfig, error) {
	var c WebhookConfig
	var events string
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT enabled,url,event_types,allow_private,timeout_ms,max_attempts,max_queue,
		length(coalesce(ciphertext,'')) > 0,hint,version,updated_at FROM webhook_config WHERE id = 1`).Scan(
		&c.Enabled, &c.URL, &events, &c.AllowPrivate, &c.TimeoutMS, &c.MaxAttempts, &c.MaxQueue, &c.SecretSet, &c.SecretHint, &c.Version, &updated)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal([]byte(events), &c.EventTypes); err != nil {
		return c, err
	}
	c.UpdatedAt = time.UnixMilli(updated).UTC()
	return c, nil
}

// SaveWebhookConfig never receives a plaintext credential. Every change drops
// queued payloads, so events consented to for one receiver cannot be forwarded
// to its replacement. Counts remain visible across restarts and reconfiguration.
func (s *Store) SaveWebhookConfig(ctx context.Context, c WebhookConfig, ciphertext []byte, keyID, hint string, replaceSecret bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	events, err := json.Marshal(c.EventTypes)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE webhook_config SET enabled=?,url=?,event_types=?,allow_private=?,timeout_ms=?,max_attempts=?,max_queue=?,version=version+1,updated_at=? WHERE id=1 AND version=?`,
		c.Enabled, c.URL, string(events), c.AllowPrivate, c.TimeoutMS, c.MaxAttempts, c.MaxQueue, time.Now().UnixMilli(), c.Version)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("webhook configuration changed; reload and retry")
	}
	if replaceSecret {
		if _, err := tx.ExecContext(ctx, "UPDATE webhook_config SET ciphertext=?,key_id=?,hint=? WHERE id=1", ciphertext, keyID, hint); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE webhook_stats SET dropped=dropped+(SELECT COUNT(*) FROM webhook_outbox) WHERE id=1"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM webhook_outbox"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) WebhookSecretCiphertext(ctx context.Context) ([]byte, error) {
	var ciphertext []byte
	err := s.db.QueryRowContext(ctx, "SELECT ciphertext FROM webhook_config WHERE id=1").Scan(&ciphertext)
	return ciphertext, err
}

// WebhookSecretForVersion prevents a concurrent rotation from signing an old
// receiver's payload with a newly configured receiver's key.
func (s *Store) WebhookSecretForVersion(ctx context.Context, version int64) ([]byte, error) {
	var ciphertext []byte
	err := s.db.QueryRowContext(ctx, "SELECT ciphertext FROM webhook_config WHERE id=1 AND version=?", version).Scan(&ciphertext)
	return ciphertext, err
}

type WebhookStats struct {
	QueueDepth     int        `json:"queueDepth"`
	Queued         uint64     `json:"queued"`
	Attempted      uint64     `json:"attempted"`
	Delivered      uint64     `json:"delivered"`
	Failed         uint64     `json:"failed"`
	Dropped        uint64     `json:"dropped"`
	Retried        uint64     `json:"retried"`
	LastSuccessAt  *time.Time `json:"lastSuccessAt"`
	LastFailureAt  *time.Time `json:"lastFailureAt"`
	LastError      string     `json:"lastError"`
	LastHTTPStatus int        `json:"lastHttpStatus"`
	Scope          string     `json:"scope"`
}

func (s *Store) GetWebhookStats(ctx context.Context) (WebhookStats, error) {
	var stats WebhookStats
	var success, failure int64
	err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM webhook_outbox),queued,attempted,delivered,failed,dropped,retried,last_success_at,last_failure_at,last_error,last_http_status FROM webhook_stats WHERE id=1`).Scan(
		&stats.QueueDepth, &stats.Queued, &stats.Attempted, &stats.Delivered, &stats.Failed, &stats.Dropped, &stats.Retried, &success, &failure, &stats.LastError, &stats.LastHTTPStatus)
	if success != 0 {
		t := time.UnixMilli(success).UTC()
		stats.LastSuccessAt = &t
	}
	if failure != 0 {
		t := time.UnixMilli(failure).UTC()
		stats.LastFailureAt = &t
	}
	stats.Scope = "persistent totals since webhook storage was created"
	return stats, err
}

type WebhookDelivery struct {
	ID            int64
	EventID       string
	EventType     string
	Payload       []byte
	Attempts      int
	ConfigVersion int64
}

// ClaimWebhookDelivery persists an attempt and a lease before any network
// operation. On restart a crashed attempt becomes eligible after 30 seconds;
// delivery is at least once, so receivers must deduplicate by event ID.
func (s *Store) ClaimWebhookDelivery(ctx context.Context, now time.Time) (WebhookDelivery, error) {
	var d WebhookDelivery
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return d, err
	}
	defer tx.Rollback() //nolint:errcheck
	err = tx.QueryRowContext(ctx, `SELECT id,event_id,event_type,payload,attempts,config_version FROM webhook_outbox WHERE next_attempt<=? ORDER BY next_attempt,id LIMIT 1`, now.UnixMilli()).Scan(&d.ID, &d.EventID, &d.EventType, &d.Payload, &d.Attempts, &d.ConfigVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE webhook_outbox SET attempts=attempts+1,next_attempt=? WHERE id=?", now.Add(30*time.Second).UnixMilli(), d.ID); err != nil {
		return d, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE webhook_stats SET attempted=attempted+1 WHERE id=1"); err != nil {
		return d, err
	}
	d.Attempts++
	return d, tx.Commit()
}

// FinishWebhookDelivery records bounded retry or a terminal outcome. Returning
// after a configuration change is a no-op: that configuration already counted
// and discarded the superseded delivery.
func (s *Store) FinishWebhookDelivery(ctx context.Context, d WebhookDelivery, success bool, retryAt time.Time, status int, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_outbox WHERE id=? AND config_version=?", d.ID, d.ConfigVersion).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	if len(detail) > 256 {
		detail = detail[:256]
	}
	if success {
		_, err = tx.ExecContext(ctx, "UPDATE webhook_stats SET delivered=delivered+1,last_success_at=?,last_error='',last_http_status=? WHERE id=1", now, status)
	} else if retryAt.IsZero() {
		_, err = tx.ExecContext(ctx, "UPDATE webhook_stats SET failed=failed+1,last_failure_at=?,last_error=?,last_http_status=? WHERE id=1", now, detail, status)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE webhook_stats SET retried=retried+1,last_failure_at=?,last_error=?,last_http_status=? WHERE id=1", now, detail, status)
	}
	if err != nil {
		return err
	}
	if retryAt.IsZero() || success {
		_, err = tx.ExecContext(ctx, "DELETE FROM webhook_outbox WHERE id=?", d.ID)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE webhook_outbox SET next_attempt=? WHERE id=?", retryAt.UnixMilli(), d.ID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
