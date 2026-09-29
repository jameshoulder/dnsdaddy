package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// AuditSchema is applied at normal store initialization alongside schema.sql.
// The initial pending row is durable before an API mutation can start.
// Completion records the actual persisted configuration difference. Because
// existing handlers use multiple store transactions, this is intentionally an
// intent/outcome journal, not a claim that the whole HTTP request was atomic.
const AuditSchema = `
CREATE TABLE IF NOT EXISTS config_change_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 at INTEGER NOT NULL,
 completed_at INTEGER,
 actor TEXT NOT NULL,
 action TEXT NOT NULL,
 target TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','complete','failed','incomplete')),
 http_status INTEGER NOT NULL DEFAULT 0,
 changes TEXT NOT NULL DEFAULT '[]',
 error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS config_change_history_at ON config_change_history(at,id);
`

func (s *Store) EnsureAuditSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, AuditSchema)
	return err
}

type ConfigChange struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Before   any    `json:"before"`
	After    any    `json:"after"`
	Redacted bool   `json:"redacted"`
}

type ConfigChangeEvent struct {
	ID          int64          `json:"id"`
	At          time.Time      `json:"at"`
	CompletedAt *time.Time     `json:"completedAt,omitempty"`
	Actor       string         `json:"actor"`
	Action      string         `json:"action"`
	Target      string         `json:"target"`
	Status      string         `json:"status"`
	HTTPStatus  int            `json:"httpStatus"`
	Changes     []ConfigChange `json:"changes"`
	Error       string         `json:"error,omitempty"`
}

func (s *Store) BeginConfigChange(ctx context.Context, actor, action, target string) (int64, error) {
	if actor == "" || len(actor) > 256 || action == "" || len(action) > 80 || len(target) > 512 {
		return 0, errors.New("invalid configuration audit identity")
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO config_change_history(at,actor,action,target,status) VALUES(?,?,?,?,'pending')`, unixMilli(time.Now().UTC()), actor, action, target)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) CompleteConfigChange(ctx context.Context, id int64, status string, httpStatus int, changes []ConfigChange, note string) error {
	if status != "complete" && status != "failed" && status != "incomplete" {
		return errors.New("invalid audit completion status")
	}
	if changes == nil {
		changes = []ConfigChange{}
	}
	encoded, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	if len(encoded) > 2<<20 {
		return errors.New("configuration audit diff exceeds 2 MiB")
	}
	// note is a fixed application status, never a SQL error, body, header,
	// provider error, or arbitrary exception whose text might contain a key.
	if len(note) > 512 {
		return errors.New("audit status note is too long")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE config_change_history SET completed_at=?,status=?,http_status=?,changes=?,error=? WHERE id=? AND status='pending'`, unixMilli(time.Now().UTC()), status, httpStatus, string(encoded), note, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("configuration audit record is not pending")
	}
	return nil
}

// ListConfigChanges uses a strict monotonically descending ID cursor. New
// writes cannot shift pages and no offset is silently clamped or restarted.
func (s *Store) ListConfigChanges(ctx context.Context, beforeID int64, limit int) ([]ConfigChangeEvent, bool, error) {
	if limit < 1 || limit > 200 || beforeID < 0 {
		return nil, false, errors.New("invalid configuration history page")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,at,completed_at,actor,action,target,status,http_status,changes,error FROM config_change_history WHERE (?=0 OR id<?) ORDER BY id DESC LIMIT ?`, beforeID, beforeID, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := []ConfigChangeEvent{}
	for rows.Next() {
		var e ConfigChangeEvent
		var at int64
		var complete sql.NullInt64
		var changes string
		if err := rows.Scan(&e.ID, &at, &complete, &e.Actor, &e.Action, &e.Target, &e.Status, &e.HTTPStatus, &changes, &e.Error); err != nil {
			return nil, false, err
		}
		e.At = fromUnixMilli(at)
		if complete.Valid {
			t := fromUnixMilli(complete.Int64)
			e.CompletedAt = &t
		}
		if err := json.Unmarshal([]byte(changes), &e.Changes); err != nil {
			return nil, false, fmt.Errorf("configuration audit history is damaged: %w", err)
		}
		if e.Changes == nil {
			e.Changes = []ConfigChange{}
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(result) > limit
	if more {
		result = result[:limit]
	}
	return result, more, nil
}

// AuditScope is selected by the management router, never from an SQL fragment.
// Empty ID means all rows of one kind, used when a creation does not yet have
// its server-assigned ID. There are deliberately no raw request snapshots.
type AuditScope struct{ Kind, ID string }
type auditValue struct {
	value  any
	hidden bool
	digest [32]byte
}
type ConfigSnapshot map[string]map[string]auditValue

type auditQuery struct {
	sql      string
	columns  []string
	hidden   map[string]bool
	resource string
}

func (s *Store) CaptureConfig(ctx context.Context, scope AuditScope) (ConfigSnapshot, error) {
	queries := []auditQuery{}
	add := func(resource, statement string, columns []string, hidden ...string) {
		h := map[string]bool{}
		for _, f := range hidden {
			h[f] = true
		}
		queries = append(queries, auditQuery{statement, columns, h, resource})
	}
	switch scope.Kind {
	case "network":
		add("network", `SELECT id,name,location,policy_id,token,enabled,allow_resolver FROM networks WHERE (?='' OR id=?)`, []string{"id", "name", "location", "policyId", "credential", "enabled", "allowResolver"}, "credential")
		add("network_cidr", `SELECT network_id || '|' || cidr,network_id,cidr,public_ack FROM network_cidrs WHERE (?='' OR network_id=?)`, []string{"id", "networkId", "cidr", "publicAcknowledged"})
	case "policy":
		add("policy", `SELECT id,name,description,categories,block_mode,safe_search,log_queries,is_default FROM policies WHERE (?='' OR id=?)`, []string{"id", "name", "description", "categories", "blockMode", "safeSearch", "logQueries", "isDefault"}, "description")
		add("policy_rule", `SELECT policy_id || '|' || kind || '|' || domain,policy_id,kind,domain,note FROM policy_rules WHERE (?='' OR policy_id=?)`, []string{"id", "policyId", "kind", "domain", "note"}, "note")
	case "feed":
		add("feed", `SELECT id,name,url,category,format,enabled,builtin FROM feeds WHERE (?='' OR id=?)`, []string{"id", "name", "url", "category", "format", "enabled", "builtin"}, "url")
	case "client":
		add("client", `SELECT ip,name FROM clients WHERE (?='' OR ip=?)`, []string{"id", "name"})
	case "token":
		add("api_token", `SELECT id,name,hash FROM api_tokens WHERE (?='' OR id=?)`, []string{"id", "name", "credential"}, "credential")
	case "provider":
		add("provider", `SELECT id,name,kind,enabled,capabilities,config,timeout_ms,rate_per_minute,cache_ttl_seconds,policy_scope FROM api_providers WHERE (?='' OR id=?)`, []string{"id", "name", "kind", "enabled", "capabilities", "config", "timeoutMs", "ratePerMinute", "cacheTtlSeconds", "policyScope"}, "config")
		add("provider_secret", `SELECT provider_id,ciphertext FROM api_provider_secrets WHERE (?='' OR provider_id=?)`, []string{"id", "credential"}, "credential")
	case "review":
		add("finding_review", `SELECT finding_id,state,note,version FROM finding_reviews WHERE (?='' OR finding_id=?)`, []string{"id", "state", "note", "version"}, "note")
	case "webhook":
		add("webhook", `SELECT CAST(id AS TEXT),enabled,url,event_types,allow_private,timeout_ms,max_attempts,max_queue,ciphertext,version FROM webhook_config WHERE (?='' OR CAST(id AS TEXT)=?)`, []string{"id", "enabled", "url", "eventTypes", "allowPrivate", "timeoutMs", "maxAttempts", "maxQueue", "credential", "version"}, "url", "credential")
	case "settings":
		add("setting", `SELECT key,value FROM settings WHERE (?='' OR key=?)`, []string{"id", "value"}, "value")
	case "integration_settings":
		add("setting", `SELECT key,value FROM settings WHERE key IN ('integrations.reputation_mode','integrations.enrichment') AND (?='' OR key=?)`, []string{"id", "value"})
	default:
		return nil, errors.New("unsupported configuration audit scope")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snapshot := ConfigSnapshot{}
	bytes := 0
	for _, q := range queries {
		rows, err := tx.QueryContext(ctx, q.sql, scope.ID, scope.ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			values := make([]any, len(q.columns))
			ptrs := make([]any, len(values))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return nil, err
			}
			id := auditString(values[0])
			row := map[string]auditValue{}
			for i, name := range q.columns[1:] {
				v := values[i+1]
				hidden := q.hidden[name]
				// A closed allowlist permits harmless settings values; all
				// other setting data stays opaque, including password hashes.
				if q.resource == "setting" && safeAuditSetting(id) {
					hidden = false
				}
				// Hash binary ciphertext as binary. Converting it to a JSON
				// string first would replace invalid UTF-8 and could hide a
				// credential rotation between two different byte sequences.
				var encoded []byte
				if blob, ok := v.([]byte); ok && hidden {
					encoded = blob
				} else {
					if blob, ok := v.([]byte); ok {
						v = string(blob)
					}
					var err error
					encoded, err = json.Marshal(v)
					if err != nil {
						rows.Close()
						return nil, err
					}
				}
				bytes += len(encoded)
				x := auditValue{hidden: hidden}
				if hidden {
					x.digest = sha256.Sum256(encoded)
				} else {
					x.value = v
				}
				row[name] = x
			}
			snapshot[q.resource+":"+id] = row
			if len(snapshot) > 20000 || bytes > 16<<20 {
				rows.Close()
				return nil, errors.New("configuration snapshot exceeds audit limits")
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func safeAuditSetting(key string) bool {
	switch key {
	case "integrations.reputation_mode", "integrations.enrichment", "install.local_dnssec_default", "dnssec.mode", "protection.settings.v1":
		return true
	}
	return false
}

func auditString(v any) string {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(v)
}

// DiffConfig exposes field-level persisted changes. Secret digests are used
// only for an in-memory comparison; neither the secret nor its digest enters
// the durable journal, HTTP response or logs.
func DiffConfig(before, after ConfigSnapshot) []ConfigChange {
	resources := map[string]bool{}
	for k := range before {
		resources[k] = true
	}
	for k := range after {
		resources[k] = true
	}
	keys := []string{}
	for k := range resources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	changes := []ConfigChange{}
	for _, resource := range keys {
		a, aExists := before[resource]
		b, bExists := after[resource]
		if aExists != bExists {
			changes = append(changes, ConfigChange{Resource: resource, Field: "exists", Before: aExists, After: bExists})
		}
		fields := map[string]bool{}
		for k := range a {
			fields[k] = true
		}
		for k := range b {
			fields[k] = true
		}
		names := []string{}
		for k := range fields {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, field := range names {
			av, aok := a[field]
			bv, bok := b[field]
			if aok == bok && reflect.DeepEqual(av, bv) {
				continue
			}
			hidden := av.hidden || bv.hidden
			var old, next any
			if aok {
				old = av.value
				if hidden {
					old = "[redacted]"
				}
			}
			if bok {
				next = bv.value
				if hidden {
					next = "[redacted]"
				}
			}
			changes = append(changes, ConfigChange{Resource: resource, Field: field, Before: old, After: next, Redacted: hidden})
		}
	}
	return changes
}

// CleanAuditLabel is display metadata, not credential material. Control
// characters are removed so a token name cannot forge terminal/log lines.
func CleanAuditLabel(raw string) string {
	value := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, raw)
	if len(value) > 256 {
		value = string([]rune(value)[:min(64, len([]rune(value)))])
	}
	return value
}
