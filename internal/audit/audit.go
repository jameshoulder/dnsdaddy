// Package audit records the changes an operator made to how this resolver
// behaves.
//
// # What this is not
//
// It is not a log of DNS traffic. query_log holds one row per question and is
// bounded by retention; this holds one row per configuration change and is
// bounded by how often somebody edits something. Conflating them would hand an
// attacker a way to fill the audit log by sending queries, which is the one
// thing an audit log must not be vulnerable to.
//
// # Redaction is at the boundary, not at the reader
//
// Before and after states are redacted by Redact on the way in, so a secret
// never reaches the database in the first place. Redacting on the way out
// would mean the secret was stored, and an audit export — the single most
// likely thing an operator hands to an auditor, an insurer, or a support
// engineer — would carry it.
//
// # Failure model
//
// The queue is bounded and drops. A management mutation that has already been
// committed must not be failed because its audit row could not be queued: the
// change happened, and reporting failure would leave the operator retrying a
// thing that already took effect. So the mutation succeeds, the drop is
// counted, and dnsdaddy doctor reports a non-zero drop count — an audit log
// with holes in it is a problem an operator has to be told about, not one to
// paper over.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jameshoulder/dnsdaddy/internal/store"
)

// Actions. Dotted verbs, closed set, safe as a metric label.
const (
	ActionPolicyCreate     = "policy.create"
	ActionPolicyUpdate     = "policy.update"
	ActionPolicyDelete     = "policy.delete"
	ActionNetworkCreate    = "network.create"
	ActionNetworkUpdate    = "network.update"
	ActionNetworkDelete    = "network.delete"
	ActionTokenCreate      = "token.create"
	ActionTokenRevoke      = "token.revoke"
	ActionProviderWrite    = "provider.credential.write"
	ActionProviderClear    = "provider.credential.clear"
	ActionModeSet          = "config.mode.set"
	ActionPasswordChange   = "auth.password.change"
	ActionSessionsRevoked  = "auth.sessions.revoke_all"
	ActionInstallDecisions = "install.decisions"
)

// Sources.
const (
	SourceDashboard = "dashboard"
	SourceAPI       = "api"
	SourceConfig    = "config-reload"
	SourceSeed      = "seed"
)

// Actor kinds.
const (
	ActorSession = "session"
	ActorToken   = "token"
	ActorSystem  = "system"
)

// Drop reasons, used as a bounded metric label.
const (
	DropFull     = "full"
	DropDisabled = "disabled"
	DropFailed   = "failed"
)

// DropReasons is every reason, so metrics can be emitted at zero.
func DropReasons() []string { return []string{DropFull, DropDisabled, DropFailed} }

// Entry is one recorded change.
type Entry struct {
	Time       time.Time
	Actor      string
	ActorKind  string
	Action     string
	TargetType string
	TargetID   string
	// Before and After are the states either side of the change. They are
	// redacted before storage; see Redact.
	Before any
	After  any
	Source string
}

// redactedKeys are field names whose values never reach the database.
//
// Matched case-insensitively on the whole key and on common suffixes, because
// the thing being protected is the value and a near-miss on the name is a
// leak. Over-redacting an innocent field costs an operator a little context in
// one audit row; under-redacting one writes a live credential into the table
// most likely to be exported.
var redactedKeys = []string{
	"password", "passwordhash", "hash",
	"token", "secret", "apikey", "api_key", "key",
	"credential", "credentials", "session", "cookie",
	"privatekey", "private_key", "bearer", "authorization",
}

// Redacted is what replaces a secret's value.
const Redacted = "[redacted]"

// Redact returns a copy of v with secret-looking values replaced.
//
// Values, not keys: an operator reading the audit log needs to see that an API
// key was set, and which provider it was set on, and must not see the key. So
// the shape of the change survives and the secret does not — "apiKey":
// "[redacted]" rather than the field vanishing, because a field that vanishes
// is indistinguishable from one that was never sent.
func Redact(v any) any {
	if v == nil {
		return nil
	}
	// Round-tripping through JSON rather than reflecting over the struct: the
	// stored form is JSON, so redacting the JSON shape guarantees there is no
	// path from a struct field to the database that skips this function.
	raw, err := json.Marshal(v)
	if err != nil {
		return map[string]string{"error": "value could not be encoded for the audit log"}
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return map[string]string{"error": "value could not be decoded for the audit log"}
	}
	return redactValue(generic)
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSecretKey(k) {
				out[k] = redactionFor(val)
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, redactValue(item))
		}
		return out
	default:
		return v
	}
}

// redactionFor keeps the shape of what was there without the content.
//
// An operator auditing a change needs to tell "a key was set" from "a key was
// cleared", and those are different events with different consequences. The
// value is never revealed either way.
func redactionFor(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return ""
		}
		return Redacted
	case bool:
		return t
	default:
		return Redacted
	}
}

func isSecretKey(k string) bool {
	lower := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(k))
	for _, s := range redactedKeys {
		bare := strings.ReplaceAll(s, "_", "")
		if lower == bare || strings.HasSuffix(lower, bare) {
			return true
		}
	}
	return false
}

// Logger queues audit entries and writes them off the request path.
//
// A nil *Logger is a working switched-off logger: Record does nothing and the
// counters read zero.
type Logger struct {
	store *store.Store
	log   *slog.Logger
	ch    chan store.AuditEntry
	done  chan struct{}

	stopped atomic.Bool
	written atomic.Uint64
	dropped [3]atomic.Uint64
}

// Options configures a Logger.
type Options struct {
	// QueueSize bounds the queue. Full means drop and count, never block.
	QueueSize int
	Log       *slog.Logger
}

// New returns a Logger. Run must be called to start draining.
func New(st *store.Store, o Options) *Logger {
	size := o.QueueSize
	if size <= 0 {
		size = 256
	}
	lg := o.Log
	if lg == nil {
		lg = slog.Default()
	}
	return &Logger{store: st, log: lg, ch: make(chan store.AuditEntry, size), done: make(chan struct{})}
}

// Record offers an entry to the queue.
//
// Non-blocking. The caller has already committed the change it is describing,
// so making it wait here would put SQLite's write latency into every
// management mutation for no gain — and failing it would be worse, because the
// change already happened.
func (l *Logger) Record(e Entry) {
	if l == nil {
		return
	}
	if l.stopped.Load() {
		l.dropped[2].Add(1)
		return
	}
	row := store.AuditEntry{
		Time:       e.Time,
		Actor:      e.Actor,
		ActorKind:  e.ActorKind,
		Action:     e.Action,
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Source:     e.Source,
		Before:     encode(Redact(e.Before)),
		After:      encode(Redact(e.After)),
	}
	if row.Time.IsZero() {
		row.Time = time.Now().UTC()
	}
	select {
	case l.ch <- row:
	default:
		l.dropped[0].Add(1)
	}
}

func encode(v any) string {
	if v == nil {
		return ""
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

// flushInterval is how long entries wait before being written.
//
// Short enough that an operator refreshing the audit view sees their own
// change, long enough that the write does not land in the same instant as the
// mutation it describes. That matters more than it sounds: SQLite takes one
// writer at a time, and an audit transaction opened the moment a policy update
// commits is the most likely thing in this process to collide with it.
const flushInterval = 200 * time.Millisecond

// Run drains the queue until ctx is cancelled, then writes what is left.
//
// Entries are batched rather than written one transaction each. The batch is
// not about throughput — there are a handful of configuration changes a week —
// it is about not competing with the mutation that produced it for SQLite's
// single write lock.
func (l *Logger) Run(ctx context.Context) {
	if l == nil {
		return
	}
	defer close(l.done)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var batch []store.AuditEntry
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case e := <-l.ch:
					batch = append(batch, e)
					continue
				default:
				}
				break
			}
			l.write(ctx, batch)
			return
		case e := <-l.ch:
			batch = append(batch, e)
		case <-ticker.C:
			l.write(ctx, batch)
			batch = batch[:0]
		}
	}
}

func (l *Logger) write(ctx context.Context, batch []store.AuditEntry) {
	if len(batch) == 0 {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	if err := l.store.RecordAuditBatch(wctx, batch); err != nil {
		l.dropped[2].Add(uint64(len(batch)))
		// The actions are named; the payloads are not. They are redacted
		// already, but a log line is a second copy in a second place and there
		// is no reason to make one.
		l.log.Error("could not record audit entries", "entries", len(batch), "error", err)
		return
	}
	l.written.Add(uint64(len(batch)))
}

// Wait blocks until Run has finished.
func (l *Logger) Wait() {
	if l == nil {
		return
	}
	l.stopped.Store(true)
	<-l.done
}

// Stats is a snapshot for /metrics and doctor.
type Stats struct {
	Written uint64
	Dropped map[string]uint64
}

// Stats returns the counters. Safe on a nil Logger.
func (l *Logger) Stats() Stats {
	s := Stats{Dropped: map[string]uint64{}}
	for _, r := range DropReasons() {
		s.Dropped[r] = 0
	}
	if l == nil {
		return s
	}
	s.Written = l.written.Load()
	s.Dropped[DropFull] = l.dropped[0].Load()
	s.Dropped[DropDisabled] = l.dropped[1].Load()
	s.Dropped[DropFailed] = l.dropped[2].Load()
	return s
}
