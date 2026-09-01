# Bring your own intelligence: external API providers

DNS Daddy ships with curated blocklist feeds. This document describes the
**external API provider** subsystem, which lets an operator attach their own
threat-intelligence, reputation and enrichment services — Google Safe Browsing,
VirusTotal, an internal reputation service, anything that speaks HTTP.

It is written for two audiences: an operator deciding whether to turn this on,
and a developer adding an adapter. Sections 1–5 are for the first, 6–9 for the
second.

---

## 1. What this is, and what it costs you

Everything DNS Daddy does today happens on your machine. A blocklist feed is
downloaded on a schedule, parsed into an in-memory index, and consulted with a
map lookup that takes microseconds and reaches no network. Nothing about a
query leaves the building.

An external API provider changes that, and the change is not small:

> **When you enable a provider, the names your network resolves are sent to a
> third party.** Not summaries, not counts — the actual domain, at the time it
> was asked for, from a source address that identifies your deployment.

That is a real trade-off, made knowingly, for real value: a curated blocklist
is hours to days old, and a live reputation service knows about the domain
registered forty minutes ago. This subsystem exists so that operators who want
that can have it, with the cost stated plainly rather than buried.

Section 5 is the full threat-model delta. Read it before enabling anything.

### The three things a provider can do

| Capability | What it means | Hot path? |
|---|---|---|
| **Reputation** | Answers "is this domain malicious?" for a single name | Only in `blocking` mode, and only within a hard budget |
| **Enrichment** | Adds context — registrar, first-seen, categories, ASN — to query-log rows and findings | Never. Always asynchronous |
| **Feed** | Bulk download, parsed like any other blocklist | Never. Scheduled, like existing feeds |

A provider declares which of these it supports. Most support one or two.

---

## 2. Architecture

```
                        ┌──────────────────────────────────────┐
   DNS query            │           internal/policy            │
   ──────────────────►  │  Evaluate()  ← allow / block / cats  │
                        │      │                               │
                        │      │ reputation mode != off        │
                        │      ▼                               │
                        │  intel.Consult()  ── cache hit ──►   │  microseconds, no I/O
                        └──────┬───────────────────────────────┘
                               │ cache miss
                               │
             ┌─────────────────┴──────────────────┐
             │                                    │
    mode = cache_only                     mode = blocking
    enqueue warm, return                  wait ≤ budget, then
    "unknown" immediately                 fail open and enqueue
             │                                    │
             └─────────────────┬──────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │ internal/apiprovider │
                    │        Engine        │
                    │  ┌────────────────┐  │
                    │  │ bounded queue  │  │  drops + counts when full
                    │  └───────┬────────┘  │
                    │          ▼           │
                    │   worker pool (N)    │
                    │          │           │
                    │  ┌───────▼────────┐  │
                    │  │ per-provider:  │  │
                    │  │  rate limiter  │  │
                    │  │  circuit brkr  │  │
                    │  │  timeout       │  │
                    │  │  retry+jitter  │  │
                    │  └───────┬────────┘  │
                    └──────────┼───────────┘
                               ▼
                    ┌──────────────────────┐
                    │ adapters/            │
                    │  safebrowsing        │
                    │  virustotal          │
                    │  customhttp          │
                    └──────────┬───────────┘
                               ▼
                         external HTTP
                               │
                               ▼
                    ┌──────────────────────┐
                    │ two-layer cache      │
                    │  L1 in-memory TTL    │
                    │  L2 intel_verdicts   │  survives restart
                    └──────────────────────┘
```

### Package layout

| Path | Holds |
|---|---|
| `internal/secrets` | AES-256-GCM keyring. Sealing and opening credentials. Nothing else. |
| `internal/apiprovider` | Types, capability interfaces, registry, resilient HTTP client, breaker, limiter, cache, engine |
| `internal/apiprovider/adapters` | One file per concrete provider |
| `internal/store` | `api_providers`, `api_provider_secrets`, `intel_verdicts`, `intel_enrichment` |
| `internal/api` | `/api/v1/integrations/providers` handlers |
| `internal/web/static` | Integrations → External APIs dashboard section |

The dependency direction is one-way: `adapters` imports `apiprovider`, never
the reverse. The registry maps a provider *kind* string to a constructor, so
adding an adapter is one file and one registration line.

---

## 3. Data model

Four new tables. All additive, all `CREATE TABLE IF NOT EXISTS`, consistent
with the existing migration story (`internal/store/store.go`): a downgrade to
the previous binary keeps reading the database, because nothing existing
changes shape.

### `api_providers`

The provider's configuration. Contains **no secret material**.

| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | `apr_<hex>` |
| `name` | TEXT | Operator's label |
| `kind` | TEXT | Registry key: `safebrowsing`, `virustotal`, `customhttp` |
| `enabled` | INTEGER | Disabled providers are never called |
| `capabilities` | TEXT | JSON array, the subset the operator switched on |
| `config` | TEXT | JSON. Adapter-specific non-secret settings (endpoint, field paths) |
| `timeout_ms` | INTEGER | Per-request budget |
| `rate_per_minute` | INTEGER | Token-bucket refill |
| `cache_ttl_seconds` | INTEGER | How long a verdict stays fresh |
| `policy_scope` | TEXT | JSON array of policy IDs; empty means all |
| `created_at` / `updated_at` | INTEGER | |

### `api_provider_secrets`

Separate table, one row per provider, so a `SELECT *` on the configuration
table can never carry a credential into a log, a backup script, or a JSON
response by accident. Deleting a provider cascades.

| Column | Type | Notes |
|---|---|---|
| `provider_id` | TEXT PK | `REFERENCES api_providers(id) ON DELETE CASCADE` |
| `ciphertext` | BLOB | AES-256-GCM: `nonce ‖ sealed` |
| `key_id` | TEXT | Which keyring key sealed it, so rotation is possible |
| `hint` | TEXT | Last 4 characters of the plaintext, for the UI |
| `created_at` / `rotated_at` | INTEGER | |

### `intel_verdicts` — the persistent cache layer

| Column | Type | Notes |
|---|---|---|
| `subject` | TEXT | Normalised domain (or URL/IP) |
| `provider_id` | TEXT | |
| `score` | REAL | 0.0–1.0, provider-normalised |
| `disposition` | TEXT | `malicious`, `suspicious`, `benign`, `unknown` |
| `categories` | TEXT | JSON array |
| `raw` | TEXT | Bounded excerpt of the provider's own answer, for inspection |
| `fetched_at` / `expires_at` | INTEGER | |
| PK | | `(subject, provider_id)` |

Why persist a cache at all: a restart on a 1 GB VPS should not re-ask a paid
API for every domain the network resolves in its first ten minutes. The table
is pruned on the same schedule as the query log.

### `intel_enrichment`

| Column | Type | Notes |
|---|---|---|
| `subject` | TEXT | |
| `provider_id` | TEXT | |
| `data` | TEXT | JSON document, size-capped |
| `fetched_at` / `expires_at` | INTEGER | |
| PK | | `(subject, provider_id)` |

### Migration plan

1. New tables appear via `schema.sql` on first start of the new binary.
2. No existing table changes. No `addedColumns` entry is needed.
3. No provider exists until an operator creates one, so the feature is inert on
   upgrade — the engine starts with an empty registry and does no work.
4. Downgrade: the previous binary ignores four tables it does not know about.
   Nothing breaks; the tables sit unused until an upgrade.

---

## 4. Secrets at rest

### The key

`<data_dir>/secrets.key` — 32 bytes from `crypto/rand`, mode `0600`, created on
first use. It is **not** derived from the admin password: an operator changing
their password must not silently invalidate every stored credential, and a
password is not 256 bits of entropy.

The file is the whole secret. Backing up the database without it produces
ciphertext nobody can open, which is the intended property: a leaked
`dnsdaddy.db` does not leak API keys.

### The sealing

AES-256-GCM, 12-byte random nonce per seal, stored as `nonce ‖ ciphertext`.

The provider ID is passed as **additional authenticated data**. That binds a
sealed credential to the row it belongs to: moving a ciphertext from one
provider row to another — by editing the database directly, or through a bug in
an UPDATE — fails to open rather than silently authenticating provider A with
provider B's key.

### The rules, enforced by tests

- A secret is returned **exactly once**, in the response to the request that
  created or rotated it. Never again, by any endpoint, in any shape.
- `GET` responses carry a `secretHint` (last 4 characters) and
  `secretSet: true`. Never the secret.
- Secrets never enter a log line, a metric label, an error message, or an
  OpenAPI example.
- The OpenAPI spec marks the field `writeOnly: true`.

`internal/api/response_safety_test.go` already scans responses for accidental
disclosure; the provider endpoints are added to it.

### Losing the key

If `secrets.key` is missing or unreadable, providers do not silently
fail-closed-and-quiet: the engine reports every provider as **unavailable —
credential could not be opened**, `doctor` says so, and the dashboard shows it.
Resolution is unaffected, because resolution never depends on a provider.

---

## 5. Threat model delta

`docs/threat-model.md` describes DNS Daddy as it ships. Enabling an external
provider changes four things.

### 5.1 Query names leave the network

Every domain sent to a provider is disclosed to that provider, along with your
source address and an implicit timestamp. For a reputation lookup this is
inherent — you cannot ask "is this bad?" without saying which name.

Mitigations that exist:

- Providers are **off by default**, and each capability is enabled separately.
- `policy_scope` restricts a provider to named policies, so a guest VLAN can
  use a live service while a finance VLAN does not.
- Cache TTL means a repeatedly-resolved domain is sent once per TTL, not once
  per query.

Mitigations that do **not** exist, and are documented as such: DNS Daddy does
not implement oblivious lookups, k-anonymity prefixes, or private set
intersection. Safe Browsing's hash-prefix API would allow the first of those
and is a candidate for future work; the current adapter uses the Lookup API,
which sends full URLs.

### 5.2 A third party gains influence over resolution

In `blocking` mode a provider's answer can block a domain. That is the point,
and it means:

- A compromised or hostile provider can block arbitrary names for your network.
- A provider outage becomes your outage — unless the failure policy is
  fail-open, which is the **default and the only mode we recommend**.

The circuit breaker exists for this. After a threshold of failures a provider
is taken out of the path entirely and the resolver stops consulting it, rather
than adding its timeout to every query.

### 5.3 Responses are untrusted input

Every provider response is parsed defensively:

- Response bodies are read through an `io.LimitReader` — a provider cannot
  exhaust memory with a large body.
- JSON is decoded into typed structs. Unknown fields are ignored, not stored.
- Strings that reach the dashboard are escaped by the existing tagged-template
  escaper; the raw excerpt is stored bounded and rendered as text.
- Scores are clamped to `[0, 1]`. Categories are matched against the known
  catalogue and otherwise dropped.

### 5.4 Credentials become an asset on this host

Previously a stolen `dnsdaddy.db` gave an attacker query history and
configuration. Now it may also give them ciphertext of your VirusTotal key —
useless without `secrets.key`, which is why they are separate files and why the
key is never in the database.

---

## 6. The provider interface

Capability interfaces rather than one fat one, so an adapter implements what it
can actually do and the compiler enforces the rest.

```go
// Every provider identifies itself.
type Provider interface {
    Descriptor() Descriptor
}

// Answers "is this bad?" for one subject.
type ReputationProvider interface {
    Provider
    Reputation(ctx context.Context, s Subject) (Verdict, error)
}

// Adds context without judging.
type Enricher interface {
    Provider
    Enrich(ctx context.Context, s Subject) (Enrichment, error)
}

// Bulk download, parsed like a blocklist feed.
type FeedSource interface {
    Provider
    Fetch(ctx context.Context) (io.ReadCloser, string, error)
}

// Proves the credential works, without spending a reputation quota.
type HealthChecker interface {
    Provider
    CheckHealth(ctx context.Context) error
}
```

`Subject` carries what is being asked about and its kind (domain, URL, IP), so
one adapter can serve several. `Verdict` is provider-independent: a normalised
score, a disposition, categories, a TTL hint, and a bounded raw excerpt.

---

## 7. Resilience

Each provider gets its own instance of all four, keyed by provider ID:

**Timeout.** A per-provider `timeout_ms`, defaulted low (2 s) and clamped. The
context deadline is the authority; the HTTP client's own timeout is a backstop.

**Rate limiter.** Token bucket, refilled at `rate_per_minute`. Blocks the
worker, never the caller: the hot path checks the cache and enqueues, so a
saturated limiter costs a queued item rather than a slow query.

**Circuit breaker.** Three states.

```
      failures ≥ threshold
CLOSED ──────────────────► OPEN ──── cooldown elapsed ───► HALF-OPEN
   ▲                                                            │
   │                              probe succeeds                │
   └────────────────────────────────────────────────────────────┘
                                  probe fails → OPEN
```

While open, calls return `ErrCircuitOpen` immediately without touching the
network. One probe is admitted in half-open; success closes, failure re-opens
with the cooldown restarted.

**Retry.** At most one retry, on transport errors and 5xx only — never on 4xx,
which will fail identically, and never on 429, which retrying makes worse.
Backoff is jittered to stop a restart synchronising every provider.

**Connection reuse.** One shared `http.Transport` across all providers with
bounded idle connections, so N providers do not mean N connection pools on a
1 GB box.

---

## 8. Caching

**L1, in-memory.** Bounded map with TTL, sharded by subject hash. This is what
the hot path reads: one lock, one map lookup, no allocation on a hit.

**L2, `intel_verdicts`.** Read on an L1 miss by the worker, not by the hot
path. Survives restart.

A miss in both is an enqueue, and the answer is `unknown`. **`unknown` never
blocks.** A provider that has not answered yet has, by definition, not said the
domain is bad.

---

## 9. Adding a provider

Four steps. `internal/apiprovider/adapters/customhttp.go` is the reference.

**1. Write the adapter.**

```go
package adapters

type myService struct {
    cfg    apiprovider.InstanceConfig
    client *apiprovider.Client
}

func (m *myService) Descriptor() apiprovider.Descriptor {
    return apiprovider.Descriptor{
        Kind:         "myservice",
        DisplayName:  "My Service",
        Capabilities: []apiprovider.Capability{apiprovider.CapReputation},
        DocsURL:      "https://example.com/docs",
    }
}

func (m *myService) Reputation(ctx context.Context, s apiprovider.Subject) (apiprovider.Verdict, error) {
    // Build the request. Never log the credential.
    // Decode into a typed struct.
    // Normalise to a Verdict. Clamp the score.
}
```

**2. Register it.** One line in `adapters/register.go`:

```go
apiprovider.Register("myservice", newMyService)
```

**3. Add a template** so the dashboard wizard can offer it, in
`adapters/templates.go`: display name, docs link, which fields the operator
must supply, and sensible defaults for timeout and rate.

**4. Test it** against an `httptest.Server` replaying a real captured response.
Do not test against the live API: a test that needs a credential is a test
nobody runs.

### Rules for an adapter

- **Never** log, wrap into an error, or return the credential.
- **Always** bound the response body.
- **Always** clamp the normalised score to `[0, 1]`.
- Return `ErrNotSupported` for a capability you do not implement rather than a
  zero value that reads as a real answer.
- Treat every field as absent-by-default. A provider that changes its schema
  should degrade to `unknown`, not panic.

---

## 10. Configuration

```yaml
integrations:
  # The whole subsystem. Off means no workers start and no table is read.
  enabled: false

  # Workers draining the lookup queue.
  workers: 2

  # Bounded queue. Full means drop-and-count, never block.
  queue_size: 1024

  # How the policy engine may use reputation:
  #   off        never consulted (default)
  #   cache_only consult the local cache only; never waits on a network call
  #   blocking   cache first, then wait up to reputation_budget, then fail open
  reputation_mode: "off"

  # The hard ceiling on how long Evaluate may wait in blocking mode.
  reputation_budget: 50ms

  # Enrich query-log rows and findings asynchronously.
  enrichment: false

  # How long a cached verdict stays fresh when a provider gives no TTL.
  default_cache_ttl: 6h
```

Every value has a safe default and the feature is off. An operator who never
opens the Integrations page gets the resolver they have today, byte for byte.
