# Privacy, outbound traffic and retained data

DNS Daddy processes requested domain names, client attribution and resolution
outcomes. A query can reveal sensitive interests or activity, but it does not
prove that a person visited a website: applications, prefetching and background
services also make DNS requests. Findings and learned baselines are inferences
from that traffic, not verified statements about a person or device.

This guide describes the implemented data paths and controls. It covers more
than the query log because decisions, findings, external integrations and
recovery files can retain related information independently.

## Defaults and the effective configuration

Fresh installations select Forward (`off`) and use Cloudflare DoH forwarding
at `https://1.1.1.1/dns-query` and `https://1.0.0.1/dns-query`. Cloudflare
receives forwarded client names; the literal addresses avoid a separate DNS
bootstrap lookup. Local statistical learning and decision recording are
enabled, subject to their query-logging and client-attribution controls.
Existing installation choices and explicit mode pins are preserved. The
dashboard reports the
**effective** mode and which setting selected it; do not infer it from an old
configuration example.

Native is also the default transport profile. Optional encrypted forwarding
requires operator-approved endpoints and acknowledgement; changing the mode
alone does not enable that endpoint bundle. The selected transport remains active
in Forward mode. Native Learn/Live are deliberate choices that add direct
authoritative DNS traffic; an encrypted profile uses its approved endpoints
instead. See [encrypted DNS](encrypted-dns.md).

External reputation, investigation enrichment and webhook delivery start off.
Every installation supplies its own external accounts and credentials. A newly
saved provider is disabled unless deliberately enabled. There is no shared
DNS Daddy intelligence account or external model-training service behind the
local learner.

## What leaves the host

| Path | What may be disclosed | Control |
|---|---|---|
| Native DNS resolution | Names needed to walk from root to authoritative servers, source IP and DNS protocol metadata. Native traffic uses plaintext UDP/TCP port 53. QNAME minimisation limits which labels each delegation sees; it does not encrypt them. | With the native profile, Live uses this for client answers and Learn performs independent native lookups after forwarded resolution. Forward stops Daddybound validation and anchor refresh. The encrypted profile constructs no native recursive fallback. |
| Configured forwarded DNS | Requested names and DNS metadata go to the configured upstream URLs, over UDP, TCP, DoT or DoH as configured. The built-in defaults use Cloudflare DoH on TCP 443. | Used for Forward/Learn client answers with the native profile. Native Live does not silently fall back to this path. Encrypting a client connection does not encrypt native authoritative traffic. |
| Optional encrypted forwarding | The approved recursive resolvers receive requested names, supporting DNSSEC questions, anchor refreshes and protocol/source-IP metadata over authenticated TLS 1.3 DoQ, HTTP/3 DoH or HTTP/2 DoH. Encryption protects this network leg, not secrecy from the approved recipient or its onward resolution. | The operator chooses endpoint identities and literal bootstrap IPs. All modes use those endpoints while the encrypted profile is selected; there is no automatic provider discovery, plaintext fallback or external IP-discovery request. Client Live validates returned records locally. An explicit endpoint test sends a root DNSKEY question, not retained browsing history. |
| Daemon background hostname DNS | Feed, provider, webhook and other process-owned hostname lookups disclose those hostnames to the selected DNS recipient. They are separate from uploading client query logs. | Under the encrypted profile they use the same approved encrypted endpoints with no system-DNS fallback; under native they use system DNS. These background lookups do not receive Daddybound's independent client Live validation. |
| Threat-feed downloads | The configured feed service sees the resolver host's connection, request URL, user agent and refresh cadence. A bulk download does not upload the query log or the list of matching clients. | Enabled feed URLs, scheduled/startup refresh settings and explicit refresh actions. Local file feeds avoid the corresponding HTTP download. The bundled Threat Observatory connector is retired. |
| External API providers | The requested domain and protocol/account metadata required by the selected adapter. Providers can retain these requests or charge for them. The provider API is separate from ordinary DNS resolution. | Own credentials, provider enablement, policy scopes and global reputation/enrichment settings. Tests and manual enrichment require explicit consent. |
| Webhooks | Selected finding summaries can contain domains, client IPs and network IDs. Selected review events contain operator notes and actor labels. | Own receiver and signing secret, selected event types and explicit sharing consent. Receiver tests send a synthetic event without real query/finding data. |
| Operator exports and backups | Retained datasets or a recovery package are transferred to the authenticated management client; any subsequent sharing is controlled by the operator. | Explicit export/download/backup action and the operator's storage and retention procedures. |

**Cache-only reputation still permits external sharing:** a cache miss can
queue a background provider lookup. It avoids waiting for that lookup on the
DNS answer path. Reputation Off does not disable independently enabled manual
enrichment. A provider test is a real outbound request even while normal
reputation is off; where needed it uses the fixed name `example.com`.

GET investigation, policy preview, provider settings/templates/health and
learning/status routes read local state. They do not resolve the investigated
name, contact providers or train a model. Domain enrichment is a separate
consented POST. Provider workers recheck enablement before starting queued
work; a request already transmitted cannot be recalled. See
[external APIs](external-apis.md) and [webhooks](webhooks.md).

The authenticated server-address endpoint reads local interfaces only. When
host hardening prevents enumeration, it may report the server-side local IP of
the accepted management connection instead, with
`source: connection_local_address`, `partial: true` and an empty interface name. This
does not use Host/forwarding headers or the client/peer address, and never calls
an external “what is my IP” service. The result is not added to public health
or login responses or persisted as a new address-history table. A proxy,
tunnel, container or NAT can make it different from the address another device
must use. Protect dashboard access because interface names and local IPs are
deployment information.

The authenticated live-activity endpoint reads in-memory resolver counters;
it does not run a DNS probe or read query history. Its rolling 60-second
window and process-lifetime totals contain no names or client IPs and reset
when the process restarts. They continue to count requests when query logging
is disabled. Internal health checks reaching the DNS handler are included;
malformed wire messages and DoH authentication/parsing failures rejected
before the handler are outside this measurement. The endpoint still uses
the normal management authentication checks.

Client-to-DNS-Daddy encryption is configured separately from outbound DNS.
Choosing encrypted outbound forwarding does not turn plain client UDP/TCP
queries into encrypted requests or control the provider's onward transport.

Turning off query logging controls **retention and local analysis admission**.
It does not stop the DNS exchange needed to answer a query, withdraw consent
from separately enabled providers, or erase their caches or remote copies.
To prevent provider disclosure for a policy, also remove that policy from
provider scopes or turn the relevant provider modes off.

## Which privacy switches apply to new observations

Both the instance's `log.query_log` setting and the matched policy's
`logQueries` setting must permit a per-query record. The handler carries that
same decision into the following paths:

| Data path | Query logging off globally or for this policy | Client-IP logging off |
|---|---|---|
| Query rows and client-presence rows | No new rows for these requests | Query rows omit client IP/name; no client-presence row |
| Decision records and captured evidence | No new records from these requests | Recorded domain/policy decision omits client IP/name |
| Stored Daddybound observations | No row naming these requests; operational aggregate counters can still increase | Observation has no client identity; query correlation cannot reconstruct an address that was not stored |
| Heuristic detector admission | These requests do not enter the detector or create findings | Permitted traffic can still produce network-attributed findings without a client address/name |
| Statistical learner admission | These requests do not enter the learner | These requests also do not enter the learner, because its baseline requires client attribution |
| Resolution statistics | Aggregate counts still update | Aggregate counts still update |

`log.decision_records: false`, `detection.enabled: false` and
`learning.enabled: false` independently disable those components. Turning off
heuristic detection does not disable the separate statistical learner or DNS
validation. The learner's score alone never changes a DNS answer.

Privacy changes prevent new admission. They do not retroactively erase saved
records, completed model parameters, already accepted work or remote copies.
A previously accepted detector window may finish after a policy change.
Native aggregate counters and per-client rate-limit state still support DNS
availability; rate-limit state is bounded runtime memory, not a query-history
table or a source of client-address metric labels.

## What is written to disk

The main database is `dnsdaddy.db` in the data directory. SQLite WAL files can
contain committed recent changes. The database is **not encrypted as a whole**
by the application; restrict access to its directory and to the service
account. Credentials have separate field encryption, described below.

| Retained data | Contents and default lifetime |
|---|---|
| `query_log` | Requested name/type, time, outcome/reason, policy network, optional client address/name, protocol, elapsed time and cache status. `dnssecSource` records `native`, `encrypted_forwarded` or `upstream` validation provenance; an empty legacy value means unknown. Current settings do not relabel earlier rows. Default 7 days via `log.retention_days`. |
| `client_hourly` | Client address and the hour it was seen, only for privacy-permitted attributed query rows. Uses the same 7-day query retention. |
| `dnssec_observations` | Domain, local verdict/reason, recorded provenance and timing/work measurements. Native Learn (`native`), encrypted Learn (`encrypted_forwarded`), native Live (`native_live`) and encrypted Live (`encrypted_live`) remain distinguishable after mode/profile changes. Uses query-log retention. It is written asynchronously; missing correlation is not evidence of a successful validation. |
| `stats_hourly` and `blocked_domain_stats` | Per-network/category counts and blocked-domain counts. No client-IP column, but blocked names and network identifiers remain sensitive context. Default 90 days via `log.rollup_days`. |
| `decisions`, capture manifests and evidence snapshots | Original policy or local-protection outcome, explanation, attributed context and immutable cited evidence. Default 30 days via `log.decision_retention_days`. Captures expire with their decision. Legacy decisions explicitly disclose mutable-reference limitations. |
| `findings`, `finding_reviews`, `finding_review_history` | Measured signals and bounded example names, confidence/score limitations, domain/device/network context, operator classifications, notes and authenticated actor labels. Default finding retention 30 days; associated review rows cascade when the finding is removed. Reviewing does not rewrite original evidence. |
| `evidence`, `intel_verdicts`, `intel_enrichment` | Local/feed/provider claims, queried subjects and bounded provider response excerpts/context. Expiring records are pruned by their expiry; non-expiring operator/local claims can remain. These tables are not erased merely by switching query logging off. |
| Configuration and authentication | Networks/CIDRs, client names, policies/rules, enabled feeds, DNS transport selection and approved endpoint/bootstrap settings, provider/webhook settings, password/token hashes, sessions and credential ciphertext. Some configuration values themselves are sensitive. Retained until explicitly changed, removed or expired as applicable. |
| `config_change_history` | Actor, action, target, times, pending/completed/error outcome and redacted configuration differences. It currently has no automatic pruning. It does not include request bodies, authorization headers or plaintext credentials. |
| `webhook_outbox` and `webhook_stats` | Pending bounded event payloads, retry/lease state and durable delivery counters. Delivered or terminally failed payloads are removed. Any saved webhook configuration change discards pending payloads and counts the drops. This queue has its own lifecycle, independent of finding retention. |
| `export_sequences` | Three non-identifying insertion counters that preserve export boundaries and prevent new query-ID reuse after pruning or restart. They contain no names, client identities or per-query ledger. |

The normal retention sweep runs shortly after startup and hourly thereafter.
Bounded asynchronous queues can drop records under load; counters report these
losses. Retained data is not a guaranteed complete reconstruction of traffic.

### Files outside SQLite

- **`daddybound-learning.json`** retains completed per-client baseline keys,
  timestamps, counts, means and variances. It omits raw queried names and
  client display names, but is still sensitive behavioural metadata. It uses
  mode `0600`, bounded size, version checks and atomic checkpoint replacement.
  The default client idle lifetime is 24 hours; actively used models adapt
  across restarts. Disabling learning does not delete an existing checkpoint.
  See [learning](learning.md).
- **`daddybound-anchors.json`** retains public trust anchors, their lifecycle
  and hold-down progress. It contains DNSSEC trust state, not an operator's
  private signing key. Native material/answer caches remain in memory.
- **`secrets.key`** is the credential encryption key. Provider credentials and
  the webhook signing secret are AES-256-GCM ciphertext in separate database
  fields, bound to their identities. API reads return only status/hints. A
  database copy plus this key can decrypt them; key-file access therefore
  matters as much as database access.
- **Optional findings JSONL output** is a second copy of findings for a log
  shipper, disabled unless `detection.findings_file` is configured. It is
  written with mode `0640` and rotated. A shipper or SIEM manages its own copy.
- **Configuration, feed caches/local feeds and referenced TLS files** can be
  stored outside the database. Original YAML can retain a bootstrap password;
  a TLS key is a private credential. Do not put provider tokens in readable
  endpoint/configuration fields: use the separate secret input.
- **Operational logs** can include domain names, failure context or host paths,
  particularly at debug level or when reporting an internal error. Apply
  separate access and retention controls to service/container/proxy logs.
- **Exports and recovery files** are independent copies. Ordinary NDJSON
  exports are plaintext. `.ddbackup` is passphrase-encrypted and includes the
  database, matching credential key, relevant configuration, native/learner
  state and referenced recovery files. The passphrase is not stored by DNS
  Daddy. Original source YAML inside a backup may contain old secrets. See
  [recovery](recovery.md) for exact inclusions and exclusions.

The query table does not store full DNS response packets or subsequent web
connections. Evidence reasons and provider excerpts can still contain names,
addresses or other response-derived context, so that is not a promise that
only query-table columns hold sensitive information.

## Reducing collection

To keep aggregate statistics while withholding new query rows, decisions,
stored DNSSEC observations, heuristic admission and learning admission:

```yaml
log:
  query_log: false
```

For one network policy, turn off **Policies → Log individual queries**. To
retain permitted query rows without recorded client addresses or statistical
client learning:

```yaml
log:
  log_client_ip: false
```

To disable both analytical components while retaining DNS protection:

```yaml
detection:
  enabled: false
learning:
  enabled: false
```

These YAML options apply on restart. Daddybound mode, DNS transport and external API
modes have their own dashboard controls. If reducing outbound sharing, disable
reputation, enrichment and webhook delivery separately, and review enabled
feed URLs and the selected DNS transport. For shorter retention, set the
query, rollup, decision and finding windows deliberately; one setting does not
change all four.

## Investigation, exports and removing retained data

Investigation is a bounded view, not a complete subject export. For retained
query, decision and finding data, use the authenticated exports with the
appropriate client filter and `hours=0`, follow every `Link` continuation, and
check `X-Export-Skipped` on each page. A full first page is not the full
population. See [exports](exports.md); review history, configuration history,
provider caches and model state require their corresponding local records.

There is currently **no all-copies client erasure endpoint**. Deleting only
`query_log WHERE client_ip = ...` leaves other potentially attributable data.
Before planned removal, prevent new collection/delivery, stop the service for
an offline change and identify the relevant copies:

1. Query rows and correlated DNSSEC observation IDs, captured before removing
   the query-to-observation link; client-presence rows and friendly names.
2. Decisions and their captures, findings and associated review history,
   client model entries and any related current evidence. Domain-only evidence
   may be shared with other subjects and cannot always be attributed to one
   client after logs were pruned or anonymised.
3. Pending webhook payloads, exported files, JSONL output and operational
   logs. Disabling/reconfiguring the webhook clears its pending queue, but
   cannot withdraw an already delivered event.
4. Backups, restored installations and copies held by external providers or
   receivers. Database retention and local deletion do not control them.

Keep the database, key files and learner state in a consistent, usable state
when making offline changes. Do not describe a single SQL deletion or a
successful backup download as complete erasure. Protect exports collected for
review and give them a defined retention period as well.

## Management and deployment access

Management API authentication protects these read and write routes. It does
not protect files from a host administrator, stop a permitted API token from
reading the data it can access, or secure a downloaded export afterward. Use a
protected management connection, limit host/service-account access, and keep
backup passphrases separate from the files they unlock.

Hosting the resolver in a particular region locates its local files there;
external DNS, feeds, opted-in providers, receivers and operator-held backups
can introduce other recipients or copies. Explain the actual chosen settings
and recipients to the people whose traffic is processed. This software's
reports and controls do not by themselves establish compliance with a legal,
insurance or certification requirement.

Report unintended disclosure through [SECURITY.md](../SECURITY.md).

Implementation references: [DNS admission and recording](../internal/dnsserver/handler.go),
[database schema](../internal/store/schema.sql),
[retention sweep](../cmd/dnsdaddy/main.go),
[learner persistence](../internal/learning/persistence.go),
[webhook queue](../internal/store/webhooks.go), and
[configuration history](../internal/store/audit.go).
