# What DNS Daddy actually does

This page is the single source of truth for what is implemented, what is
experimental, and what is only an intention. Everything else in this repository
is expected to agree with it.

The distinction is deliberate and load-bearing. A security tool that describes
planned functionality in the present tense is worse than one that describes
less, because someone will rely on the missing part. If you find a claim
anywhere in this repository that this page does not support, that is a bug —
please [open an issue](https://github.com/jameshoulder/dnsdaddy/issues).

## The three categories

| | Meaning |
|---|---|
| **Available** | Implemented, covered by tests, documented, and expected to work. Not the same as *audited* — see the caveat below. |
| **Experimental** | Implemented and tested, but validated only against synthetic data or a small number of deployments. Behaviour and thresholds may change. Do not build a control you depend on around these. |
| **Planned** | Not implemented. Nothing in the code does this today. |

**The caveat that applies to all of it:** DNS Daddy is an unaudited,
AI-assisted personal project. "Available" means the feature exists and its
tests pass. It does not mean the feature has survived adversarial review by
anyone qualified. See [SECURITY.md](../SECURITY.md).

---

## Available

### DNS resolution

| Capability | Notes |
|---|---|
| Forwarding resolver over UDP and TCP | Used when Daddybound is Off or in Learn mode. Live uses native recursion and validation instead; see Experimental below. |
| DNS-over-TLS listener | Requires a certificate; off unless configured. |
| DNS-over-HTTPS endpoint | RFC 8484, at `/dns-query/<token>`. |
| Encrypted upstream (DoT) | The default configured forwarding transport, with certificate verification. It applies to Off/Learn client answers; native Live contacts authoritative servers over plaintext UDP/TCP 53. |
| Answer cache | The forwarding cache is bounded, sharded and TTL-aware, and invalidated on feed or policy change. Live never returns an answer from that forwarding cache. |
| Request collapsing | Identical concurrent questions share one upstream flight. |
| ANY refusal (RFC 8482) | On by default; ANY is the classic amplification lever. |
| Client ACL | Source addresses outside the list are REFUSED before any work. |
| Open-resolver startup refusal | A public listener with no ACL is a startup error, not a warning. |
| Per-client rate limiting | A bounded token bucket uses the attributed client identity. Defaults are 50 questions/second, burst 100 and at most 4096 tracked clients; full state does not evict active clients to give them fresh buckets. Counters report limiting and state overflow. Configuration is versioned and persisted. |

### Filtering

| Capability | Notes |
|---|---|
| Category blocking from public threat feeds | Malware, phishing, C2, cryptomining on by default; ads, adult, gambling, newly-registered available. |
| Custom allow and block lists, per policy | Allow-list wins, so an operator can always override a bad feed entry. |
| Per-network policies | Matched by CIDR. The most specific prefix containing the client wins, decided per CIDR rather than per network, so a network's unrelated narrow range cannot promote its broad one. Equal prefixes in two networks resolve by network name, deterministically. |
| Roaming attribution by DoH token | A per-network token in the DoH path applies that network's policy from any IP. |
| Configurable block response | NXDOMAIN, 0.0.0.0/::, or REFUSED. |
| Immediate allow-listing | The answer cache is purged on a policy change, so a fix applies on the next query. |
| DNS rebinding protection | Enabled by default on both forwarding and native answers. Checks IPv4/IPv6 addresses, alias records and SVCB/HTTPS address hints. Explicit domain/CIDR exceptions support internal and split-DNS deployments; a domain exception applies to the original question rather than a target name supplied by an alias. Exceptions do not disable policy filtering or client admission. |

### Telemetry

| Capability | Notes |
|---|---|
| Per-query logging with plain-English reasons | Non-blocking and batched; drops rather than delaying a lookup. |
| Hourly and daily rollups | Survive query-log pruning, so reporting history outlives browsing history. Failed resolutions are counted in the same hourly rows as the queries they are a fraction of. |
| Overview measurements | `GET /api/v1/overview` carries a `measured` block stating each count separately with its window and scope: configured, enabled, permitted and traffic-bearing networks; attributed clients in the window or the reason there is no count; feeds enabled, loaded, failing and never downloaded; blocking policies and whether any enabled network uses one; blocked queries split into security, precaution, preference, custom and unclassified; and an error rate derived from one window, or the reason it cannot be. No field combines two scopes and none is a verdict about protection. |
| DNSSEC status per query | Records validation status together with its source: upstream for forwarded answers, native for Live answers. Learn observations remain separate from the already-decided forwarded response. See below and [dns-security/dnssec.md](dns-security/dnssec.md). |
| Prometheus metrics | Hand-rolled, no client library. |
| Markdown reports | A period summary written for someone who does not run the network. |
| Complete query, decision and finding exports | Dedicated `/api/v1/{queries,decisions,findings}/export` endpoints return bounded NDJSON pages with a frozen time window, insertion high-water, continuation links and emitted/skipped counts. They report the final page explicitly. Retention can still remove rows during a walk, and review-state filters use the current review state; this is not an exactly-once change feed. See [exports.md](exports.md). |
| Daddybound status | `GET /api/v1/dnssec/status` reports configured/effective mode and its source, actual client answer path, plaintext native transport, anchor lifecycle and refresh/persistence health, bounded work and observation counters, and sample limitations. Live is an available experimental mode, with its actual enforcement and errors reported; a readiness label is not a claim of production reliability. Polling status resolves nothing or edits trust state. |
| Finding review | Each finding carries a review record beside it: `new`, `acknowledged`, `resolved` or `false_positive`, with a bounded plain-text note, a version for optimistic concurrency, the authenticated actor as the API knows it (`session:admin` or `token:<name>`) and a change history. The finding's own measurements are never modified, and a review changes nothing about enforcement: a false positive disables no detector, relaxes no policy, deletes no evidence and allows no domain. See [detection/README.md](detection/README.md#reviewing-findings). |
| Domain and client investigation | `GET /api/v1/investigate/domain/{domain}` and `/client/{ip}`, and the dashboard's Investigate page: what the query log recorded for one exact name or address, the decisions stored at the time, a read-only preview of what the current configuration would decide now, what is on file and whether any of it ever decided a query, and related experimental findings and Daddybound observations — each in its own section. Nothing is written and no external provider is contacted; a name an external provider would be asked about is reported as *not evaluated*, never guessed allowed. Enrichment is a separate POST that uses the configured providers within their existing mode and budget. Exact name match only: it is not a substring search, a passive-DNS history, an IP-reputation source or a device discovery tool. |

### Management

| Capability | Notes |
|---|---|
| Embedded dashboard | No build step, no npm tree; served from the binary. |
| REST API with OpenAPI 3.1 | Each build serves its own spec at `/openapi.yaml`. |
| Session and bearer-token authentication | Bcrypt password, rate-limited login, same-origin checks on cookie-authenticated writes. |
| Single static binary | `CGO_ENABLED=0`, pure-Go SQLite, cross-compiles from a laptop. |
| Bring-your-own external APIs | Configure VirusTotal, Google Safe Browsing or a custom HTTP/JSON adapter from External APIs. Each user provides their own keys, stored encrypted with a separate master key and never returned in plaintext. Providers, outbound tests, reputation modes and optional enrichment require deliberate configuration/consent; default reputation is Off and enrichment is disabled. See [external-apis.md](external-apis.md). |
| Configuration history | Authenticated management writes record a durable intent followed by actual redacted before/after values and outcome. Writes are refused if their initial journal entry cannot be saved; post-write failure is explicitly reported as potentially changed. This is not a transaction spanning the entire request or a tamper-proof audit system. See [recovery.md](recovery.md). |
| Encrypted backup and offline restore | Authenticated download and CLI package the consistent SQLite snapshot, provider/webhook master key, effective/source configuration, native anchor and learned state, feed caches, local feeds and referenced TLS material. Restore verifies authentication/checksums/key agreement, rewrites paths and revokes sessions in a new private directory; it never replaces a live database. See [recovery.md](recovery.md). |
| Optional webhooks | One user-configured HTTPS receiver, HMAC signatures with an encrypted user-owned signing secret, a bounded persistent outbox and bounded asynchronous retries. Finding creation and optional review events are captured transactionally. Disabled by default; delivery is at least once and receivers must deduplicate by event ID. See [webhooks.md](webhooks.md). |

### Diagnostics

| Capability | Notes |
|---|---|
| `dnsdaddy doctor` | Reads configuration and the database, and sends real DNS queries at the configured listeners and through each upstream. Reports SYSTEM, DATABASE, DNS LISTENER, CLIENT ACCESS, UPSTREAM, WEB INTERFACE and THREAT INTELLIGENCE as PASS/WARN/FAIL with the evidence behind each verdict. Changes nothing — the database is opened read-only — and exits non-zero on failure. `--json` for machine consumption. |
| Client-access cross-check | Reports a network configured in the dashboard whose addresses the **effective** client ACL does not permit — the bootstrap list from configuration unioned with the dashboard's own permissions, with both sources named separately. Surfaced at startup, at `GET /api/v1/diagnostics`, in `dnsdaddy doctor`, and on the dashboard. Coverage is decided by single-prefix containment, so two allowed prefixes that between them cover a network are reported as *partial* rather than *full* — it over-warns in a rare case rather than under-warning in a common one. |
| Dashboard-managed resolver access | A network can be permitted to query the resolver from the dashboard, in force on the next query with no restart. Enforced server-side: a default route is refused outright, and a publicly routable range needs an explicit acknowledgement recorded per range. See [docs/deploy.md](deploy.md#who-may-use-the-resolver) for the precedence rules and the properties that can surprise — an empty bootstrap ACL stays unrestricted, there are no deny rules, and permitting a catch-all you created grants nothing because it has no ranges of its own. The built-in **Default** row is the exception: its control is *Ad-hoc DNS access*, which decides whether unmatched clients already inside `dns.allowed_client_cidrs` are served. Off on a new installation, turned on once when upgrading an installation that was already serving them, and never able to widen that list. |
| Public-exposure warning | Names each permitted range that is reachable from the internet, every time diagnostics run, from **both** sources — a range permitted through `DNSDADDY_ALLOWED_CLIENT_CIDRS` exposes a resolver exactly as much as one permitted in the dashboard. Each is labelled with the setting responsible. It never resolves itself and never claims a firewall state: DNS Daddy cannot see a cloud security group and does not change one. |
| First-run guidance | The dashboard uses measured refusals and the effective ACL, including the Default network's ad-hoc access setting. Being inside a private address range does not by itself prove a client is admitted; inspect the effective permissions. |
| Port-conflict attribution | When nothing answers, distinguishes "nothing is listening" from "another process holds the port" and names that process by reading `/proc` socket inodes. Naming a process owned by another user needs root; without it the check says so rather than guessing. |
| Management-exposure detection | Records management requests arriving over plain HTTP from a public address and raises them as a failure. Evidence, not inference: the process cannot see its own port publishing, so this fires only on traffic that has actually arrived. Silent for private, loopback and carrier-grade-NAT sources, for TLS, and for `/dns-query`. |
| `dnsdaddy_client_refused_total` | Queries rejected on their source address, in `/metrics`. Deliberately unlabelled by address: the refusal path writes no query-log row so an unauthorised source cannot fill the disk, and a metric label would reintroduce that. |
| Client-access gauges | `dnsdaddy_networks_total`, `dnsdaddy_networks_resolver_permitted`, `dnsdaddy_client_acl_prefixes`, `dnsdaddy_client_acl_public_prefixes` and `dnsdaddy_client_acl_unrestricted`. Counts only, no labels — an ACL is exactly the place where labelling by CIDR grows one series per network and then one per client. `client_acl_public_prefixes` counts **distinct** ranges across both sources, so permitting the same range in configuration and in the dashboard does not read as exposure doubling. Everything derivable from the live snapshot is exported unconditionally, so a momentary database error cannot silently drop the series an operator alerts on. |

### DNSSEC status has a source

In Off/Learn mode, the client answer comes from a configured upstream. DNS
Daddy requests and records the upstream AD verdict ([RFC 6840] §5.7). An
upstream `unvalidated` response does not distinguish an unsigned zone from an
upstream that did not validate. A Learn observation is independent native work
after that answer is decided and cannot change it.

In Live mode, Daddybound resolves and validates the records it actually returns
to the client. Secure answers and proven insecure delegations can be served;
bogus, indeterminate and operational failures return SERVFAIL. A client that
sets CD requests DNSSEC checking to be skipped, while policy and rebinding
checks still apply. Native status is explicitly distinguished from upstream
status. This client-serving validator is experimental; implementation and
default selection do not establish production reliability. See
[dns-security/dnssec.md](dns-security/dnssec.md).

---

## Experimental

### Daddybound — native resolution and DNSSEC validation

Daddybound implements DNS resolution and the DNSSEC chain of trust in Go,
using established cryptographic primitives and the DNS wire library. It is
separate from the incremental local traffic model described below.

| Mode | Client answer | Daddybound's effect |
| --- | --- | --- |
| **Live** (`enforce`) | Native authoritative recursion | Resolves the exact returned records and validates them. Secure/proven-insecure answers can be served; bogus, indeterminate, timeout and bounded-work failures return SERVFAIL. No silent upstream fallback. |
| **Learn** (`observe`) | Configured forwarding upstream | Independently resolves allowed queries after the answer is decided and records observations. A Learn verdict cannot change that answer. |
| **Off** (`off`) | Configured forwarding upstream | No native observer, trust-anchor refresh or native client-serving work. Local policy, rate limiting and rebinding protection remain active. |

**Fresh installations default to Live.** Upgrades retain an installation's
recorded Off/Learn selection. An explicit YAML mode pins the choice; otherwise
a persisted dashboard selection can be changed with acknowledgement of native
transport and failure behavior. A configuration default is a product decision,
not evidence that the validator is mature.

Native resolution uses plaintext UDP/TCP port 53 with QNAME minimisation.
Configured encrypted forwarding upstreams do not encrypt native traffic.
Live does not use the forwarding answer cache or silently fall back to an
upstream when validation cannot complete. This changes the deployment's egress
requirements, latency and failure behavior. A DNSSEC CD request skips
cryptographic checks only, not the other DNS Daddy controls.

Implemented protocol work includes the chain walk, authenticated NSEC/NSEC3
denial, CNAME/DNAME processing, native authoritative resolution, and managed
RFC 5011 root-anchor state. Live binds validation to the actual returned
answer rather than validating a separate lookup and borrowing its verdict.
The repository includes signed offline laboratories and optional differential
comparisons with libunbound and BIND `delv`.

Remaining evidence gaps include extended production deployment, real-device
behavior, constrained-hardware load, longitudinal anchor rollovers and
independent review. These are not filled by passing synthetic cases. Read
[daddybound/README.md](daddybound/README.md) before relying on Live in a deployment.

### Incremental local traffic learning

`learning.enabled` defaults to `true`. A local per-client model learns query
rate, longest-label length and entropy, name diversity, TXT usage and label
count from permitted observations. It uses Welford warm-up, then clipped
exponentially weighted updates. It scores each later window against the
previous baseline before learning from it.

Default readiness requires 12 eligible five-minute windows, at least 20
successful queries per eligible window, and at least one hour of history.
Blocked, failed, partial, lost, saturated or strongly anomalous windows are
excluded from normal-baseline updates. Bounds limit clients, observations,
window volume and diversity. Completed parameters persist in a versioned
owner-only checkpoint; raw queried names are not persisted in that file.
Global query logging, client-IP logging and policy logging determine whether
new observations may enter the model.

**A learned anomaly is an investigation lead, never a block decision.** The
score measures deviation from previous local behavior, not the probability of
maliciousness. Confidence is explicitly uncalibrated. Contamination guards do
not establish adversarial robustness, and unknown malicious traffic can still
influence warm-up. Finding reviews and provider labels do not silently retrain
the model. Read [learning.md](learning.md).

The checked-in [evaluation report](../labs/evaluation/RESULTS.md) separates
training and held-out synthetic cases and publishes false alerts, missed
scenarios, non-scored populations and denominators. The scenarios were written
by the implementation's authors. They are not independent ground truth or a
measured production false-positive rate.

### Behavioural detection

Six detectors that observe query behaviour and raise explainable findings.
Full detail in [detection/README.md](detection/README.md).

| Detector | Looks for | Max severity |
|---|---|---|
| `dns_tunnel` | DNS used as a data carrier | high |
| `dga_like` | Algorithmically generated domains | high |
| `nxdomain_anomaly` | Bursts of failed lookups | medium |
| `txt_anomaly` | Unusual TXT record usage | medium |
| `dns_beaconing` | Fixed-cadence check-ins | medium |
| `resolution_failure` | Domains persistently failing upstream | medium |

**Why experimental, specifically:** the thresholds are calibrated against the
synthetic corpora in `internal/detect`, not against production traffic. The
corpora were written from the same understanding of the problem that produced
the detectors, so they test internal consistency rather than real-world
accuracy. Nobody has yet run these against a large real network and measured a
false-positive rate.

**None of them block anything, and that is a design decision rather than an
unfinished feature.** They observe, score, explain and alert. A false positive
turned into a block is a working service silently broken by a heuristic, and no
confidence number makes that a good trade. Heuristic scores do not enter
blocking policy. Explicit rules and enabled intelligence sources make policy
decisions; native Live separately enforces DNSSEC validation of its answers.

Every detector reports its own maturity through `/api/v1/detectors`, so the
running software states this rather than relying on this page being current.

### Other experimental features

| Capability | Notes |
|---|---|
| NDJSON findings file | Format is stable within schema version 1.x. See [siem.md](siem.md). |
| `detection.window_scale` | A demonstration setting for the lab, not a tuning knob. |
| The lab (`docker compose --profile lab`) | See [labs/README.md](../labs/README.md). |

---

## Planned

Nothing here is implemented. Do not plan around any of it. Ordered roughly by
how likely it is to happen — see [roadmap.md](roadmap.md) for the reasoning.

| | Why it is not done |
|---|---|
| **Policy enforcement from behavioural findings** | Needs a measured false-positive rate first. Blocking on a heuristic with an unknown FP rate is not a feature. |
| **`safeSearch` enforcement** | The flag is accepted by the API and stored on the policy. The resolver does not act on it, and setting it changes nothing about how queries are answered. A known gap since the first release; the field is marked `deprecated` in the OpenAPI schema with that stated in the description, so a generated client cannot present it as a working control. |
| **Native syslog sink and vendor-specific notification adapters** | Generic signed HTTPS webhooks and versioned NDJSON exports are implemented; bespoke syslog, Slack, Teams and other adapters are not. |
| **Sigma rule export / detection-as-code** | Research. The finding schema was designed with it in mind. |
| **Word-list DGA detection** | The current heuristic measures surface statistics and misses dictionary-word generators completely. This is a research problem. |
| **Clustering, anycast, HA** | One server is one server. Run two and give clients both addresses. |
| **SSO, RBAC, multi-tenancy** | A single admin password plus API tokens. |
| **Blocking encrypted-DNS bypass** | DNS Daddy cannot stop a device resolving elsewhere. That needs a network control. See [dns-security/encrypted-dns.md](dns-security/encrypted-dns.md). |

---

## Things DNS Daddy will never do

Not "planned" — deliberately excluded.

**Block on an unvalidated heuristic.** The observe/score/explain/alert model is
the point of the detection engine, not a stepping stone to automatic blocking.
If enforcement is ever added it will be opt-in, per-detector, and gated on a
published false-positive measurement.

**Send hidden project telemetry.** There is no account, licence check or
project phone-home. Public threat feeds are downloaded from their listed
operators. DNS resolution necessarily sends DNS questions to the selected
upstream or authoritative servers. Optional external APIs and webhooks send
the documented domain/client/evidence data only after operator configuration
and consent; they use the operator’s own accounts and credentials.

**Claim to protect against what it cannot see.** A device using an external DoH
resolver bypasses DNS Daddy entirely. That is a property of DNS, and the
documentation says so rather than implying otherwise.

**Present an anomaly as calibrated certainty.** The local learner fits and
persists statistical parameters. Its score is a deviation measure with stated
limits, not an AI verdict, measured maliciousness probability or independent
proof that a domain is safe or harmful.

---

## Checking this page against the code

```bash
# What the running build says about its own detectors
curl -H "Authorization: Bearer dnsd_…" https://your-server/api/v1/detectors | jq

# The API surface this build actually serves
curl https://your-server/openapi.yaml

# What this build says about its own configuration and health
dnsdaddy doctor --json
```

These commands inspect the running build's reported capabilities, embedded API
contract and operational state. Compare the output with this page when reviewing
a change; metadata and documentation still require maintenance.

[RFC 6840]: https://www.rfc-editor.org/rfc/rfc6840#section-5.7
