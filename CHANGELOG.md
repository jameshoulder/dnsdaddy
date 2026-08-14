# Changelog

All notable changes to DNS Daddy.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**What "breaking" means here.** This project has three separate compatibility
surfaces, and they do not move together:

| Surface | Promise |
|---|---|
| **Configuration** | A config file that worked keeps working. New options get defaults that preserve existing behaviour. |
| **REST API** (`/api/v1`) | Additive within v1. Fields may be added, never removed or repurposed. |
| **Finding schema** | Versioned independently (`schemaVersion`). Additive within a major version. |

Database migrations are additive columns with defaults, so downgrading to the
previous binary keeps working. That is deliberate: rolling back a bad release
should be swapping a binary, not restoring a backup.

---

## [Unreleased]

### Added

**Behavioural detection engine** (`internal/detect`) — experimental.

Six detectors turn query behaviour into structured, explainable findings:

| Detector | Event type | Max severity |
|---|---|---|
| `dns_tunnel` | `dns_tunnel_suspected` | high |
| `dga_like` | `dga_like_domains` | high |
| `nxdomain_anomaly` | `nxdomain_burst` | medium |
| `txt_anomaly` | `txt_activity_anomaly` | medium |
| `dns_beaconing` | `dns_beaconing_suspected` | medium |
| `resolution_failure` | `resolution_failure_burst` | medium |

**Nothing in this engine blocks anything.** The detectors observe, score,
explain and alert. Enforcement stays with the policy and threat-feed engine,
which acts on curated intelligence rather than inference. `DetectorInfo.Enforces`
is published in the API and is `false` everywhere, asserted by a test.

**All six are experimental.** Thresholds are calibrated against synthetic
corpora rather than production traffic, and no real-world false-positive rate
has been measured. Every finding carries a `maturity` field saying so.

The engine runs entirely off the resolution path: observations go onto a
buffered channel and are dropped-and-counted when full. A test drives 200
queries through a handler whose detection queue is full and whose only detector
panics if reached, asserting resolution neither stalls nor changes.

- Findings carry the signals that produced them with floors, ceilings, weights
  and contributions, so a score can be reproduced by hand — plus evidence,
  false-positive guidance, investigation steps, and ATT&CK mappings with
  rationale. Mappings describing what the behaviour *would* be if malicious are
  flagged `hypothesis: true`.
- Detector state is bounded with O(1) approximate-LRU eviction, so a flood of
  unique names cannot make the resolver allocate without limit.
- A shipped exclusion list covers reputation services, CDNs and `.arpa`, whose
  normal traffic is shaped exactly like the behaviour being hunted. Extend it
  with `detection.excluded_domains`.

**DNSSEC telemetry.** Outgoing queries set the AD bit ([RFC 6840] §5.7) so a
validating upstream reports its verdict, recorded per query as `validated`,
`unvalidated` or `servfail`, and shown in the query log and dashboard.

This is **not** local DNSSEC validation and is not presented as such anywhere.
It records the upstream's conclusion, which is strictly weaker — a lying
upstream will set the bit happily. `unvalidated` covers an unsigned zone and a
non-validating upstream equally, because a forwarder cannot distinguish them.

**Findings storage and API.**

- `findings` table with a 30-day default retention, pruned alongside the query
  log.
- `GET /api/v1/findings`, `/findings/{id}`, `/findings/summary`,
  `/findings/export` (NDJSON, oldest first) and `/detectors`.
- The detector catalogue is generated from the running detectors, so what the
  software claims about its own capability cannot drift from what it does.
- Optional NDJSON sink (`detection.findings_file`) for a log shipper. Off by
  default: it is browsing-history-derived data in a second place.
- Prometheus counters for observations, drops, exclusions, suppressions and
  findings by type and severity.
- A **Detections** page on the dashboard showing each finding's signal
  breakdown, evidence, ATT&CK mappings and investigation steps.

**The lab** — `docker compose --profile lab up --build`.

An isolated, entirely offline environment: its own resolver, its own synthetic
upstream, and seven scenario clients on a private network. Every name is under
`.example` or `.test` ([RFC 2606], [RFC 6761]); no query leaves the machine and
no malicious infrastructure is involved.

Two of the seven scenarios are designed to produce **no** findings.
`high-entropy-subdomains` generates genuinely random labels and asserts silence
— the concrete answer to "high entropy means malicious".

- `cmd/dnsdaddy-lab` generates the traffic and, with `-sink`, serves the zone.
  Deterministic from a seed.
- Each scenario has a document covering objective, expected signals, why it
  fired, ATT&CK mapping, false positives, investigation and mitigation.
- The `lab` Docker stage keeps these tools out of the production image.

**Documentation.**

- `docs/capabilities.md` — the source of truth for Available / Experimental /
  Planned.
- `docs/threat-model.md` — assets, boundaries, actors, 20 threats, mitigations
  and residual risk.
- `docs/detection/` — pipeline, finding schema, ATT&CK policy, tunnelling in
  depth.
- `docs/threat-hunting/` — six executable hunts, plus five that are not
  possible and what each would need.
- `docs/dns-security/` — protective DNS, DNSSEC, DoH/DoT and bypass.
- `docs/siem.md` — Wazuh, Elastic, Splunk, Sentinel.
- `docs/roadmap.md` — ordered by what would have to be true first.

### Changed

- `dnsserver.Handler` reports each query to the detection engine after the
  response is decided. Nil-safe and non-blocking.
- The AD bit is now stripped from responses to clients that set neither DO nor
  AD ([RFC 4035] §3.2.3). Previously the upstream's AD bit passed through
  unchanged; because telemetry now sets AD on every upstream query, passing it
  on would tell a client its answer was authenticated when it never asked.
- `resolver.Result` carries `Rcode`, `Validated` and `MinTTL`.
- `store.QueryEvent` and the `query_log` table carry a `dnssec` column, added
  by an idempotent migration.
- The query log shows a DNSSEC column.
- `docs/architecture.md` and `docs/privacy.md` cover the detection path and
  findings storage.

### Configuration

All additive with defaults preserving existing behaviour.

| Option | Default | Notes |
|---|---|---|
| `dns.dnssec_telemetry` | `true` | Sets the AD bit on upstream queries. |
| `detection.enabled` | `true` | Alert-only and off the resolution path. |
| `detection.min_severity` | `low` | |
| `detection.retention_days` | `30` | |
| `detection.eval_interval` | `30s` | |
| `detection.cooldown` | `15m` | |
| `detection.buffer_size` | `4096` | |
| `detection.findings_file` | *(empty)* | NDJSON sink, off by default. |
| `detection.excluded_domains` | *(empty)* | Added to the built-in list. |
| `detection.disable_default_exclusions` | `false` | |
| `detection.window_scale` | `1.0` | Demonstration setting; see the docs. |

`dns.dnssec_telemetry` defaulting to on is the only change in outbound
behaviour. It sets one header bit that standards-compliant resolvers already
handle, does not request DNSSEC records, and does not change response sizes.
Set it to `false` to restore the previous wire behaviour exactly.

### Security

- Findings and the NDJSON file are written 0640; the metrics endpoint exposes
  counts only, asserted by a test that no domain or client IP from a finding
  reaches `/metrics`.
- Detection state is bounded and its eviction is O(1), so it cannot be used to
  exhaust memory or to make the resolver do quadratic work per query.

---

## [0.1.0] — Initial public release

First public release: a single Go binary and one SQLite file.

- Forwarding resolver over UDP, TCP, DNS-over-TLS and DNS-over-HTTPS, with
  DoT upstreams by default.
- Category filtering from public threat-intelligence feeds, cached to disk so
  a restart never leaves a window with no blocklist.
- Per-network policies matched by CIDR, or by DoH token for roaming clients.
- Query logging with plain-English reasons, hourly rollups outliving the raw
  log, and Markdown reports.
- Answer cache with generation-counted invalidation and request collapsing.
- Client ACL, startup refusal to run as an open resolver, and RFC 8482 ANY
  handling.
- Embedded dashboard with no build step, REST API with OpenAPI 3.1, and
  Prometheus metrics.
- CI running tests with the race detector, cross-platform builds, an
  end-to-end smoke test, CodeQL, gosec, govulncheck, Trivy, fuzzing and an
  SBOM.

[RFC 2606]: https://www.rfc-editor.org/rfc/rfc2606
[RFC 4035]: https://www.rfc-editor.org/rfc/rfc4035
[RFC 6761]: https://www.rfc-editor.org/rfc/rfc6761
[RFC 6840]: https://www.rfc-editor.org/rfc/rfc6840
