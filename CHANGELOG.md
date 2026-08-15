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

### Security

- **Go toolchain raised to 1.25.13**, fixing five standard-library
  vulnerabilities that `govulncheck` reports as reachable from this code:
  [GO-2026-6218] (`net/url`), [GO-2026-6090] (`crypto/tls`), [GO-2026-6089] and
  [GO-2026-5026] (`net/http`), and [GO-2026-5972] (`encoding/asn1`).

  Every one of those packages is on a path that handles untrusted input here:
  `crypto/tls` terminates DoT and verifies upstream certificates, `net/http`
  serves the management API and downloads threat feeds, `net/url` parses
  operator- and API-supplied feed URLs, and `encoding/asn1` parses
  certificates. The pin is raised in `go.mod`, the Dockerfile, both workflows,
  and the documentation.

  Found by re-running `govulncheck` during an audit; the advisories were
  published after the previous CI run passed.

- **Semgrep now runs in CI**, with `--error`, against `p/golang`,
  `p/github-actions` and `p/secrets`. The repository already carried
  `// nosemgrep:` suppressions and a triage write-up from a hosted scan, but
  nothing re-ran the tool — so nothing checked that the suppressions still
  matched, or that a change had not reintroduced what they were written for.

  Re-running it found that **three of those suppressions had stopped working**:
  Semgrep honours the annotation only on the matched line or the one
  immediately above, and an intervening comment line silently disabled both
  `cookie-missing-secure` suppressions in `internal/api/auth.go`. They are
  fixed, and one new contextual false positive (`math/rand` in the lab, where
  reproducibility is the requirement) is suppressed with its reasoning. The
  tree is at zero findings. Written up in
  [docs/security/semgrep-triage-2026-07-29.md](docs/security/semgrep-triage-2026-07-29.md).

### Fixed

- `dnsdaddy-lab` no longer defaults to `127.0.0.1:53`. On a host running DNS
  Daddy that is the production resolver, so a bare
  `dnsdaddy-lab -scenario dns-tunnelling` would have written synthetic attack
  findings into real telemetry and sent reserved-TLD lookups to the real
  upstream. The default is now the lab resolver's port, and a standard DNS port
  (53 or 853) is **refused** rather than warned about: the refusal names the
  lab resolver's address and the `-allow-production-target` flag that overrides
  it, so the dangerous path is deliberate rather than accidental. Covered by
  `cmd/dnsdaddy-lab/main_test.go`, which also asserts that every scenario and
  every lab zone stays inside the reserved namespaces of RFC 2606 and RFC 6761.
- `go.mod` had every direct dependency marked `// indirect`, which misrepresents
  the dependency surface and skews how Dependabot prioritises updates. Tidied,
  with a CI check so it cannot silently recur. No dependency versions changed.

### Changed

- **`safeSearch` is now marked `deprecated` in the OpenAPI schema**, on both
  `Policy` and `PolicyInput`, with a description that states the resolver does
  not act on it. The field has never been enforced and the README and
  `docs/capabilities.md` have always said so, but the machine-readable contract
  did not — a generated client presented it as an ordinary working boolean.

  The field itself is kept rather than removed: `/api/v1` promises fields are
  never removed within v1, and dropping the database column would break the
  guarantee that a downgrade is a binary swap. Two tests in `internal/api` hold
  the line — one fails if the "not enforced" wording is dropped from the spec,
  the other pins the value still round-tripping so an operator who set it does
  not silently lose it. The reasoning is written up in
  [docs/roadmap.md](docs/roadmap.md#safesearch-enforcement).

### Documentation

- **Corrected the blocklist capacity figures**, which understated memory use by
  roughly 3×. The index was documented at "roughly 55 bytes per blocked domain,
  about 30 MB for 500,000" in README, `docs/architecture.md` and
  `docs/threat-intel.md`. Measured: **165–215 bytes per domain, 80–105 MB for
  500,000**.

  The old figure was not achievable by the data structure — `Entry` holds three
  strings and is 48 bytes before the key or any of its bytes. A new test,
  `TestIndexMemoryPerDomainStaysWithinBudget`, measures it and fails above a
  per-case ceiling, so the published numbers now have a source of truth.

  It is published as a range rather than a single number because the index
  stores the names themselves: the same 500,000 entries cost 167 bytes each as
  short registrable names and 215 as the long third-level names a DGA feed is
  full of. The test measures all three shapes, so the range is the measurement
  rather than a hedge around one.

  Container limits (`GOMEMLIMIT=512MiB`, `mem_limit: 640m`) remain correct:
  even the top of the range leaves the index, the answer cache and the runtime
  comfortably inside them. Only the documentation was wrong.
- Binary size corrected from "~18 MB" to ~13 MB, and idle memory from "~35 MB"
  to ~14 MB before any feed loads. Both previously overstated.

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
[GO-2026-5026]: https://pkg.go.dev/vuln/GO-2026-5026
[GO-2026-5972]: https://pkg.go.dev/vuln/GO-2026-5972
[GO-2026-6089]: https://pkg.go.dev/vuln/GO-2026-6089
[GO-2026-6090]: https://pkg.go.dev/vuln/GO-2026-6090
[GO-2026-6218]: https://pkg.go.dev/vuln/GO-2026-6218
