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

- **DNS Daddy Threat Observatory as a first-class feed.**
  [threats.dnsdaddy.dev](https://threats.dnsdaddy.dev) is now in the shipped
  catalog as `dnsdaddy-observatory`, consumed through the same feed machinery,
  the same disk cache, the same category filtering, and the same plain-English
  block reasons as URLhaus or Phishing Army. There is no second blocking path.

  **It ships disabled.** Every other source in the catalog is one you can fetch
  and diff yourself, and a default that quietly reached back to a DNS Daddy
  server would cost that property for every install. Enabling it is one toggle
  on **Threat feeds**, and what it exposes — your server's IP and refresh
  cadence, never your queries — is spelled out in
  [`docs/threat-intel.md`](docs/threat-intel.md#the-dns-daddy-threat-observatory).

  A new feed format, `observatory`, reads the Observatory's JSON indicator
  document. It is the first non-line-based format and the first whose entries
  carry **their own categories**, so one feed row contributes to malware,
  phishing, C2 and cryptomining at once and a policy still gets exactly the
  categories it enabled. An indicator keeps every category it names, so one
  tagged both malware and C2 is blocked by a malware-only policy and a C2-only
  policy alike. An unrecognised label falls back to the feed's own category
  rather than losing the block to a vocabulary mismatch. IP indicators are
  skipped — there is no name to block.

  Individual indicators are parsed forgivingly — unknown fields skipped, a
  malformed entry costing only itself — but the document is not. A response
  that is not complete and well-formed is refused before it can replace the
  cached copy; see **Fixed** below.

  There is no per-feed filtering knob. The Observatory decides what belongs in
  `feed.json`; your policies decide what gets blocked. Indicator fields DNS
  Daddy does not act on (`severity`, `family`, `last_seen`) are parsed past and
  ignored. Wanting a subset is a question for the feed URL, not for DNS Daddy's
  configuration.

  The format is not reserved for our URL — point a custom feed at your own
  Observatory-shaped JSON, including over `file://`.

  The endpoint contract the client targets is documented in full in
  `docs/threat-intel.md`. The Observatory does not serve it yet; until it does,
  enabling the feed records an HTTP 404 against that feed and changes nothing
  else, which is one more reason it is off.

- **One-click activation for the Threat Observatory.** A card on **Threats**,
  and a compact **Threat intelligence** panel on the **Dashboard**, turn the
  feed on without a trip to the advanced feeds page. One click enables the
  built-in feed row, downloads it immediately rather than waiting up to twelve
  hours for the scheduler, validates and indexes it through the ordinary feed
  machinery, and reports what actually came back.

  The card is careful about the difference between enabled and working. It
  reads **Active** only once a download has validated; an enabled feed that has
  never succeeded says so plainly, and one that succeeded and is now failing
  shows how old the intelligence it is still enforcing is. A 404 — the state
  the Observatory's endpoint is in today — is explained as the endpoint not
  being live yet rather than shown as an HTTP status.

  Activation changes no policy. The card names which of malware, phishing, C2
  and cryptomining the operator's own policies enforce, and which Observatory
  indicators are therefore indexed but not blocked. Disable turns off that one
  feed, rebuilds the index so its domains stop being blocked straight away, and
  leaves every other feed and the built-in row itself intact.

  The Observatory stays an ordinary row on **Threat feeds** — URL, domain
  count, refresh status, last refresh, errors — and stays disabled by default.

- **`POST /api/v1/feeds/{id}/refresh`** refreshes a single feed, using the same
  download, validation, caching and index rebuild as a full refresh. Switching
  a feed on can now be verified in seconds rather than after a download of
  every third-party list.

- **`loaded` and `loadError` on every feed row**, reporting whether a feed's
  cached copy is in the index answering queries *right now*. This is the only
  field that can say a feed is protecting anything: `lastSuccessAt` records
  that a download once succeeded, and cannot know that the file it produced has
  since gone missing or stopped parsing. A feed in that state is skipped at
  every rebuild while its row still shows a healthy refresh, and the dashboard
  now says "Not blocking" rather than "Active".

- **`lastSuccessAt` on every feed row** (`feeds.last_success_at`), recording the
  last download that produced usable content. `lastRefreshedAt` moves on every
  attempt including failures, so on its own it could not answer the question an
  erroring feed actually raises: how old is the intelligence still being
  enforced. Existing rows read `null` until their first refresh after upgrade.

### Fixed

- **A domain listed under several categories is now blocked by a policy
  enabling any one of them.** The index previously kept a single category per
  domain and discarded the rest, so a domain claimed as both malware and C2 was
  invisible to a C2-only policy. Two feeds disagreeing about a domain hit the
  same defect.

  This was reachable before the Observatory — two feeds have always been able
  to classify a domain differently — but the Observatory makes it routine,
  because one indicator can name several categories at once.

  `Index` now keeps every claim: the most severe one is primary, and the rest
  live in a second map that is empty for the overwhelming majority of domains,
  which are claimed once. Policy evaluation goes through `LookupEnabled`, which
  returns the claim the policy actually enabled, so the query-log reason always
  names a category the operator ticked. A domain claimed once costs exactly
  what it did before; a second claim costs about 7 bytes.

  A related fail-open goes with it: a name listed only under categories a
  policy does not enable no longer shadows a parent it does. If `evil.com` is
  on a malware list, `login.evil.com` is blocked by a malware-enabling policy
  even when it also appears on an ad list.

- **A truncated or malformed Observatory download can no longer replace a
  working blocklist.** The cache was written atomically but never checked, so a
  body that stopped halfway — or an HTML error page served with status 200 —
  would be renamed over a good feed and silently unblock everything it carried.

  Downloads are now validated as complete, well-formed documents before the
  rename that installs them. A bad response leaves the previous copy in use,
  records the error against that one feed, and leaves every other feed alone —
  the same behaviour as a provider being unreachable. Cached files are
  re-validated when loaded, so a copy damaged on disk cannot half-populate the
  index either.

  This applies to the `observatory` format only. Every prefix of a hosts file
  is a valid hosts file, so there is nothing there to check.

### Changed

- **A feed download must now be a feed, not merely valid JSON.** The check that
  guards the cache was a token-level walk: it proved a body was complete and
  well-formed and nothing more, so `{"indicators":{}}`, or an API error served
  with status 200, passed it, replaced intelligence that was blocking traffic,
  and was recorded as a successful refresh — then failed at load time, leaving
  the feed contributing nothing while the dashboard showed it healthy.

  Validation is now the parser itself, run with nothing to emit to, so the two
  cannot drift: whatever the loader will refuse, the download gate refuses
  first, before the rename that installs it. It stays a streaming pass and
  buffers nothing. A document with no `indicators` array is refused outright.

- **`file://` feeds are validated before they replace the cache**, like every
  other feed. A local file is not more trustworthy for being local: it can be
  half-written by whatever produces it, truncated by a full disk, or repointed
  through a symlink between refreshes.

- **A rebuild reads the current feed configuration**, not the list the refresh
  that triggered it started with. A refresh reads its feed list, then spends
  minutes downloading; a feed disabled in that window used to be put back into
  the index by that refresh's own rebuild, blocking traffic after the database
  and the dashboard both said it was off, until the next refresh happened to
  correct it.

- **Enabling or disabling a feed now rebuilds the block index immediately**,
  from the local cache and without any network access. Previously a disabled
  feed kept blocking until the next scheduled refresh, up to twelve hours
  later.

- **Per-feed contribution counts are read back off the finished index**, rather
  than tallied while each feed loads, so a feed whose claim on a domain is
  superseded by a more severe one is no longer credited with it.

### Security

- **`golang.org/x/mod` raised to v0.40.0**, clearing [CVE-2026-56864] (a
  malicious `GOSUMDB` able to serve arbitrary module content) and
  [CVE-2026-56865] (`x/mod/sumdb/tlog` transparency-log tile verification
  bypass), both HIGH.

  Neither is reachable from anything DNS Daddy ships. `x/mod` is a module-graph
  requirement inherited from `miekg/dns` and `modernc.org/libc` build tooling —
  `go version -m` confirms it is linked into neither the resolver binary nor
  the lab binary, and `govulncheck`, which resolves by symbol, never reported
  it. Trivy reads `go.mod` declaratively, so it flagged the requirement
  regardless, and a HIGH finding sitting in CI indefinitely is its own cost.

  It cannot be raised alone. `x/mod` and `x/tools` require each other, so
  minimum version selection drags a chain: `x/mod v0.40.0` requires
  `x/tools v0.49.0`, which requires `x/net v0.58.0` and `x/sync v0.22.0`, and
  `x/net v0.58.0` requires `x/crypto v0.55.0`. All five move together or none
  does. `x/sys` already satisfied the new floor and is unchanged, as is every
  non-`x/` dependency.

  Of the five, only two contribute compiled code here: `x/crypto/bcrypt`, which
  hashes the admin password, and `x/net/publicsuffix`, which resolves eTLD+1 for
  the detection engine. DNS-over-TLS is stdlib `crypto/tls` and `miekg/dns`, and
  neither moves. Public-suffix results were diffed across both `x/net` versions
  over a 30-name corpus and are identical.

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
[CVE-2026-56864]: https://avd.aquasec.com/nvd/cve-2026-56864
[CVE-2026-56865]: https://avd.aquasec.com/nvd/cve-2026-56865
[GO-2026-6218]: https://pkg.go.dev/vuln/GO-2026-6218
