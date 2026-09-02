# DNS Daddy v0.3 — "Assurance": implementation plan

**Status:** proposed, awaiting maintainer sign-off on scope.
**Branch:** `claude/v0.3-assurance`, from `main` at `883f77b`.
**Baseline:** `gofmt`, `go vet`, `go build` and `go test ./...` all clean at that
commit — 21 packages, plus 161 dashboard tests. Recorded before any change.

---

## 0. How to read this

The brief for v0.3 describes a large amount of work. A substantial fraction of
it **already exists** in the repository, and a smaller but important fraction
**contradicts positions this project has already taken and written down**.

This plan therefore does three things before it proposes any code:

1. states what is already built, so v0.3 does not rebuild it;
2. states where the brief and the repository disagree, and proposes a
   resolution for each rather than quietly picking one;
3. cuts the scope to something a single maintainer can actually finish, using
   the brief's own priority order (§60) and its own governing principle (§70:
   prefer the less sophisticated feature whose behaviour is understandable).

Section 8 is the honest scope proposal. Sections 1–7 are the evidence for it.

---

## 1. Current-state assessment

### 1.1 Shape of the codebase

| | |
|---|---|
| Go | 51,286 lines across 164 files; 73 test files |
| Dashboard | 3,610 lines JS, 1,859 CSS, 2,019 test — no framework, strict CSP |
| SQLite | 17 tables, 12 indexes, 285 lines of `schema.sql` |
| Docs | 28 markdown files, ~8,500 lines |
| API | 63 registered routes, OpenAPI 3.1 with contract tests |

Largest packages: `internal/api` (10.5k), `internal/store` (6.1k),
`internal/detect` (5.9k), `internal/apiprovider` (3.9k),
`internal/blocklist` (3.6k).

### 1.2 What the brief asks for that is already built

This is the most important section of the audit. **Roughly half of the
brief's §60 release scope is already in `main`.**

| Brief section | State | Where |
|---|---|---|
| §8–12 Provider framework, capabilities, health, custom HTTP, privacy notes | **Built** (merged in #50, days ago) | `internal/apiprovider` |
| §11 Provider SSRF controls | **Built and tested** — link-local + AWS IPv6 metadata refused at the dialer *and* at the URL before any dial, redirects never followed, 1 MiB response cap, per-provider timeout/rate-limit/breaker | `internal/apiprovider/dial.go`, `client.go` |
| §12 Provider privacy transparency | **Built** — every template carries a `privacyNote` and a `verification` statement, surfaced on each dashboard card | `registry.go`, `pages.integrations` |
| §16 Detector framework (observe/score/explain) | **Built** | `internal/detect/engine.go` — `Detector` interface with `Observe`/`Evaluate`/`Sweep`/`Tracked`, plus `DetectorInfo` with maturity and max severity |
| §17 DGA detection with interpretable contributions | **Built** — and it already produces exactly the "+22 entropy, +18 n-gram" explanation the brief asks for | `dga.go`, `analysis.go` |
| §18 DNS tunnelling detector | **Built**, with its own document | `tunnel.go`, `docs/detection/dns-tunnelling.md` |
| §19 NXDOMAIN anomaly detector | **Built** | `nxdomain.go` |
| §20 Beaconing detector | **Built** — the brief expected this might slip to v0.3.1 | `beacon.go` |
| §45 MITRE mapping, carefully worded | **Built** — already phrased as evidence-relevance, not detection claims | `mitre.go`, `docs/detection/mitre.md` |
| §49 Detector documentation standard | **Built, and better than asked** — `FalsePositives` and `NextSteps` ship *inside every finding*, not only in docs, so they are in front of the analyst at the moment they matter | `finding.go` |
| §50 Prometheus metrics, bounded, no unbounded labels | **Built** | `internal/api/metrics.go` |
| §51 NDJSON / SIEM export with a versioned schema | **Built** | `detect/sink.go`, `docs/siem.md` |
| §41 Threat model | **Built** — 416 lines | `docs/threat-model.md` |
| §39 Privacy and retention | **Partly built** — `docs/privacy.md` (264 lines), retention configured per data class (query log 7d, rollups 90d, findings 30d, intel by TTL) with an hourly pruner | `config.go`, `main.go:runRetention` |
| §15 Feed health | **Partly built** — `feeds` table records last refresh, last success, status, error; dashboard renders it | `schema.sql`, `pages.feeds` |
| §68 README positioning, Alpha honesty | **Already correct** | `README.md` |

The `Signal` type deserves a specific note, because it is the thing the brief's
§34 asks to build and it already exists in a stronger form:

```go
type Signal struct {
    Name, Description string
    Value             float64  // what was measured
    Floor, Ceiling    float64  // the band over which it contributes
    Normalised        float64  // Value mapped onto 0..1
    Weight            float64  // this signal's share of the score
    Contribution      float64  // Normalised * Weight
}
```

Every finding carries these. A score is reproducible by hand from the finding
alone. That is the "no unexplained proprietary score" property of §69, already
satisfied for behavioural detection.

### 1.3 What is genuinely missing

Nine real gaps. These are v0.3.

| # | Gap | Why it matters |
|---|---|---|
| **G1** | **No unified evidence model.** Evidence exists in three disconnected shapes — `blocklist.Entry{Category,FeedID,FeedName}` in the index, `detect.Finding` in the findings table, `intel_verdicts` from providers — and nothing joins them. | This is §7, the stated architectural foundation. Without it §14 (corroboration) and §29 (WHY) cannot be built honestly. |
| **G2** | **No decision record.** `policy.Decision` is `{Blocked, Reason, Category, Source, BlockMode, LogQuery}` and is discarded after the query log flattens it to strings. | You cannot ask "why was this blocked" and get the evidence back. §29 and §69 both depend on this. |
| **G3** | **No audit log.** Confirmed absent: no table, no writer, no reader. | §38. Policy edits, provider credentials and token creation currently leave no trace. |
| **G4** | **Investigation is shallow.** Global search filters the query log by domain and nothing else. No domain view, no timeline. | §28, §30. |
| **G5** | **Device identity is `clients(ip, name, updated_at)`.** | §25. No persistent identity, no identity source, no confidence. |
| **G6** | **No policy simulation or policy explain.** | §23, §24. |
| **G7** | **No first-seen domain index.** Approximated from the query log, so it is only as good as 7-day retention. | §21 — and the repo's own roadmap already calls this out as cheap and worth doing. |
| **G8** | **No `docs/assurance/`, no `SECURITY-ASSURANCE.md`.** | §40, §48. Material exists but is scattered across 28 files. |
| **G9** | **Feeds have no per-indicator lifecycle.** A feed refresh replaces the index wholesale; there is no first-seen/last-seen/expiry per indicator, so §13's lifecycle and §14's corroboration have nothing to stand on. | §13, §14. |

---

## 2. Where the brief conflicts with this repository

Three conflicts. Each is a case where the brief asks for something the project
has already considered and deliberately not done, **with the reasoning written
down**. I am not going to silently overrule a documented position.

### 2.1 Behavioural enforcement (brief §22 vs `docs/roadmap.md`)

The brief's §22 lists policy actions `allow / alert / block` over behaviour
categories (DGA, tunnelling, beaconing, NXDOMAIN).

`docs/detection/README.md` states the opposite as a *position*, not a gap:

> Behavioural detection does not enforce policy in DNS Daddy, and this is not a
> missing feature. […] A false positive turned into a block is a working
> service silently broken, at a time nobody chose, with a cause nobody will
> guess. The engineer who has to explain that outage will not be comforted by a
> confidence of 0.83.

And `docs/roadmap.md` sets a hard precondition:

> **Hard precondition: a published false-positive rate.** Not an intention to
> measure one — a measurement.

**Proposed resolution.** Build the policy model so behaviour categories are
first-class and can carry `allow` and `alert`. Do **not** ship `block` for
behavioural categories in v0.3.0. Instead ship the thing that unlocks it: the
false-positive testing methodology of §44. The brief's own §16 ("experimental
detectors default to ALERT ONLY") and §70 point the same way. This costs
nothing and keeps the project's word.

### 2.2 Device behavioural baselines (brief §25J vs `docs/roadmap.md`)

The brief asks for per-device behavioural baselines that feed detection.
The roadmap places this in *Medium — needs design* with a named blocker:

> An attacker present while the baseline is learned teaches the system that
> their behaviour is normal — and a baseline that learns continuously
> un-learns an ongoing attack. This is a real research problem, not a
> configuration option.

**Proposed resolution.** Ship **descriptive** per-device statistics — "this
device normally makes 5–20 queries an hour; right now it is making 298" — as an
investigation aid on the device profile, computed from data already in
`stats_hourly`. Do not let it produce findings or influence scoring in v0.3.
That gives §25J's operator value without pretending the poisoning problem is
solved.

### 2.3 Asset Intelligence and active discovery (brief §25A–§25Z)

This is 26 lettered subsections asking for: persistent asset identity,
multi-signal correlation across DHCP/ARP/NDP/mDNS/MAC-OUI, device
classification, active network discovery (ARP sweeps, ICMP), a network map with
a security overlay, and integrations with UniFi/pfSense/OPNsense/MikroTik.

Four problems, in order of severity:

1. **It is a second product.** Realistically several months on its own. Adding
   it to the other 21 items in §60 makes the release undeliverable.
2. **Active discovery fights the deployment model.** ARP and NDP need raw
   sockets — `CAP_NET_RAW` — which the Docker deployment deliberately does not
   grant, and which the container runs unprivileged specifically to avoid. §25F
   asks for it disabled by default; the capability still has to be *grantable*,
   which means documenting how to weaken the container. That is a real cost
   against §4's "small attack surface".
3. **Most signals are unavailable in the common deployment.** A resolver in a
   container on a VPS, or on a different L2 segment from its clients, sees
   neither ARP nor DHCP nor mDNS. The honest output for most installs is
   "Unknown", which §25I correctly says is acceptable — but a feature whose
   honest answer is usually "unknown" is a poor use of the release's budget.
4. **It is the least aligned with the release's own name.** "Assurance" is
   about understanding and trusting security decisions. Asset intelligence is
   inventory.

**Proposed resolution.** Take the part that is cheap, useful, and needs no new
privileges — **persistent device identity with explicit source and confidence**
(§25, §25B, §25D, §25I) — and defer the rest to a v0.4 line where it can be
designed properly. Concretely, v0.3 ships:

* a persistent `devices` table with a stable ID independent of IP;
* identity from signals already available: DNS source IP, configured network,
  operator-set name, reverse DNS (opt-in), DHCP lease file where the operator
  points at one;
* every inferred property carries its **source** and a **Low/Medium/High**
  confidence with the evidence behind it;
* `Unknown` as a first-class, well-rendered state;
* a device investigation profile (§25P) built from real observations.

v0.3 does **not** ship: active ARP/NDP/ICMP discovery, MAC-OUI vendor
databases, mDNS parsing, device-type classification, vendor controller
integrations, or the network map. The architecture in §25Z (observation →
identity evidence → correlation → asset) is respected, so the deferred layers
have something to attach to.

---

## 3. Proposed architecture

The organising idea is small: **make the thing the resolver already decides
into a record, and give every input to that decision a common shape.**

```
                    ┌───────────── evidence sources ─────────────┐
  DNS query  ──►    │ feeds        providers      detectors      │
                    │ (blocklist)  (apiprovider)  (detect)       │
                    └──────┬────────────┬──────────────┬─────────┘
                           │            │              │
                           ▼            ▼              ▼
                        ┌──────────────────────────────────┐
                        │  evidence  (one normalised shape) │   G1
                        └──────────────┬───────────────────┘
                                       ▼
                        ┌──────────────────────────────────┐
                        │  assessment (what we think, why)  │
                        └──────────────┬───────────────────┘
                                       ▼
                        ┌──────────────────────────────────┐
                        │  policy  →  ALLOW / ALERT / BLOCK │
                        └──────────────┬───────────────────┘
                                       ▼
                        ┌──────────────────────────────────┐
                        │  decision record                  │   G2
                        └──────────────┬───────────────────┘
                                       ▼
                          UI "why?"  ·  API  ·  NDJSON
```

Two deliberate constraints on this diagram:

**The hot path does not change shape.** Today `Evaluate` consults allow-list →
block-list → category index → (optionally) reputation cache, and returns. That
stays. Evidence assembly for a *blocked* query happens after the answer is
sent, on the query-log path, which is already asynchronous and already
lossy-by-design under load. An allowed query assembles nothing.

**Evidence is written, not derived on read.** Reconstructing "why" at display
time from feeds that have since refreshed would produce explanations that
change after the fact — the opposite of an audit trail.

### 3.1 The evidence model (G1)

```go
// internal/evidence
type Kind string   // feed | provider | detector | local | operator

type Evidence struct {
    ID         string
    Subject    Subject      // {Type: domain|ip|device, Value: string}
    Kind       Kind
    Source     string       // feed ID, provider ID, detector name, "operator"
    SourceName string       // display name at the time it was recorded
    Claim      string       // "malware infrastructure"
    Category   string       // malware | phishing | c2 | ...
    Confidence Confidence   // low | medium | high — see below
    ObservedAt time.Time
    ExpiresAt  *time.Time
    Detail     map[string]any
}
```

`Confidence` is deliberately a three-value enum, not a float. A float invites
arithmetic across sources that have no common scale — the "two feeds =
definitely malicious" trap §14 warns about. Where a source has its own numeric
score it goes in `Detail` and is displayed as that source's number, attributed
to it.

Corroboration (§14) is then presentation and assessment, not arithmetic: the
assessment names how many independent sources agree and of what kind, and the
UI shows each one separately. No blending.

### 3.2 The decision record (G2)

One row per *enforced or alerted* decision — not per query. Blocked and alerted
queries are a small fraction of traffic, which keeps this bounded.

```
decisions(id, ts, query_log_id, subject, action, category, policy_id,
          policy_path, device_id, explanation_version)
decision_evidence(decision_id, evidence_id, contributed BOOLEAN)
```

`policy_path` is the readable trace §24 asks for
(`global → network:Office → policy:Standard → category:malware → BLOCK`).
`contributed` distinguishes evidence that was *present* from evidence that
*changed the outcome* — §7 asks for exactly this.

### 3.3 Schema changes

New tables: `evidence`, `decisions`, `decision_evidence`, `audit_log`,
`devices`, `device_identities`, `domain_first_seen`, `indicator_lifecycle`.

Added columns: `query_log.decision_id` (nullable), `clients.device_id`
(nullable).

Migration strategy is the project's existing one, unchanged: `CREATE TABLE IF
NOT EXISTS` in `schema.sql` applied idempotently at open, column additions
through the existing `addedColumns` path that treats a duplicate-column error
as success. **No versioned migration runner**, deliberately — that is what
makes rolling back a bad release a binary swap rather than a restore. All new
tables are additive and all new columns are nullable, so the previous binary
continues to work against the new database.

Retention: every new table gets a documented retention rule and joins the
existing hourly pruner. `evidence` expires by `expires_at`; `decisions` follow
the findings window (30d); `audit_log` is kept longer (365d) and is small;
`domain_first_seen` is one row per domain ever seen and is never pruned by age
— that is the point of it.

Indexes will be added only where a query in this plan needs one, and each will
be justified in the commit that adds it.

---

## 4. Scope proposal for v0.3.0

Applying the brief's own priority order (§60: Evidence → Providers →
Explanation → Detection → Policy → Investigation → Assurance).

### In scope

| Phase | Work | Gap |
|---|---|---|
| **P1** | Evidence model + store + retention | G1 |
| **P2** | Feeds and providers become evidence producers; per-indicator lifecycle (active/stale/expired); feed health surfaced as evidence quality | G1, G9 |
| **P3** | Decision record + `policy_path` + "why?" API and UI | G2 |
| **P4** | Audit log: table, writer, API, dashboard view, NDJSON export | G3 |
| **P5** | Domain investigation view: assessment, evidence by source, local history, timeline from real events; global search over domain / IP / device | G4 |
| **P6** | Persistent device identity with source and confidence; device profile; descriptive per-device statistics | G5, §2.2 |
| **P7** | Policy explain (`policy test`) and policy simulation against recent traffic, read-only | G6 |
| **P8** | First-seen domain index, as contextual evidence | G7 |
| **P9** | `docs/assurance/` + `SECURITY-ASSURANCE.md` with accurate statuses; false-positive testing methodology and harness (§44) | G8 |
| **P10** | Security review (§65), full validation (§66), docs (§67) | — |

### Explicitly deferred, with reasons

| Deferred | To | Why |
|---|---|---|
| Behavioural **block** action | after §44 produces a measured FP rate | The project's published precondition. §2.1. |
| Device behavioural baselines that *detect* | v0.4 | Baseline poisoning is unsolved. §2.2. Descriptive stats ship instead. |
| Active discovery (ARP/NDP/ICMP), MAC-OUI, mDNS, device classification, network map, UniFi/pfSense integrations | v0.4 "Asset Intelligence" | Second product; needs `CAP_NET_RAW`; mostly unavailable in the common deployment. §2.3. |
| Roaming client | v0.3.2+ | Brief already defers it (§26, §62). |
| Relationship graph visualisation (§36) | v0.3.1 | Investigation view first; the graph is a second way to look at the same data. |
| Live activity stream (§32) | v0.3.1 | Polling cost vs value; the query log already answers this less prettily. |
| Visual refresh (§31) | continuous | The V3 palette work landed recently. New views adopt it; no separate refresh phase. |

---

## 5. Security controls and threat model additions

Every phase carries its own security work rather than deferring it to P10.

* **Evidence and decisions are attacker-influenced by definition.** A domain
  name in an evidence row comes from a client query; a claim string comes from
  a third-party provider. Both are already treated as untrusted on the provider
  path; the evidence store extends that to display and export. The dashboard's
  strict CSP and auto-escaping `html` template make this enforceable rather
  than aspirational.
* **The audit log must not become a credential leak.** It records *that* a
  provider credential changed, never the value, and the existing
  `secrets.Hint` (last four characters) is the most it may show.
* **Policy simulation must be read-only** and must be shown to be. It runs
  against a copy of the compiled policy and writes nothing — asserted by test.
* **Device identity must not become an authorisation mechanism.** Identity is
  evidence with a stated confidence; policy continues to bind to networks and
  CIDRs, which are enforced. This will be stated in the docs because the
  distinction is easy to lose.
* **New threat-model entries:** evidence poisoning by a compromised provider;
  decision-record forgery; audit-log tampering; device-identity spoofing;
  simulation used as an oracle for policy contents.

---

## 6. Test and performance strategy

Unchanged from how this project already works, because it works:

* Every security property is verified **non-vacuously** — the property is
  reverted and the test that covers it must fail. This has caught four vacuous
  tests and three real defects in the last two work packages alone.
* Hot-path budget: `Evaluate` must not gain a database read, a lock, or an
  allocation for an allowed query. Asserted by a benchmark and by a test that
  counts store calls.
* Evidence assembly happens off the resolution path; a test asserts that a
  blocked query's *answer* is not delayed by it.
* SQLite growth is measured for each new table at a stated query rate, and the
  numbers go in the privacy document.
* Existing gates on every phase: `gofmt`, `vet`, `go test`, `-race`,
  `staticcheck`, `gosec`, `govulncheck`, `shellcheck`, dashboard tests,
  documentation links.

---

## 7. Backwards compatibility

* **Config:** all new keys default to inert. A v0.2 config file runs unchanged.
* **API:** additive only. New routes; no field removed or repurposed. The
  existing OpenAPI contract tests enforce that every route is documented and
  that no credential field becomes readable.
* **Database:** additive tables and nullable columns only; the previous binary
  runs against the new database.
* **Finding schema:** `schemaVersion` is already versioned. Evidence and
  decisions get their own version constant from the start.
* **NDJSON:** existing fields keep their meaning. New fields are added, not
  substituted, so existing SIEM rules keep matching.

---

## 8. Is this too complex for a single maintainer?

The brief asks this question directly (§71), so here is the honest answer.

**The brief as written is too large.** §60 lists 22 items, roughly half of
which are already built, and §25A–Z adds a second product on top. Attempting
all of it produces a release that is 60% finished in every direction.

**The plan above is still on the large side.** Ten phases is a lot. If it has
to shrink further, the order to cut is the reverse of §60's priority: P7
(simulation) before P6 (device identity) before P5 (investigation). The
irreducible core — the part without which "Assurance" is just a name — is
**P1, P3 and P9**: a common evidence shape, a decision record that explains
itself, and honest documentation of what is and is not verified. Those three
deliver §69's definition of success on their own.

**One thing the plan deliberately does not do** is rewrite anything that works.
The detector framework, the provider framework, the metrics, the NDJSON schema
and the threat model stay as they are and get connected to the evidence model.
§6's instruction — *do not rewrite working systems simply because another
design is aesthetically preferable* — is the reason this plan is mostly
additive.

---

## 9. Proposed commit and PR structure

One PR per phase, each independently reviewable and each green on its own.
Phases P1–P4 are sequential; P5–P8 can land in any order once P1 and P3 exist.

```
P1  evidence: a common shape for what we think we know
P2  feeds and providers produce evidence; indicators get a lifecycle
P3  decisions: record what was decided and what decided it
P4  audit: who changed what, and when
P5  investigate: domains, devices, timelines, one search
P6  devices: persistent identity with a stated source and confidence
P7  policy: explain a decision, simulate a change
P8  first-seen: local intelligence the query log cannot provide
P9  assurance: what is verified, what is not, and how the detectors were tested
P10 security review, validation, documentation
```

No merges to `main` without explicit instruction.

---

## 10. v0.3.0 acceptance criteria

The release is done when all of these are demonstrably true:

1. A blocked domain's dashboard view names every piece of evidence that existed
   at decision time, each with its source, claim, confidence and timestamp, and
   marks which ones changed the outcome.
2. That explanation is reproducible from stored data after the contributing
   feed has refreshed — it does not change retroactively.
3. Two independent sources agreeing is shown as two sources agreeing, with both
   named, and never as a blended score.
4. `policy test <domain> --client <device>` prints the full decision path, in
   the dashboard and on the command line, and the two agree.
5. Policy simulation reports what a proposed change would have done to recent
   traffic and provably writes nothing.
6. Every administrative change to policy, feeds, providers, credentials and
   tokens appears in the audit log, with no secret in it.
7. A device has a stable identity across an IP change, and every inferred
   property states its source and confidence — or says `Unknown`.
8. `SECURITY-ASSURANCE.md` states the real status of every control, including
   "not completed" where that is the truth.
9. The false-positive testing methodology is documented and runnable, and its
   results — whatever they are — are published.
10. Hot path unchanged: an allowed query performs no additional database read,
    lock or allocation, asserted by benchmark and test.
11. Full gate green; baseline test results equalled or improved.

## 11. Deferred to v0.3.1 / v0.3.2 / v0.4

* **v0.3.1** — relationship visualisation, live activity view, RDAP and ASN
  enrichment providers, saved investigations, more detection labs.
* **v0.3.2** — experimental roaming client, one operating system.
* **v0.4** — Asset Intelligence proper (active discovery, classification,
  network map, controller integrations); behavioural baselining once poisoning
  has an answer; behavioural enforcement once a false-positive rate exists.
