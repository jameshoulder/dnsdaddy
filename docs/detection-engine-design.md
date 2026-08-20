# Detection engine design

The question this engine exists to answer:

> **Why did DNS Daddy allow, monitor or block this DNS request?**

Not "is this domain bad". The score is a summary of the evidence, and the
evidence is the product. A user who disagrees with a verdict must be able to
see every input that produced it, what each contributed, and what was looked
for and not found.

This document describes the target architecture. It is written against
measurements from `docs/baseline-validation.md` rather than against
assumptions, and it marks clearly what exists today, what is being built, and
what is deliberately deferred.

---

## 1. What already exists

DNS Daddy is not starting from nothing, and this design does not replace what
works.

**Behavioural detection** (`internal/detect`) already runs six windowed
detectors — tunnelling, beaconing, NXDOMAIN bursts, DGA-like clustering, TXT
anomalies, resolution failures. They emit `Finding` documents carrying
per-signal `Value`, `Floor`, `Ceiling`, `Normalised`, `Weight` and
`Contribution`, a confidence separate from severity, and MITRE ATT&CK mappings
that each carry a rationale and a `hypothesis` flag. Every detector declares
`Enforces: false`.

That is already the philosophy this document argues for, applied to *client
behaviour over a window*. Verified working end-to-end during the baseline
audit.

**Policy and reputation** (`internal/policy`, `internal/blocklist`) decide
blocking, from curated feeds rather than inference, and write a plain-English
reason to the query log that was confirmed accurate against the actual
decision.

**The gap** is the join between them. There is no per-query verdict object: no
place where "this name is on two independent feeds, was first seen here four
minutes ago, and has DGA-like structure" is assembled, scored and explained for
*one question at the moment it was asked*. That is what this design adds.

## 2. Principles

1. **Evidence over verdict.** Every detector returns a structured observation
   with its own value, confidence, contribution and limitations. The aggregate
   score is derived from those and is never the primary artefact.
2. **This is not AI.** It is a set of documented heuristics with visible
   arithmetic. No model, no embedding, no training set, no "proprietary risk
   engine". Anyone should be able to reproduce a score by hand from the
   evidence shown.
3. **Absence of evidence is not evidence of absence.** The engine distinguishes
   *observed*, *not observed*, and *unavailable*. A detector that could not run
   because a feed was stale must not read as a clean bill of health.
4. **Detection never blocks DNS.** Already structurally true and must stay
   true: analysis is asynchronous, and a detector panic, a stale feed or a dead
   enrichment source degrades explanation, never resolution.
5. **Language matches the strength of the evidence.** "DGA-like characteristics
   observed", not "DGA malware domain". "Possible periodic beacon", not
   "malware detected".
6. **Memory is the binding constraint.** See §7.

## 3. The verdict object

One document per interesting query, assembled off the DNS path:

```json
{
  "domain": "example.xyz",
  "risk_score": 78,
  "confidence": 0.88,
  "verdict": "suspicious",
  "action": "monitor",
  "signals": [
    {
      "detector": "threat_intelligence",
      "triggered": true,
      "source": "ThreatFox",
      "value": 1,
      "risk_contribution": 35,
      "confidence": 0.98,
      "explanation": "Indicator currently appears in ThreatFox."
    },
    {
      "detector": "domain_entropy",
      "triggered": true,
      "value": 4.18,
      "risk_contribution": 7,
      "confidence": 0.64,
      "explanation": "The queried hostname has unusually high character entropy."
    }
  ],
  "not_observed": ["dns_tunnelling", "nxdomain_anomaly"],
  "unavailable": []
}
```

`not_observed` and `unavailable` are separate fields and both are populated.
The frontend renders the explanation; it does not reconstruct the reasoning.

Detectors satisfy a single interface — name, info, evaluate, and a declaration
of what they cannot tell you — so each is independently configurable,
independently disableable, and independently testable.

## 4. Detection categories

Designed as a whole, built incrementally. Ordered by evidence strength.

### 4.1 Threat intelligence (strongest)

Authoritative, curated, attributable. The only category permitted to drive a
block on its own, which is already how `internal/policy` works.

Requires the correlation layer in §5.

### 4.2 Domain characteristics (weak alone)

Entropy, label and name length, digit ratio, hyphen patterns, character
distribution, vowel/consonant balance, TLD context. Cheap, stateless,
computable from the name.

Individually near-worthless and jointly useful. Each triggered heuristic is
reported separately rather than rolled into one "lexical" number, because
"unusually long" and "mostly digits" are different observations that a reader
should be able to disagree with independently. **Entropy alone must never
block**, and TLD must never be sufficient on its own.

### 4.3 Local context (the differentiator)

First-seen-locally, query frequency, NXDOMAIN rate, unique subdomain counts,
deviation from this client's own baseline.

This is what a self-hosted resolver knows that a commercial feed cannot: what
is normal *for this network*. "First observed on this resolver 18 minutes ago"
is a fact DNS Daddy owns. It is **not** domain registration age and must never
be described as such — a domain registered in 2003 can be first seen locally
today.

### 4.4 Infrastructure context (deferred)

Resolved IP, ASN, hosting provider, related indicators. Requires enrichment
that must be asynchronous and cached, must never touch the synchronous DNS
path, and must degrade to `unavailable` rather than to `safe`.

Deferred: it is the only category needing outbound lookups per indicator, and
its cost has not been measured. Not built on speculation.

## 5. Threat intelligence correlation

Today feeds collapse into a blocklist. `blocklist.Builder.Add` keeps the first
claim on a domain and discards the rest, so a domain on three feeds is
indistinguishable from a domain on one. That is correct for *blocking* — the
first claim is the most severe category — and it destroys exactly the evidence
corroboration needs.

Intelligence must therefore keep provenance: source, indicator, indicator type,
classification, malware family where given, first seen, last seen, ingested at,
provider confidence, and reference. Never collapsed to `malicious = true`.

### Corroboration, sized against measurement

Multiple independent sources should raise confidence. The obvious objection is
memory: the default feed set is 2.88M domains and the baseline audit left about
90 MB of headroom in the shipped container.

Measured across the shipped feeds:

| Listed on | Domains | Share |
|---|---|---|
| 1 feed | 2,753,257 | **95.64%** |
| 2 feeds | 125,447 | 4.36% |
| 3 feeds | 12 | 0.00% |

**Corroboration is sparse.** 95.6% of indicators have nothing to corroborate,
so the layer costs nothing for them. Only the 4.4% overlap needs a side table,
which at a few million domains is single-digit megabytes rather than hundreds.

This is the design decision the measurement settles: a sparse side table keyed
only on multiply-listed domains, not a provenance record per indicator.

### Not double-counting

Corroboration is only meaningful between *independent* sources. Several public
lists are derived from the same upstream data or mirror each other outright.
Feeds therefore need a declared provenance group, and sources in the same group
count once. An undeclared relationship is a false-confidence bug, so the
default for an unknown feed is "assume related to nothing" — the conservative
direction is to under-credit corroboration, never to invent it.

### Recency

Recent intelligence describes current risk better than intelligence last
confirmed three years ago. The model must be simple, documented and visible in
the evidence — a stated decay applied to contribution, not a hidden multiplier.

Historical intelligence is separated from currently-actionable intelligence
rather than deleted: "listed by URLhaus in 2021, not seen since" is useful
context for an investigator and must not read as an active detection.

### Availability

Intelligence lookups are served from the local index and local storage. No feed
API sits in the synchronous DNS path, and resolution continues unchanged when a
provider is offline, rate-limiting or failing. Stale data is marked stale; it
does not become "clean".

### Licensing

Every feed's terms need auditing and recording against the feed: whether it may
be downloaded, stored, displayed, redistributed, and what attribution is
required. The catalogue ships public no-registration sources today, and the
terms must be captured per feed rather than assumed uniform.

## 6. Risk aggregation and operating modes

A 0–100 score with bands (low / informational / elevated / suspicious / high),
**calibrated against measurement rather than chosen**. Thresholds are worthless
until run against both synthetic malicious traffic and a realistic benign
corpus; the numbers in this document are a starting point to be moved.

Contributions are additive per signal and shown per signal, so the arithmetic
is reproducible by hand.

Three explicit modes:

| Mode | Behaviour |
|---|---|
| **Observe** | Analyse, score, explain, alert. Never blocks on a behavioural score. The default for every experimental heuristic. |
| **Protect** | Existing behaviour: explicit policy rules and curated threat-intelligence blocks. Heuristics inform, they do not enforce. |
| **Experimental enforcement** | Behavioural scores may block. Opt-in, clearly labelled, documented with its failure modes, and reversible. Never the default. |

The `Enforces` field already on `DetectorInfo` is the mechanism, and its value
being `false` everywhere is a property worth keeping visible rather than
assumed.

## 7. Resource budget

From `docs/baseline-validation.md`, measured rather than assumed:

- Latency has enormous headroom: p50 0.4 ms, p95 0.6 ms, p99 under 1 ms at 100
  queries/second, at roughly 2% of one core.
- **Memory does not.** The default install peaks near 550 MB inside a 640 MB
  container.

So the constraint that governs this design is resident footprint, not CPU. Every
new detector is judged on **bytes per tracked key**, and anything holding
per-domain or per-client state ships with a bounded size and a sweep from the
first commit — not added later. The existing detectors already do this via
`internal/detect/tracker.go`; new ones follow it.

Storage follows the same rule: raw per-query rows stay compact and retention-
bounded, derived features are recomputed or aggregated rather than stored
forever, and indicators are deduplicated.

## 8. Status

| Area | Status |
|---|---|
| Behavioural detectors (tunnel, beacon, NXDOMAIN, DGA cluster, TXT, resolution) | **Stable-ish, experimental maturity, shipped** |
| Finding model with per-signal evidence | **Shipped** |
| Alert-only enforcement posture | **Shipped** |
| Feed provenance and corroboration | **In progress** — §5 |
| Per-query verdict object | **Planned** — §3 |
| First-seen-locally | **Planned** |
| Lexical / entropy / TLD per-query detectors | **Planned** |
| Score calibration against a benign corpus | **Planned, blocking any enforcement mode** |
| Infrastructure/ASN enrichment | **Deferred** — §4.4 |

Nothing in the "planned" or "deferred" rows should be described as protection
in user-facing material until it ships and is calibrated.
