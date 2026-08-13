# Detection engineering

How DNS Daddy turns query behaviour into findings somebody can act on, and the
reasoning behind the design decisions that shaped it.

- [The pipeline](#the-pipeline)
- [Design principles](#design-principles)
- [The finding schema](#the-finding-schema)
- [Scoring, severity and confidence](#scoring-severity-and-confidence)
- [The detectors](#the-detectors)
- [False positives](#false-positives)
- [Extending it](#extending-it)

Related: [dns-tunnelling.md](dns-tunnelling.md) · [mitre.md](mitre.md) ·
[../threat-hunting/](../threat-hunting/) · [../siem.md](../siem.md) ·
[../../labs/](../../labs/)

---

## The pipeline

```
        DNS query
            │
            ▼
   ┌─────────────────┐
   │ dnsserver       │  the answer is decided here, and is already sent
   │  policy → cache │  before anything below runs
   │  → upstream     │
   └────────┬────────┘
            │  Observation (a plain value, copied)
            ▼
   ╔═════════════════╗
   ║ buffered channel║  full → dropped and counted, never blocks
   ╚════════┬════════╝
            ▼
   ┌─────────────────┐
   │ enrichment      │  registered domain (public suffix list), labels,
   │                 │  NXDOMAIN/SERVFAIL derivation, exclusion check
   └────────┬────────┘
            ▼
   ┌─────────────────────────────────────────────────┐
   │ detectors — bounded per-key state, one goroutine │
   │                                                 │
   │  dns_tunnel  dga_like  nxdomain_anomaly         │
   │  txt_anomaly  dns_beaconing  resolution_failure │
   └────────┬────────────────────────────────────────┘
            │  window closes → score → Finding
            ▼
   ┌─────────────────┐
   │ severity filter │
   │ + cooldown      │
   └────────┬────────┘
            ▼
      ┌─────┴──────┬──────────────┐
      ▼            ▼              ▼
   SQLite      app log      findings.jsonl
   (dashboard,              (SIEM)
    API)
```

The single most important property: **the answer is already decided before any
of this runs**. Detection is downstream of resolution in every sense. It cannot
delay a lookup, cannot fail one, and cannot change one.

That is enforced by a test rather than by convention — 200 queries are driven
through a handler whose detection queue is full and whose only detector panics
if it is ever reached, asserting that resolution neither stalls nor changes
([`internal/dnsserver/detection_test.go`](../../internal/dnsserver/detection_test.go)).

## Design principles

### Observe, score, explain, alert — never block

Behavioural detection does not enforce policy in DNS Daddy, and this is not a
missing feature.

The heuristics here infer intent from traffic shape. They have false positives;
that is inherent, not a defect to be tuned away. A false positive turned into a
block is a working service silently broken, at a time nobody chose, with a
cause nobody will guess. The engineer who has to explain that outage will not
be comforted by a confidence of 0.83.

Blocking stays with the policy and threat-feed engine, which acts on curated
intelligence — a human somewhere decided that domain was malicious — rather
than on inference.

`DetectorInfo.Enforces` is published in the API and is `false` everywhere, and
a test asserts it stays that way. If enforcement is ever added it will be
opt-in, per-detector, and gated on a published false-positive measurement.

### A finding must be checkable by hand

"Suspicious DNS traffic" is not actionable. What is actionable is:

> 187 distinct subdomains of `example.com` in five minutes, mean label entropy
> 4.71 bits/char, 91% NXDOMAIN, 64% TXT.

So every finding carries the individual measurements that produced it, with the
floor and ceiling of each signal's band, its weight, and what it contributed.
The contributions sum to the score, and a test asserts they do. An analyst can
reproduce the arithmetic on paper.

This is not decoration. A score nobody can reproduce is a score nobody should
act on, and a detection stack that cannot explain itself gets ignored.

### No single measurement raises a finding

Every property these detectors measure has a common benign cause. High entropy
is a hash. High cardinality is a CDN. Long names are service discovery. TXT is
a mail server. Perfect timing is an updater.

So the tunnel detector requires at least three of seven signals to be
meaningfully present, and the beaconing detector gates on regularity itself
rather than letting volume and duration accumulate a finding on their own.

The lab's [high-entropy-subdomains](../../labs/high-entropy-subdomains.md)
scenario exists to demonstrate this: genuinely random labels, no finding.

### State must be bounded

This code is fed directly by untrusted network traffic. A client spraying a
million unique names must not be able to make the resolver allocate a million
tracking entries.

Every detector's state is capped, and eviction is O(1) — a small random sample,
least-recently-updated of that sample evicted, the standard approximate-LRU
trade. Scanning for the true oldest would hand an attacker quadratic work per
query and turn the detector into the amplifier.

Eviction means **missed detections**, not merely reduced accuracy. It is
reported through metrics rather than hidden.

### Say what the telemetry cannot support

Two examples worth pointing at, because they show the rule biting:

The `resolution_failure` detector reports domains persistently returning
SERVFAIL. Failed DNSSEC validation is one cause. It is *not* called
`dnssec_validation_failure`, because DNS Daddy forwards rather than validating
and cannot tell a bogus signature from an unreachable nameserver. It lists the
alternative causes in its evidence and carries **no ATT&CK mapping at all**.

The `nxdomain_burst` finding maps to T1568.002 with `hypothesis: true`,
because a failure burst is the *expected observable* of a DGA and also of a
stale search suffix. The mapping states what the behaviour would be if the
finding is a true positive, which is a different claim from what the evidence
establishes.

---

## The finding schema

Version **1.0**. Within a major version, fields may be added but never removed
or repurposed. The full JSON Schema is in
[`internal/api/openapi.yaml`](../../internal/api/openapi.yaml).

```json
{
  "schemaVersion": "1.0",
  "id": "9f2c1a4b7e8d3f6a0b5c2e91",
  "time": "2026-03-14T09:05:00Z",
  "eventType": "dns_tunnel_suspected",
  "severity": "high",
  "confidence": 0.87,
  "score": 0.84,
  "client":  { "ip": "192.168.1.42", "name": "laptop-07", "networkId": "n_office" },
  "domain":  "example.com",
  "qtype":   "TXT",
  "title":   "Possible DNS tunnelling",
  "summary": "laptop-07 (192.168.1.42) queried 187 distinct subdomains of example.com …",

  "signals": [
    {
      "name": "unique_subdomains",
      "description": "Distinct names seen below this registered domain from this client. …",
      "value": 187, "floor": 20, "ceiling": 200,
      "normalised": 0.93, "weight": 0.28, "contribution": 0.26
    }
  ],

  "evidence": { "unique_subdomains": 187, "average_entropy": 4.71, "…": "…" },
  "window":   { "start": "…", "end": "…", "queries": 210 },

  "mitre": [
    {
      "id": "T1071.004",
      "name": "Application Layer Protocol: DNS",
      "tactic": "Command and Control",
      "url": "https://attack.mitre.org/techniques/T1071/004/",
      "rationale": "The measured behaviour is the mechanism T1071.004 describes …",
      "hypothesis": false
    }
  ],

  "falsePositives": ["Anti-spam and file-reputation lookups …"],
  "nextSteps":      ["Identify the parent domain's owner …"],
  "detector": "dns_tunnel",
  "maturity": "experimental"
}
```

Three fields are unusual and deliberate.

**`falsePositives` ships inside the finding.** Not only in the documentation,
because the moment an analyst needs to know what benign thing looks like this
is the moment they are staring at the alert at 23:00.

**`nextSteps` likewise.** The investigation path for a finding type is knowable
in advance, so it travels with the finding rather than living in a runbook
somebody has to locate.

**`maturity` is on every finding.** Presenting a heuristic written last month
with the same authority as a curated threat feed is how a security tool teaches
people to ignore it.

### Where findings go

| Sink | Use |
|---|---|
| SQLite | Dashboard and `/api/v1/findings`. Retention `detection.retention_days`, default 30. |
| Application log | Logged at `warn`, so `docker logs` shows them. |
| `findings.jsonl` | Newline-delimited JSON for a log shipper. Off by default. See [../siem.md](../siem.md). |

---

## Scoring, severity and confidence

Each signal has a **band** — a floor below which it contributes nothing and a
ceiling at which it contributes fully — and a **weight**. Weights within a
detector sum to 1.0, asserted by a test.

```
normalised   = clamp01((value - floor) / (ceiling - floor))
contribution = normalised × weight
score        = Σ contributions
```

**Severity** answers *how much should this interrupt someone*:

| Score | Severity |
|---|---|
| ≥ 0.75 | high |
| ≥ 0.55 | medium |
| ≥ 0.40 | low |
| < 0.40 | info (below the default `min_severity`, so not stored) |

Each detector also declares a **ceiling**. Beaconing is capped at medium
however clean the maths looks, because perfect periodicity is exactly what a C2
implant does and exactly what a software updater does.

**Confidence** answers a different question — *how sure are we* — and is the
score damped by sample size:

```
confidence = score × (0.7 + 0.3 × sample_fraction)
```

A detector firing on the bare minimum sample says so in its confidence rather
than in a footnote. The same score over 40 queries is less trustworthy than
over 400, and pretending otherwise is how behavioural detection loses an
analyst's trust.

Severity and confidence are independent on purpose. A high-confidence
advertising beacon is still informational; a medium-confidence tunnelling
signal on a server VLAN is worth looking at tonight.

---

## The detectors

All six are **experimental**. Their thresholds are calibrated against the
synthetic corpora in `internal/detect`, which were written from the same
understanding of the problem that produced the detectors — so they test
internal consistency, not real-world accuracy. Nobody has yet measured a
false-positive rate on a large production network.

### `dns_tunnel` — DNS used as a data carrier

Keyed on (client, registered domain), 5-minute window, max severity **high**.
Seven signals; at least three must be meaningfully present. Full treatment in
[dns-tunnelling.md](dns-tunnelling.md).

### `dga_like` — algorithmically generated domains

Keyed on client, 10-minute window, max severity **high**.

Each distinct registered domain has its second-level label scored on four
surface statistics — vowel distribution, longest consonant run, digit fraction,
and per-character entropy — equally weighted. Labels scoring ≥0.45 count as
candidates.

| Signal | Band | Weight |
|---|---|---|
| `algorithmic_domain_count` | 8 – 60 | 0.40 |
| `mean_randomness` | 0.45 – 0.80 | 0.25 |
| `candidate_nxdomain_ratio` | 0.30 – 0.90 | 0.25 |
| `distinct_tlds` | 2 – 8 | 0.10 |

The NXDOMAIN ratio is computed over candidate domains only; mixing in ordinary
browsing would wash the signal out.

**It will not detect a word-list DGA.** Families generating pronounceable
domains from a dictionary score near zero on all four properties. This approach
misses them completely. It is a heuristic, not a model — there is no training
data and no learned representation, and calling four arithmetic measurements
"AI" would make the output less trustworthy, not more.

### `nxdomain_anomaly` — bursts of failed lookups

Keyed on client, 5-minute window, max severity **medium**.

| Signal | Band | Weight |
|---|---|---|
| `failed_lookups` | 50 – 500 | 0.40 |
| `failure_ratio` | 0.30 – 0.90 | 0.30 |
| `distinct_failed_domains` | 10 – 100 | 0.30 |

Two exclusions carry this detector. **Policy blocks are not counted** — DNS
Daddy answers a blocked name with NXDOMAIN, so counting them would mean the
better your filtering worked, the more your network looked like an incident.
**Names with no registered domain are not scored** — a stale search suffix
producing `printer.corp.local` across the estate is the loudest false positive
this detector has, and it is removed structurally rather than by threshold.

The domain-spread signal is what separates "one dead internal service" (one
domain, quiet) from "a host walking a generated list" (hundreds, loud).

### `txt_anomaly` — unusual TXT activity

Keyed on client, 5-minute window, max severity **medium**.

Standard infrastructure lookups — `_dmarc`, `_domainkey`, `_spf`,
`_acme-challenge`, `_mta-sts`, `_tlsa`, DKIM selectors — are identified by
label structure and excluded *before* anything is measured. Without that step
the detector reports the mail server every five minutes forever. The excluded
count is reported in the evidence so the reader can see what was filtered.

| Signal | Band | Weight |
|---|---|---|
| `txt_query_count` | 30 – 300 | 0.35 |
| `txt_query_ratio` | 0.10 – 0.60 | 0.25 |
| `distinct_txt_names` | 15 – 150 | 0.25 |
| `mean_txt_subdomain_entropy` | 3.2 – 4.2 | 0.15 |

The ratio and distinct-name signals matter more than the raw count. Reading a
policy record means asking for the same few names repeatedly; moving data means
asking for new ones.

### `dns_beaconing` — fixed-cadence check-ins

Keyed on (client, exact name), 30-minute window, max severity **medium**.

Regularity is measured as the coefficient of variation of inter-arrival times —
standard deviation over mean, which makes a 30-second and a 10-minute beacon
comparable. `regularity = 1 − CV`. Human traffic sits near 0; a fixed timer
near 1.

| Signal | Band | Weight |
|---|---|---|
| `timing_regularity` | 0.75 – 0.97 | 0.45 |
| `observation_count` | 8 – 40 | 0.20 |
| `observed_duration` | 300 – 1800s | 0.15 |
| `ttl_independence` | 0.15 – 0.6 | 0.20 |

**Regularity is a gate, not just a weight.** Below 0.75, no finding at all —
otherwise volume and duration could accumulate a low-severity finding on
visibly irregular traffic.

**The TTL discriminator** is the most useful thing in this detector. A client
re-resolving because its own cache expired queries at exactly the record's TTL.
That is perfect periodicity with a complete, boring explanation, so where the
observed period matches the TTL within 15% the finding is **suppressed
entirely** rather than downgraded.

This is also the most expensive detector: keyed per exact name, its state is
capped at 16,384 keys and evicts under pressure. On a busy network that is a
real coverage gap.

### `resolution_failure` — domains failing upstream

Keyed on registered domain, 10-minute window, max severity **medium**.
Fires when ≥5 SERVFAIL and >50% of lookups for a domain fail.

| Signal | Band | Weight |
|---|---|---|
| `failed_lookups` | 5 – 100 | 0.50 |
| `failure_ratio` | 0.50 – 1.0 | 0.30 |
| `affected_clients` | 1 – 10 | 0.20 |

Causes include unreachable authoritative servers, broken delegation, DNSSEC
validation failure at the upstream, and upstream problems. DNS Daddy cannot
distinguish them, so it names none of them in the title, lists all of them in
the evidence, and carries **no ATT&CK mapping**.

---

## False positives

The exclusion list is the load-bearing false-positive control, and it is a
trade-off rather than a free win.

Some services do exactly what these detectors hunt for, as their designed mode
of operation. Anti-spam blocklists and endpoint file-reputation services encode
the thing being checked into a DNS label and look it up — thousands of unique,
high-entropy names an hour, mostly NXDOMAIN. That is a DNS tunnel's exact
traffic profile, performed honestly. CDNs issue per-request hostnames. IPv6
reverse DNS is 32 hex labels per lookup.

None of that is caught by cleverer scoring, because the traffic really is the
same shape. It is excluded by domain, in
[`internal/detect/exclusions.go`](../../internal/detect/exclusions.go), with a
comment on each entry explaining why it is there.

**The residual risk is real:** an attacker who tunnels through a domain that
resembles a security vendor's, or who compromises one, evades this entirely.
That is what exclusion lists cost, and pretending otherwise would be worse than
the trade.

`TestDNSBLTrafficWouldFireWithoutExclusions` asserts both halves — that the
corpus fires with the list disabled and stays quiet with it enabled — so if the
exclusion list ever stops being the reason, the test fails rather than the
behaviour silently changing.

### Tuning on your own network

Prefer adding a domain to `detection.excluded_domains` over raising a
threshold. An exclusion costs you coverage in one place; a threshold change
costs it everywhere.

```yaml
detection:
  excluded_domains:
    - "reputation.your-av-vendor.example"
    - "gateway.your-mail-filter.example"
```

Matching is suffix-based. **This never affects whether a domain resolves** — it
is not an allow-list for blocking.

---

## Extending it

A detector implements `detect.Detector`:

```go
type Detector interface {
    Name() string
    Info() DetectorInfo
    Observe(e *Event)
    Evaluate(now time.Time) []Finding
    Sweep(now time.Time)
    Tracked() int
}
```

`Observe`, `Evaluate` and `Sweep` are driven from one goroutine and are never
called concurrently, so implementations hold state without locking.

House rules for a new detector, learned from the six that exist:

1. **Bound the state.** Use `newTracker`; do not hold an unbounded map.
2. **Gate on volume before scoring.** Refusing to produce a finding is the
   honest way to say "not enough evidence".
3. **Require more than one signal**, or gate on the one that defines the
   detector.
4. **Publish the bands.** A score that cannot be reproduced by hand is not
   explainable.
5. **Write the benign corpus first.** For every malicious pattern there is
   benign traffic sharing its most obvious property — a CDN against a tunnel, a
   mail server against a TXT channel. If you cannot construct that corpus, you
   do not yet understand the false positives.
6. **Attach ATT&CK only with a rationale**, and mark hypotheses as hypotheses.
   No mapping is better than a decorative one.
7. **Start at `MaturityExperimental`.** Promotion needs measurement.
8. **Set `Enforces: false`.** It has never been anything else.
