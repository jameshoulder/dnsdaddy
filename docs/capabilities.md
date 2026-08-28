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
| Forwarding resolver over UDP and TCP | Not recursive — it does not walk the root zone. |
| DNS-over-TLS listener | Requires a certificate; off unless configured. |
| DNS-over-HTTPS endpoint | RFC 8484, at `/dns-query/<token>`. |
| Encrypted upstream (DoT) | The shipped default. Upstream certificates are verified. |
| Answer cache | Bounded, sharded, TTL-aware, invalidated on feed or policy change. |
| Request collapsing | Identical concurrent questions share one upstream flight. |
| ANY refusal (RFC 8482) | On by default; ANY is the classic amplification lever. |
| Client ACL | Source addresses outside the list are REFUSED before any work. |
| Open-resolver startup refusal | A public listener with no ACL is a startup error, not a warning. |

### Filtering

| Capability | Notes |
|---|---|
| Category blocking from public threat feeds | Malware, phishing, C2, cryptomining on by default; ads, adult, gambling, newly-registered available. |
| Custom allow and block lists, per policy | Allow-list wins, so an operator can always override a bad feed entry. |
| Per-network policies | Matched by CIDR, most specific prefix first. |
| Roaming attribution by DoH token | A per-network token in the DoH path applies that network's policy from any IP. |
| Configurable block response | NXDOMAIN, 0.0.0.0/::, or REFUSED. |
| Immediate allow-listing | The answer cache is purged on a policy change, so a fix applies on the next query. |

### Telemetry

| Capability | Notes |
|---|---|
| Per-query logging with plain-English reasons | Non-blocking and batched; drops rather than delaying a lookup. |
| Hourly and daily rollups | Survive query-log pruning, so reporting history outlives browsing history. |
| DNSSEC status per query | The **upstream's** verdict. See below and [dns-security/dnssec.md](dns-security/dnssec.md). |
| Prometheus metrics | Hand-rolled, no client library. |
| Markdown reports | A period summary written for someone who does not run the network. |
| Structured security findings | Stored, queryable, and exportable as NDJSON. See [detection/README.md](detection/README.md). |

### Management

| Capability | Notes |
|---|---|
| Embedded dashboard | No build step, no npm tree; served from the binary. |
| REST API with OpenAPI 3.1 | Each build serves its own spec at `/openapi.yaml`. |
| Session and bearer-token authentication | Bcrypt password, rate-limited login, same-origin checks on cookie-authenticated writes. |
| Single static binary | `CGO_ENABLED=0`, pure-Go SQLite, cross-compiles from a laptop. |

### Diagnostics

| Capability | Notes |
|---|---|
| `dnsdaddy doctor` | Reads configuration and the database, and sends real DNS queries at the configured listeners and through each upstream. Reports SYSTEM, DATABASE, DNS LISTENER, CLIENT ACCESS, UPSTREAM, WEB INTERFACE and THREAT INTELLIGENCE as PASS/WARN/FAIL with the evidence behind each verdict. Changes nothing — the database is opened read-only — and exits non-zero on failure. `--json` for machine consumption. |
| Client-access cross-check | Reports a network configured in the dashboard whose addresses the **effective** client ACL does not permit — the bootstrap list from configuration unioned with the dashboard's own permissions, with both sources named separately. Surfaced at startup, at `GET /api/v1/diagnostics`, in `dnsdaddy doctor`, and on the dashboard. Coverage is decided by single-prefix containment, so two allowed prefixes that between them cover a network are reported as *partial* rather than *full* — it over-warns in a rare case rather than under-warning in a common one. |
| Dashboard-managed resolver access | A network can be permitted to query the resolver from the dashboard, in force on the next query with no restart. Enforced server-side: a default route is refused outright, and a publicly routable range needs an explicit acknowledgement recorded per range. See [docs/deploy.md](deploy.md#who-may-use-the-resolver) for the precedence rules and the properties that can surprise — an empty bootstrap ACL stays unrestricted, there are no deny rules, and permitting the catch-all grants nothing because it has no ranges of its own. |
| Public-exposure warning | Names each permitted range that is reachable from the internet, every time diagnostics run, from **both** sources — a range permitted through `DNSDADDY_ALLOWED_CLIENT_CIDRS` exposes a resolver exactly as much as one permitted in the dashboard. Each is labelled with the setting responsible. It never resolves itself and never claims a firewall state: DNS Daddy cannot see a cloud security group and does not change one. |
| First-run guidance | The dashboard's onboarding card branches on measurements, not inference: refusals counted by the ACL, and whether the effective ACL admits anything beyond loopback. It does not treat "no network carries a permission" as "every client will be refused" — a stock LAN install has no permissions and serves every private range. |
| Port-conflict attribution | When nothing answers, distinguishes "nothing is listening" from "another process holds the port" and names that process by reading `/proc` socket inodes. Naming a process owned by another user needs root; without it the check says so rather than guessing. |
| Management-exposure detection | Records management requests arriving over plain HTTP from a public address and raises them as a failure. Evidence, not inference: the process cannot see its own port publishing, so this fires only on traffic that has actually arrived. Silent for private, loopback and carrier-grade-NAT sources, for TLS, and for `/dns-query`. |
| `dnsdaddy_client_refused_total` | Queries rejected on their source address, in `/metrics`. Deliberately unlabelled by address: the refusal path writes no query-log row so an unauthorised source cannot fill the disk, and a metric label would reintroduce that. |
| Client-access gauges | `dnsdaddy_networks_total`, `dnsdaddy_networks_resolver_permitted`, `dnsdaddy_client_acl_prefixes`, `dnsdaddy_client_acl_public_prefixes` and `dnsdaddy_client_acl_unrestricted`. Counts only, no labels — an ACL is exactly the place where labelling by CIDR grows one series per network and then one per client. `client_acl_public_prefixes` counts **distinct** ranges across both sources, so permitting the same range in configuration and in the dashboard does not read as exposure doubling. Everything derivable from the live snapshot is exported unconditionally, so a momentary database error cannot silently drop the series an operator alerts on. |

### DNSSEC — read this carefully

DNS Daddy sets the AD bit on outgoing queries ([RFC 6840] §5.7) so a validating
upstream reports whether it authenticated each answer, and records the result
as `validated`, `unvalidated` or `servfail`.

**This is not DNSSEC validation.** DNS Daddy does not verify signatures, does
not hold a trust anchor, and does not build a chain of trust. It records what a
validating upstream concluded, which is a strictly weaker statement. In
particular `unvalidated` covers "the zone is unsigned" and "the upstream does
not validate" equally, because a forwarder cannot distinguish them.

Local validation is **Planned**. See [dns-security/dnssec.md](dns-security/dnssec.md).

---

## Experimental

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
confidence number makes that a good trade. Enforcement stays with the policy
and threat-feed engine, which acts on curated intelligence rather than
inference.

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
| **Local DNSSEC validation** | Requires trust-anchor management, negative-proof handling and a considered failure mode. Getting it wrong means silently accepting forged answers, which is worse than not claiming it. |
| **Policy enforcement from behavioural findings** | Needs a measured false-positive rate first. Blocking on a heuristic with an unknown FP rate is not a feature. |
| **`safeSearch` enforcement** | The flag is accepted by the API and stored on the policy. The resolver does not act on it, and setting it changes nothing about how queries are answered. A known gap since the first release; the field is marked `deprecated` in the OpenAPI schema with that stated in the description, so a generated client cannot present it as a working control. |
| **Webhook and syslog sinks** | The NDJSON file plus a log shipper covers the same ground today without a bespoke client per vendor. |
| **Sigma rule export / detection-as-code** | Research. The finding schema was designed with it in mind. |
| **Behavioural baselining** | "Unusual *for this network*" needs a learned baseline, which needs a considered answer to poisoning during the learning window. |
| **Word-list DGA detection** | The current heuristic measures surface statistics and misses dictionary-word generators completely. This is a research problem. |
| **Machine learning anywhere** | Stays on this list until there is a defensible dataset, a baseline to beat, and an evaluation methodology. Statistics relabelled as AI would make the output less trustworthy, not more. |
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

**Send your data anywhere.** No telemetry, no phone-home, no account, no
licence check. The threat feeds are public URLs listed in
[`internal/catalog`](../internal/catalog/catalog.go) and downloaded directly
from their operators.

**Claim to protect against what it cannot see.** A device using an external DoH
resolver bypasses DNS Daddy entirely. That is a property of DNS, and the
documentation says so rather than implying otherwise.

**Label arbitrary statistics as AI.** Entropy is entropy.

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

Both are generated from the running code, so they cannot drift from it the way
a document can.

[RFC 6840]: https://www.rfc-editor.org/rfc/rfc6840#section-5.7
