# Threat model

DNS Daddy sits in the resolution path of every name lookup on a network. That
position is what makes it useful and what makes it worth attacking: a
compromise here is a compromise of everything downstream, silently and without
touching any endpoint.

This document covers what is being protected, from whom, where the boundaries
are, what is done about it, and — the part most threat models skip — what is
left over.

Scope: DNS Daddy as deployed, its dependencies, and the operational practices
around it. It is a design-level model, not a penetration test, and no
independent review has been done. See [SECURITY.md](../SECURITY.md).

---

## Assets

Ordered by what an attacker gains from each.

| Asset | Why it matters |
|---|---|
| **The resolution path itself** | Anyone who controls the answers controls where every device on the network connects. This is the crown jewel; everything else is a route to it. |
| **Query logs** | A complete record of what every device looked up. Browsing history, device inventory, working patterns, and the software in use, all in one file. |
| **Behavioural findings** | The same information, condensed and pre-analysed. Also reveals what the operator is capable of detecting. |
| **The admin password and session key** | Full control of the resolution path. |
| **API tokens** | The same, programmatically. |
| **Policy and network configuration** | Reveals the network's structure; altering it disables filtering. |
| **The blocklist index** | Corrupting it disables protection without any visible error. |
| **DoH network tokens** | Let an outsider obtain a specific network's policy, and identify roaming devices. |
| **Upstream trust** | Whatever the upstream says becomes truth for the whole network. |

## Trust boundaries

```
  ┌─ Internet ──────────────────────────────────────────────────────────┐
  │                                                                     │
  │   threat feeds (HTTPS)          upstream resolvers (DoT)            │
  └──────────┬──────────────────────────────┬───────────────────────────┘
             │  B4                          │  B3
  ═══════════╪══════════════════════════════╪═══════════════════════════
             ▼                              ▼
  ┌─ DNS Daddy host ────────────────────────────────────────────────────┐
  │                                                                     │
  │   feed downloader ──▶ blocklist index ──▶ policy engine             │
  │                                              ▲                      │
  │   SQLite (config, query log, findings)       │                      │
  │        ▲                                     │                      │
  │        │  B5                                 │                      │
  │   management API / dashboard          resolution path               │
  └────────▲────────────────────────────────────▲──────────────────────┘
           │  B2                                │  B1
  ═════════╪════════════════════════════════════╪═══════════════════════
           │                                    │
      operator                            network clients
   (browser / API token)              (trusted only to send bytes)
```

| | Boundary | What crosses it | What is assumed |
|---|---|---|---|
| **B1** | Client → resolver | DNS messages over UDP/TCP/DoT/DoH | Nothing. Every field is attacker-controlled. |
| **B2** | Operator → management API | HTTP requests, credentials | Authenticated, but the browser may be attacked separately. |
| **B3** | Resolver → upstream | DNS queries and answers | The upstream is honest but not verified. This is the weakest assumption in the model. |
| **B4** | Feed downloader → feed providers | HTTPS downloads of domain lists | Providers are honest; TLS is verified; content is not. |
| **B5** | Process → SQLite and data directory | All state | The host is not already compromised. |

## Threat actors

| Actor | Capability | Motivation |
|---|---|---|
| **Opportunistic internet scanner** | Finds open ports within days. No specific interest. | Amplification, cryptomining, mass exploitation. |
| **Compromised client on the network** | Sends arbitrary DNS traffic from a trusted source address. | Exfiltration, C2, evading the filter. |
| **Malicious insider** | Legitimate network access, possibly dashboard access. | Bypassing policy, covering tracks. |
| **Network-adjacent attacker** | Can observe or inject on the local segment. | Interception, redirection. |
| **Upstream or transit adversary** | Can observe or alter traffic to the upstream, or is the upstream. | Mass surveillance, targeted redirection. |
| **Supply-chain attacker** | Can influence a dependency, a threat feed, or a release artefact. | Broad, silent compromise. |
| **Targeted attacker** | Time, skill, and a specific interest in this network. | Everything above. |

---

## Threats and mitigations

### T1 — Malicious domain resolution

*Malware, phishing or C2 domains resolve normally and a client connects.*

**Mitigations.** Category blocking from public threat feeds, refreshed on a
timer and cached to disk so a restart never leaves a window with no blocklist.
Suffix matching, so blocking a domain blocks everything beneath it. Category
priority ordering, so a domain on both a malware and an ad list is reported as
malware. Custom block lists per policy.

**Residual risk.** Feeds are reactive and always incomplete. A domain
registered an hour ago is on nothing. **DNS filtering is one control among
several and is not a substitute for endpoint protection** — it is a wide, cheap
net, not a fine one.

### T2 — Phishing and look-alike domains

*A domain that reads like a brand at a glance.*

**Mitigations.** Phishing feeds and the optional newly-registered-domains
category, which is heavily over-represented in attacks.

**Residual risk.** No homoglyph or typosquat detection. A look-alike registered
this morning and used within the hour will resolve. Detecting this well needs a
brand list to protect and a considered false-positive story; it is on the
roadmap, not implemented.

### T3 — DNS tunnelling *(ATT&CK [T1071.004], [T1048.003])*

*A client encodes data into DNS names to move it past the firewall.*

**Mitigations.** The `dns_tunnel` detector scores seven independent properties
of DNS-as-transport and raises an explainable finding. Manual blocking of a
confirmed tunnel domain by policy.

**Residual risk, stated plainly.** The detector is **experimental** and
**alert-only**; nothing is blocked automatically. A slow tunnel — a few
messages an hour — falls below the volume gates by design, because the
alternative is alerting on every CDN. An attacker who tunnels through a domain
on the exclusion list evades it entirely. Detection is not prevention: the
finding tells you it happened, not that it was stopped.

### T4 — DNS-based command and control *(ATT&CK [T1071.004])*

*An implant takes instructions over DNS.*

**Mitigations.** C2 category feeds. The `dns_beaconing` detector for
fixed-cadence check-ins, and `txt_anomaly` for TXT-based tasking. Request
collapsing means a host spraying one lookup costs one upstream query.

**Residual risk.** Beaconing detection cannot distinguish an implant from a
software updater by timing, which is why it is capped at medium severity and
framed as a hunting lead. Its state is keyed per exact name, so on a busy
network eviction causes real coverage gaps — reported via metrics rather than
hidden.

### T5 — DGA-like behaviour *(ATT&CK [T1568.002])*

*Malware tries hundreds of generated domains to find its rendezvous point.*

**Mitigations.** The `dga_like` detector scores second-level labels on four
surface statistics; `nxdomain_anomaly` catches the resulting failure burst. The
two corroborate each other.

**Residual risk.** Word-list DGAs producing pronounceable domains defeat this
approach completely. It is a heuristic, not a model, and is described as such
everywhere it appears.

### T6 — Unusual TXT usage

*TXT records used to carry payloads or tasking.*

**Mitigations.** The `txt_anomaly` detector, after excluding SPF, DKIM, DMARC,
MTA-STS, ACME and verification lookups by label structure.

**Residual risk.** A vendor using non-standard selector names is not excluded
and will produce findings until added to `detection.excluded_domains`.

### T7 — NXDOMAIN anomalies

*Bursts of failed lookups indicating enumeration or a DGA.*

**Mitigations.** The `nxdomain_anomaly` detector, scoring rate, ratio and
domain spread. Policy blocks and names with no registered domain are excluded
from scoring — otherwise effective filtering and a stale search suffix would
each produce a permanent false alarm.

**Residual risk.** A stale search suffix under a *real* registered domain is
not excluded and will fire.

### T8 — DNS rebinding

*A short-TTL name that resolves externally then internally, to reach a private
service from a browser.*

**Mitigations.** Cache `min_ttl` raises very short TTLs, which incidentally
slows the flip.

**Residual risk. This is not mitigated.** DNS Daddy does **not** filter private
addresses out of upstream answers, which is the actual control. If you need
rebinding protection, it belongs on the browser and on the internal service's
host header validation. This is an honest gap rather than a claimed feature,
and it is on the roadmap.

### T9 — Cache poisoning

*Forged answers accepted into the cache and served to everyone.*

**Mitigations.** Upstream queries go over DNS-over-TLS by default with
certificate verification, which removes off-path spoofing entirely — an
attacker cannot inject into a TLS session. Message IDs are randomised per
upstream query and the client's ID is never reused. Cache keys include the
question and the DO bit, so a DNSSEC-aware and a plain query cannot collide.
Only single-question messages are accepted, so a crafted second question cannot
ride upstream unevaluated. Answers are re-attached to the client's own
question rather than trusted wholesale.

**Residual risk.** With a plaintext upstream configured, off-path spoofing
becomes possible again — the resolver warns loudly at startup when this is the
case. A malicious or compromised upstream can poison at will; see T11.

### T10 — DNSSEC validation failures

*A domain fails validation, or an attacker strips signatures.*

**Mitigations.** The AD bit is requested on every upstream query so the
upstream's verdict is recorded per query. The `resolution_failure` detector
reports domains persistently returning SERVFAIL.

**Residual risk. DNS Daddy does not validate DNSSEC.** It relies entirely on
the upstream to do so, and a forwarder cannot distinguish "unsigned zone" from
"upstream does not validate" — both appear as `unvalidated`. Neither can it
distinguish a bogus signature from an unreachable nameserver, which is why the
finding is called `resolution_failure_burst` and carries no ATT&CK mapping. See
[dns-security/dnssec.md](dns-security/dnssec.md).

### T11 — Compromised upstream infrastructure

*The upstream resolver is malicious, coerced, or hijacked.*

**Mitigations.** DoT with certificate verification prevents impersonation.
Multiple upstreams can be configured. `race` mode queries several at once.

**Residual risk. This is the weakest assumption in the model.** A genuinely
malicious upstream can return whatever it likes, and without local DNSSEC
validation DNS Daddy has no way to tell. The AD bit is *self-reported by the
upstream* and a lying upstream will happily set it. The mitigation available
today is choosing an upstream you have reason to trust and watching for
unexpected `unvalidated` transitions on domains you know are signed. Local
validation is the real fix and is not implemented.

### T12 — DoH/DoT bypass

*A client resolves directly with an external encrypted resolver.*

**Mitigations.** Documentation, and network controls the operator must
configure themselves: blocking outbound 53 and 853 except to DNS Daddy, and
blocking or DNS-blocking known DoH endpoints.

**Residual risk. DNS Daddy cannot prevent this and does not claim to.** DoH is
HTTPS to port 443; distinguishing it from web traffic requires inspection DNS
Daddy does not do and is not positioned to do. A device configured to use
external DoH is invisible — not just unfiltered, but *unlogged*, so its absence
is the only signal. See
[dns-security/encrypted-dns.md](dns-security/encrypted-dns.md).

### T13 — Compromised client

*A device on the network is under attacker control.*

**Mitigations.** The client ACL bounds who can query at all. Per-network
policies limit blast radius. Detection findings identify the device. Query
logs support investigation. Malformed messages are rejected before any
processing; name length is bounded; the suffix walk allocates nothing.

**Residual risk.** A compromised client is *inside* B1 and is trusted to send
bytes. It can exhaust its own network's detection budget, and it can bypass
DNS entirely by using hard-coded IP addresses — DNS filtering has nothing to
say about a connection that never asks a question.

### T14 — Administrative interface compromise

*An attacker reaches the dashboard or API.*

**Mitigations.** The dashboard binds loopback only by default; the documented
remote path is a reverse proxy or an SSH tunnel. Bcrypt password hashing.
Login attempts are rate-limited (10 per 15 minutes). Session cookies are
HttpOnly, SameSite, and Secure when TLS is in front. State-changing
cookie-authenticated requests require a same-origin check, so a hostile page
cannot drive the API. Bearer tokens are exempt from that check because a
browser never attaches them automatically. Tokens are stored hashed and the
secret is shown once. Request bodies are capped at 1 MiB. Unknown JSON fields
are rejected. A panic in a handler becomes a 500 rather than taking the
resolver down.

**Residual risk.** A single shared admin password with no SSO, no MFA and no
RBAC. Anyone with it has everything. Compromise here is total: policy can be
disabled, logs read, and answers redirected.

### T15 — Authentication and authorisation flaws

**Mitigations.** One privilege level, so there is no authorisation logic to get
wrong. Constant-time credential comparison. Sessions signed with a key
generated at first run and stored 0600. Auth is enforced by a wrapper around
the whole authenticated mux rather than per handler, so a new endpoint cannot
be added unprotected by omission.

**Residual risk.** No MFA. No per-token scoping — every token is a full-access
token. No session revocation beyond changing the password.

### T16 — Secrets handling

**Mitigations.** Passwords bcrypt-hashed, API tokens hashed, the generated
first-run password written 0600 and printed once. The session key is generated
locally, never transmitted. Findings and the data directory are 0640/0750.
Secret scanning and dependency scanning run in CI.

**Residual risk.** `DNSDADDY_ADMIN_PASSWORD` in an environment variable is
visible to anything that can read the process environment, and to
`docker inspect`. The first-run password sits in plaintext in
`initial-password.txt` until deleted. No secrets-manager integration.

### T17 — Log poisoning

*Crafted DNS names injected into logs or reports to attack whoever reads them.*

**Mitigations.** This has been found and fixed once already, which is the
strongest thing that can be said for it. A Semgrep review found **Markdown
injection** in generated reports — feed, network, location and policy names
reached the rendered output unescaped — and it was remediated. The dashboard
escapes every interpolation by default through a tagged template, with `raw()`
as an explicit opt-out. Query-log paths stay out of the request log at info
level. Names are normalised and length-bounded before storage. Metrics use
`%q` and are served with `nosniff`.

The full triage is in
[security/semgrep-triage-2026-07-29.md](security/semgrep-triage-2026-07-29.md),
findings and residual risk included.

**Residual risk.** Anything consuming the NDJSON findings file or the query log
must do its own escaping. Domain names in a finding are attacker-chosen
strings, and a SIEM dashboard that renders them as HTML has the same problem
the reports had.

### T18 — Denial of service and resource exhaustion

*Flooding the resolver, or making it allocate without bound.*

**Mitigations.** ANY refused per RFC 8482, removing the amplification lever.
The client ACL rejects unauthorised sources before any work and without writing
a log row — otherwise an outsider could fill the disk. Upstream concurrency is
bounded (`max_inflight`); waiters give up at the query's own timeout. Request
collapsing means N identical queries cost one upstream flight. The answer cache
is bounded by entry count. Query-log writes are batched and drop rather than
block. Name length is capped at 1024 presentation bytes, found by a fuzz test.
The suffix walk allocates nothing.

Detection state is bounded per detector with O(1) approximate-LRU eviction,
specifically so a client spraying unique names cannot make the resolver
allocate per name — and the observation queue drops rather than making a lookup
wait.

**Residual risk.** No per-client query rate limiting. A single authorised
client can saturate the resolver, and on a 1 GB box that is not a high bar.
Detection eviction under load is a coverage gap, reported through
`dnsdaddy_detection_dropped_total` rather than hidden. Rate limiting is on the
roadmap.

### T19 — Supply chain

*A compromised dependency, threat feed, or release artefact.*

**Mitigations.** Few dependencies, all pinned with checksums in `go.sum`.
Dependabot with a seven-day cooldown on routine bumps, so a freshly poisoned
release is not pulled in on the day it lands; security updates are exempt.
GitHub Actions pinned to commit SHAs. CodeQL, gosec, govulncheck, Trivy and a
CycloneDX SBOM in CI. Feeds are public URLs listed in the source, downloaded
over verified TLS to a temp file and renamed, so an interrupted transfer cannot
leave a truncated list that parses as a shorter, silently weaker one.

**Residual risk.** A compromised feed provider could add a legitimate domain
and cause an outage, or remove entries and silently weaken protection. Feed
content is not signed — no widely-used blocklist is. **Large parts of this
project were written with AI assistance**, which is its own supply-chain
consideration and is stated in the README rather than buried.

### T20 — Physical and host compromise

**Mitigations.** Runs as a dedicated unprivileged account. The container drops
all capabilities with `no-new-privileges`. Data directory 0750.

**Residual risk.** SQLite is not encrypted at rest. Anyone with the file has
the query log. Full-disk encryption is the operator's job.

---

## Framework mapping

**MITRE ATT&CK** — the techniques DNS Daddy produces telemetry for are listed
with their rationale in [detection/mitre.md](detection/mitre.md). The house
rule is that a technique is attached only where the behaviour actually measured
is the behaviour the technique describes.

**NIST CSF 2.0** — DNS Daddy is mostly **DE.CM** (continuous monitoring) and
**PR.PS** / **PR.IR** (protective technology), with **RS.AN** support through
query logs and findings. It contributes nothing to **ID** or **RC**.

**CIS Controls v8** — relevant to 4.9 (DNS filtering), 8.2 and 8.5 (audit log
collection and content), 9.2 (DNS filtering services), and 13.x (network
monitoring).

Mappings are offered for orientation. DNS Daddy is not audited or certified
against any of them, and no compliance claim should be built on it.

---

## Summary of residual risk

The things most likely to matter, in order:

1. **No local DNSSEC validation.** Upstream trust is unverifiable.
2. **Encrypted-DNS bypass cannot be prevented** by DNS Daddy alone.
3. **Behavioural detection is experimental, alert-only, and unmeasured** against
   real traffic.
4. **No per-client rate limiting.** One authorised client can saturate it.
5. **Single admin credential.** No MFA, no RBAC, no token scoping.
6. **No independent security review.** This is the one that qualifies all the
   others.

[T1071.004]: https://attack.mitre.org/techniques/T1071/004/
[T1048.003]: https://attack.mitre.org/techniques/T1048/003/
[T1568.002]: https://attack.mitre.org/techniques/T1568/002/
