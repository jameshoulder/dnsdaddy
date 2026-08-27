<div align="center">

# DNS Daddy

**A lightweight, self-hosted protective DNS resolver and DNS-security
visibility tool.**

Block malicious domains at the resolver. See which device asked for what, and
why it was stopped. Keep the telemetry on your own hardware.

**Free & Open Source · No Account · No Trial · No Subscription**

[![Go](https://img.shields.io/badge/Go-1.25.13+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache--2.0-BFED6D)](LICENSE)
[![CI](https://github.com/jameshoulder/dnsdaddy/actions/workflows/ci.yml/badge.svg)](https://github.com/jameshoulder/dnsdaddy/actions/workflows/ci.yml)
[![Security](https://github.com/jameshoulder/dnsdaddy/actions/workflows/security.yml/badge.svg)](https://github.com/jameshoulder/dnsdaddy/actions/workflows/security.yml)

</div>

---

> ### Alpha
>
> DNS Daddy works and is actively developed, but it is early software and
> **has not had an independent professional security review**. Run it in
> environments you control. [What is checked, and what none of it
> proves](docs/assurance.md).

## What is DNS Daddy?

DNS Daddy is a single Go binary that answers DNS for a network. It blocks
known-malicious domains using public threat-intelligence feeds, records what
happened in plain English, applies different policies to different networks,
and raises explainable findings about traffic no feed has heard of yet. It
ships with its own dashboard, a documented REST API, and a diagnostic command
that tells you why DNS is not working when it is not working.

It is aimed at the space commercial protective-DNS platforms occupy — Cisco
Umbrella, Cisco Secure Access, DNSFilter and the like — but from the other
direction. *Inspired by the useful ideas behind commercial protective DNS
platforms, and designed to stay lightweight, self-hosted and inspectable.* It
makes no claim to their capability, assurance, scale or support.

## Why would I use it?

Public resolvers like Quad9 and Cloudflare block known-bad domains, and that is
genuinely worth having. What they cannot tell you is:

- **which device** made the request,
- **why** it was blocked, and which feed said so,
- whether one endpoint has been quietly **beaconing** to the same
  infrastructure for three weeks,
- or give you any local, inspectable **record** of what happened.

DNS Daddy answers those, and lets different sites, VLANs and roaming laptops
carry different policies. Concretely, people use it to:

| | |
|---|---|
| **See what a network actually resolves** | A homelab or small office where nobody has ever looked at DNS traffic before. |
| **Investigate a device** | "This laptop was flagged — what has it been asking for?" |
| **Learn how protective DNS works** | The code, the threat model and the detector maths are all readable, and there is an offline lab. |
| **Keep telemetry in-house** | Nothing is uploaded. No account, no cloud tenant, no vendor with a copy of your DNS. |
| **Feed a SIEM** | Findings and query data as documented, versioned NDJSON. |

## DNS Daddy + Pi-hole

**Not a replacement.** Pi-hole is excellent at blocking ads and trackers, and
if that is what you want, Pi-hole on its own is a complete answer.

DNS Daddy focuses on a different question: protective DNS, threat
intelligence, explainable security decisions, and visibility into what devices
are resolving. The two run happily together — put DNS Daddy in front with
Pi-hole as its upstream, so DNS Daddy keeps per-client identity and Pi-hole
keeps blocking ads.

**[docs/pi-hole.md](docs/pi-hole.md)** works through both forwarding
topologies, what each one costs, and why the order matters. It is reasoned from
the code rather than measured end-to-end, and says so.

## What you get

| | |
|---|---|
| **Threat blocking** | Malware, phishing, C2 and cryptomining on by default. Newly registered domains, ads, adult and gambling available and off by default. |
| **Plain-English logs** | Every query records what happened and why: *"Domain is on a phishing list"*, not an error code. |
| **Per-network policies** | Match clients by CIDR, or give roaming devices a DoH URL that carries their policy anywhere. |
| **Instant allow-listing** | Clear a false positive from the dashboard. It applies on the next query — the answer cache is purged, so no waiting for a TTL. |
| **Encrypted upstream** | Forwards over DNS-over-TLS by default, so your ISP cannot read or tamper with what DNS Daddy passes on. |
| **DoH and DoT** | Serves RFC 8484 DNS-over-HTTPS and DNS-over-TLS as well as plain DNS. |
| **Behavioural detection** | Six experimental detectors — tunnelling, beaconing, NXDOMAIN bursts, unusual TXT, DGA-like domains, resolution failures. They alert and explain; they never block. |
| **Findings you can check** | Every detection publishes the measurements behind it, with bands and weights, so the score can be reproduced on paper. |
| **Self-diagnosis** | `dnsdaddy doctor` tells you why DNS is not working, in plain English, with the evidence. |
| **DNSSEC visibility** | Records the upstream's validation verdict per query. Not local validation — and the docs say so. |
| **SIEM-ready** | Newline-delimited JSON with a documented, versioned schema. Wazuh, Elastic, Splunk and Sentinel configurations included. |
| **Open by construction** | Documented OpenAPI spec, Prometheus metrics, every threat feed listed by URL in [`internal/catalog`](internal/catalog/catalog.go). |

## Quick start

Docker Compose, on a Linux machine or VM on your LAN:

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
./deploy/install-docker.sh
```

The installer checks Docker, finds your address, checks ports 53 and 8080,
asks whether this is a LAN or a public VPS, writes `.env`, starts the stack and
runs the readiness check. Use `--dry-run` to see what it would do first.

Prefer to drive it yourself:

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
cp .env.example .env
docker compose up -d
docker compose exec dnsdaddy dnsdaddy doctor
docker compose logs dnsdaddy | grep -i password
```

**On a LAN or in a VM there is nothing to edit.** The built-in client ACL
already serves loopback, every private range, carrier-grade NAT, link-local and
the IPv6 equivalents.

**To open the dashboard from your laptop**, set your machine's LAN address in
`.env` and restart:

```bash
echo "DNSDADDY_DASHBOARD_BIND=$(hostname -I | awk '{print $1}')" >> .env
docker compose up -d
```

That publishes the dashboard on your LAN and nowhere else — a private address
is not routable from the internet. Do **not** set it to `0.0.0.0`: that puts an
authenticated but *plaintext* management API on every interface, and Docker's
port publishing bypasses `ufw`.

**On a public VPS**, leave the dashboard on loopback, put TLS in front
([`deploy/Caddyfile.example`](deploy/Caddyfile.example)), and set
`DNSDADDY_ALLOWED_CLIENT_CIDRS` — your clients arrive from public addresses,
which the default does not cover, so every real query would be answered
`REFUSED`.

## What success looks like

Run `dnsdaddy doctor` **before** you point anything at the resolver. It reads
your configuration, reads the database, and sends real DNS queries at your own
listeners and through each upstream. It changes nothing, and exits non-zero if
anything fails, so it can gate a deployment script.

```text
DNS Daddy doctor — v0.2.0-alpha.1

SYSTEM
  [PASS] Configuration loaded.
  [PASS] The data directory is writable.

DNS LISTENER
  [PASS] DNS Daddy answered a query on 192.168.1.75:53 over udp.
         rcode: NOERROR
         elapsed: 23ms

CLIENT ACCESS
  [PASS] 9 address range(s) may send queries; everything else is REFUSED.
  [PASS] Network "Home" is permitted to send queries.
         192.168.1.0/24 → policy Standard business

UPSTREAM
  [PASS] Upstream tls://9.9.9.9:853#dns.quad9.net resolved a test query in 24ms.

THREAT INTELLIGENCE
  [PASS] 412,908 domains indexed, refreshed 3m ago.

READY
```

- **PASS** — checked, and fine.
- **WARN** — working, but worth knowing about. Stale threat intelligence still
  enforcing last-known-good data, say.
- **FAIL** — clients cannot use this, or are not being protected. The check
  names the values it compared and what to do about them.

Then prove it end to end from **another machine**:

```bash
nslookup example.com 192.168.1.75
dig @192.168.1.75 example.com          # NOERROR
dig @192.168.1.75 <a-domain-you-blocked>   # NXDOMAIN
```

**Do not change your router or DHCP DNS setting yet.** Point one device at DNS
Daddy, watch the Query log fill, leave it a day. Only then roll it out — a
mistake at the DHCP level takes DNS down for everyone at once.

## The interface

There are no screenshots in this repository yet, and adding some is one of the
most useful contributions available. If you run DNS Daddy on a real network,
the shots worth capturing are listed in
[docs/screenshots.md](docs/screenshots.md).

Until then, the [offline lab](#see-it-working) below produces a populated
dashboard on your own machine in about a minute, with no real traffic involved.

## See it working

The fastest way to understand what this does is to run the lab. It brings up an
isolated network with its own resolver, its own upstream and seven synthetic
clients, and produces findings in about a minute:

```bash
docker compose --profile lab up --build
# dashboard: http://127.0.0.1:8081   password: dnsdaddy-lab-demo-password
```

```
normal-dns                 172.30.0.31  no findings
dns-tunnelling             172.30.0.32  dns_tunnel_suspected (high)
high-entropy-subdomains    172.30.0.33  no findings
nxdomain-anomaly           172.30.0.34  nxdomain_burst (medium)
suspicious-txt             172.30.0.35  txt_activity_anomaly (medium)
dga-simulation             172.30.0.36  dga_like_domains (medium)
beaconing                  172.30.0.37  dns_beaconing_suspected (medium)
```

Nothing leaves the machine. Every name is under `.example` or `.test`, and the
upstream is a synthetic responder that ships with the lab — there is no
malicious infrastructure involved because there is none to involve. Everything
is seeded, so the same command produces the same traffic every time.

**The two `no findings` lines are the interesting ones.**
[`high-entropy-subdomains`](labs/high-entropy-subdomains.md) generates labels
that are genuinely random — indistinguishable from a tunnel's payload by
entropy alone — and asserts that nothing fires. A detection demo that only ever
shows detections teaches you nothing about the false positives you will
actually spend your time on.

See [labs/README.md](labs/README.md).

## Detection, and what it deliberately does not do

Blocking a domain because it is on a threat feed is a solved problem, and DNS
Daddy does it. The more interesting question is what you can tell from the
traffic itself when no feed has heard of the domain yet.

**None of the six detectors block anything, and that is the design rather than
an unfinished feature.** They are heuristics that infer intent from traffic
shape. They have false positives — that is inherent, not a tuning problem — and
a false positive turned into a block is a working service silently broken at a
time nobody chose. Blocking stays with the threat feeds, where a human
established the domain was malicious.

**All six are experimental.** Their thresholds are calibrated against synthetic
traffic, not a production network, and nobody has yet measured a real
false-positive rate. Every finding says so, in a `maturity` field.

A finding is not "suspicious DNS traffic". It is the measurements:

```
Possible DNS tunnelling — high, confidence 0.98

  127.0.0.3 queried 384 distinct subdomains of tunnel.example across 384
  lookups in 5m0s. Mean label entropy 4.45 bits/char, mean name length 113
  characters, 100% encoded-looking labels, 100% payload-capable record types,
  0% NXDOMAIN.

  signal                    measured    band         weight  contributed
  unique_subdomains              384    20 – 200       0.28         0.28
  mean_subdomain_entropy        4.45    3.2 – 4.2      0.18         0.18
  mean_qname_length              113    45 – 100       0.14         0.14
  max_label_length                55    30 – 63        0.10         0.08
  encoded_label_ratio           1.00    0.25 – 0.85    0.12         0.12
  payload_qtype_ratio           1.00    0.10 – 0.60    0.10         0.10
  nxdomain_ratio                0.00    0.20 – 0.80    0.08         0.00
                                                        score        0.90
```

*(Real output from the `dns-tunnelling` lab scenario — not a mock-up.)*

The contributions sum to the score, so an analyst can check the arithmetic.
**No single measurement can raise a finding** — the tunnelling detector requires
at least three of seven signals, which is the concrete answer to "high entropy
means malicious". It does not.

Full detail: **[docs/detection/README.md](docs/detection/README.md)**.

## Where the blocking comes from

No black-box intelligence. Every default feed is a public, no-registration
source listed with its URL in
[`internal/catalog/catalog.go`](internal/catalog/catalog.go) — abuse.ch
URLhaus, Phishing Army, The Block List Project, HaGeZi and CoinBlockerLists.
You can disable any of them and add your own.

Downloaded feeds are cached to disk, so a restart rebuilds the index locally in
seconds. A provider being down never leaves a booting server unprotected, and a
failed, truncated or malformed refresh keeps the last known good index rather
than emptying it.

Our own [DNS Daddy Threat Observatory](https://threats.dnsdaddy.dev) is in the
catalog too and ships **disabled**, so a stock install depends on nothing we
operate. Turning it on is one click, and from there it is an ordinary feed with
no more trust than the others — your policies still decide what is blocked, and
your query logs are never uploaded.

> The Observatory's public feed endpoint is not live yet. Enabling it today
> reports that the endpoint is not available; the same code works unchanged
> once it ships.

Full detail, including how to handle a false positive and exactly what enabling
the Observatory exposes: **[docs/threat-intel.md](docs/threat-intel.md)**.

## Security and assurance

DNS Daddy is an **AI-assisted open-source project**. AI assistance is treated
as implementation support, not security review. Security claims are backed
where possible by tests, reproducible evidence, documented design decisions and
automated analysis.

**It has not yet undergone independent professional security review.** Nobody
outside the project has adversarially reviewed the DNS parser, the resolver,
policy attribution or the authentication code. That is the largest gap in this
project and no amount of CI substitutes for it.

Running on every change: the race detector, `staticcheck`, `gosec`,
`govulncheck`, CodeQL, Semgrep, Trivy, fuzzing of the parsers every query hits
before authentication, an SBOM, and an end-to-end smoke test that asserts an
open-resolver configuration **refuses to start**.

**[docs/assurance.md](docs/assurance.md) is the honest version** — every
control, how to run it yourself, the invariants the test suite exists to
protect, and a section on what none of it proves that is meant to be read
twice. [docs/audit-2026-08.md](docs/audit-2026-08.md) is the most recent
full audit, including the bugs it found and where a reviewer should start.

## Honest limitations

Worth knowing before you rely on this:

- **No independent security review.** The caveat that qualifies every other
  line here.
- **Deployment is not yet verified across VM platforms.**
  [docs/deployment-matrix.md](docs/deployment-matrix.md) is the checklist, and
  every row on it is currently marked *not run*.
- **Forwarding, not recursive.** DNS Daddy forwards to upstream resolvers
  rather than walking the root zone itself.
- **It does not validate DNSSEC.** It asks the upstream for its verdict and
  records it per query, which is a strictly weaker statement — a lying upstream
  will happily claim an answer was validated.
  [docs/dns-security/dnssec.md](docs/dns-security/dnssec.md) is explicit about
  what the telemetry is and is not worth.
- **Behavioural detection is experimental and alert-only.** Thresholds come
  from synthetic traffic. Nothing is blocked on a heuristic, and a slow tunnel
  or a word-list DGA will not be caught at all.
- **Browser DoH bypasses it.** Any device can resolve over HTTPS directly to a
  public resolver and skip you entirely. Mitigations are real but need
  configuring; see
  [docs/integrations.md](docs/integrations.md#stopping-doh-bypass).
- **One server is one server.** No clustering or anycast. Run two and give
  clients both addresses.
- **No SSO, RBAC, or multi-tenancy.** A single admin password plus API tokens.
- **No per-client rate limiting.** One authorised client can saturate the
  resolver.
- **DNS rebinding is not mitigated.** Private addresses are not filtered out of
  upstream answers.
- **`safeSearch` is accepted by the API but not enforced.** Marked
  `deprecated` in the OpenAPI schema rather than removed — see
  [docs/roadmap.md](docs/roadmap.md#safesearch-enforcement).

**[docs/capabilities.md](docs/capabilities.md) is the full picture** — what is
available, what is experimental, and what is only planned. If you find a claim
anywhere in this repository that page does not support, that is a bug worth
reporting.

## Will it run on a $5 box?

Yes — that is the design target. A 1 GB / 1 vCPU Nanode is the reference
deployment.

| | |
|---|---|
| Binary | ~13 MB, static, no cgo |
| Memory | ~14 MB before any feed loads; roughly **165–215 bytes per blocked domain**, so a 500,000-domain index costs around 80–105 MB. Budget 250 MB total. |
| Disk | Query logs at ~100 bytes a row. 1M queries/day at the default 7-day retention is about 700 MB. |
| Load | The hot path does no database work and no allocation on a blocklist miss. |

Statistics are rolled up hourly and kept for 90 days independently of the raw
query log, so you can cut retention to a day without losing your charts.

*Measured on one machine. Treat as an order of magnitude, not a specification.*

## Detailed installation

| | |
|---|---|
| **[docs/deploy.md](docs/deploy.md)** | Full walkthrough: VPS, TLS, firewalling, monitoring, backups, upgrades, uninstall |
| [docs/deployment-matrix.md](docs/deployment-matrix.md) | The acceptance checklist for clean machines, VMs and VPSes |
| [docs/integrations.md](docs/integrations.md) | pfSense, OPNsense, UniFi, FortiGate, Windows Server, roaming clients |
| [docs/pi-hole.md](docs/pi-hole.md) | Running alongside Pi-hole |

**Native systemd** instead of Docker:

```bash
curl -fsSL https://raw.githubusercontent.com/jameshoulder/dnsdaddy/main/deploy/install.sh | sudo bash
```

Creates a service account, frees port 53 from `systemd-resolved`, installs a
hardened unit, and starts it.

> Pick **one** of Docker or systemd. Both bind port 53 and port 8080, and
> running both leaves whichever started second failing on "address already in
> use".

**From source:**

```bash
make build          # → bin/dnsdaddy
make run            # local dev on 127.0.0.1:5353, data in ./tmp
```

Go 1.25.13+, no cgo, no npm. The dashboard is embedded in the binary.

## Configuration

Config is a YAML file, with `DNSDADDY_*` environment variables taking
precedence. Every option is documented in
**[`dnsdaddy.example.yaml`](dnsdaddy.example.yaml)**.

The settings people change first:

```yaml
dns:
  upstreams:
    - "tls://9.9.9.9:853#dns.quad9.net"      # DoT, certificate verified
    - "tls://1.1.1.1:853#cloudflare-dns.com"
log:
  query_log: true          # false → statistics only, no per-query rows
  log_client_ip: true      # false → no device attribution
  retention_days: 7
```

Configuration deliberately lives in the file rather than the database, so a
deployment is reproducible from its config rather than from accumulated state.

## API

Every resolver serves its own OpenAPI 3.1 specification at `/openapi.yaml` —
generate a client against the exact build you are talking to.

```bash
# Create a token from Settings → API tokens, then:
curl -H "Authorization: Bearer dnsd_…" https://dns.example.co.uk/api/v1/overview

# Why DNS is not working, as JSON
curl -H "Authorization: Bearer dnsd_…" https://dns.example.co.uk/api/v1/diagnostics

# This month's evidence pack, ready to forward
curl -H "Authorization: Bearer dnsd_…" \
  'https://dns.example.co.uk/api/v1/reports/summary?days=30&format=markdown'

# Behavioural findings as NDJSON, for a SIEM
curl -H "Authorization: Bearer dnsd_…" \
  'https://dns.example.co.uk/api/v1/findings/export?hours=24'
```

Prometheus metrics are at `/metrics`.

## Documentation

**[docs/](docs/) is a growing DNS-security knowledge base**, not just operating
instructions — the concepts as well as the configuration, because a control you
do not understand is one you cannot judge.

| | |
|---|---|
| **[docs/capabilities.md](docs/capabilities.md)** | **Available / experimental / planned. Start here.** |
| [docs/assurance.md](docs/assurance.md) | What is checked, by what, and what none of it proves |
| [docs/audit-2026-08.md](docs/audit-2026-08.md) | The most recent full audit: findings, fixes, reviewer guide |
| [docs/threat-model.md](docs/threat-model.md) | Assets, boundaries, actors, threats, mitigations, residual risk |
| [docs/detection/](docs/detection/) | Detection engineering, the finding schema, ATT&CK policy, tunnelling in depth |
| [docs/threat-hunting/](docs/threat-hunting/) | Six hunts you can run against telemetry this actually produces |
| [docs/dns-security/](docs/dns-security/) | Protective DNS, DNSSEC, DoH/DoT and bypass |
| [labs/](labs/) | The offline lab and its seven scenarios |
| [docs/siem.md](docs/siem.md) | Wazuh, Elastic, Splunk, Sentinel |
| [docs/threat-intel.md](docs/threat-intel.md) | Every default feed, where it comes from, and handling a false positive |
| [docs/privacy.md](docs/privacy.md) | What is stored, for how long, and how to store less |
| [docs/architecture.md](docs/architecture.md) | How a query flows through the system, and why it is built this way |
| [docs/roadmap.md](docs/roadmap.md) | What might come next, and what would have to be true first |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and house style |

## Help wanted

This is a solo project and the things that would help most are specific. If any
of these is your area, it would be genuinely valuable.

**Go review** — ranked by risk, with a reviewer's guide in
[docs/audit-2026-08.md](docs/audit-2026-08.md#g-where-a-reviewer-should-start):

- `internal/dnsserver` — the DNS handler and the client ACL. Every query goes
  through it.
- `internal/resolver` — cache key construction, upstream failover, DoT/DoH.
- `internal/policy` — client attribution. Wrong attribution silently gives a
  device someone else's policy.
- `internal/api` — session handling, API tokens, CSRF, proxy trust.
- `internal/blocklist` — feed refresh and the atomic index swap. The
  last-known-good invariant is the one to attack.

**Deployment testing** — every row in
[docs/deployment-matrix.md](docs/deployment-matrix.md) is currently *not run*.
Ubuntu, Debian, Proxmox, Hyper-V, VMware, VirtualBox, a cloud VPS, plain Docker
Compose. **Rows that fail are more valuable than rows that pass**: a failure is
a real product defect, and if you had to invent a step to get through it, that
step is missing from the documentation.

**Pi-hole users** — [docs/pi-hole.md](docs/pi-hole.md) is reasoned from the
code, not measured. Running either topology on a real network and reporting
what client attribution actually looks like would turn analysis into evidence.

**Security practitioners** — please try to break:

- the resolver ACL and the open-resolver protections,
- DoH and DoT handling, including the per-network token path,
- reverse-proxy header trust,
- threat-feed handling and what a malicious or malformed feed can do,
- resource exhaustion by an authorised client.

Report anything sensitive privately via [SECURITY.md](SECURITY.md). Everything
else is welcome as an issue or a PR — see
[CONTRIBUTING.md](CONTRIBUTING.md).

**A well-described bug is worth more than a patch to code you do not yet
trust.** Findings without fixes are very welcome.

## ☕ Support the project

DNS Daddy is free, open source and self-hosted. There are no subscriptions, no
paid tiers and no licence fees, and buying a coffee unlocks precisely nothing —
there is no supporter-only build, no supporter-only feature, and no private
support queue. Everything is in this repository under Apache-2.0, for everyone,
including the people who never send a penny.

If you find the project useful and fancy supporting the hosting, testing and
caffeine behind it, you are welcome to
[buy me a coffee](https://buymeacoffee.com/jameshoulder). You absolutely don't
have to, and it buys no guarantees.

Code reviews, bug reports, documentation improvements and pull requests are
every bit as appreciated — genuinely more so.

## Project status

**Alpha. Actively developed, not independently reviewed, and free —
permanently.**

| | |
|---|---|
| Maintained by | One person, in spare time |
| Licence | Apache-2.0, no commercial edition planned or possible |
| Independent security review | **None.** The caveat that qualifies every other line. |
| Core DNS resolution | Tested, fuzzed, and unchanged in shape since the first release |
| Behavioural detection | **Experimental.** Thresholds from synthetic traffic; no measured false-positive rate |
| Deployment matrix | **Not yet executed.** See [docs/deployment-matrix.md](docs/deployment-matrix.md) |
| API | Versioned at `/api/v1`, with an OpenAPI spec served by each build |
| Finding schema | Version 1.0. Additive changes only within 1.x |
| Breaking changes | Recorded in [CHANGELOG.md](CHANGELOG.md) |

DNS Daddy began as a cybersecurity Master's project exploring how a small,
transparent protective DNS platform could work without enterprise
infrastructure. It has been developed since with an explicit engineering
process — see [docs/assurance.md](docs/assurance.md) and
[docs/audit-2026-08.md](docs/audit-2026-08.md) — and the most useful thing
anyone can do for it now is run it somewhere real and report what broke.

## Licence

[Apache-2.0](LICENSE).
