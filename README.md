<div align="center">

# DNS Daddy

**A free, open-source, self-hosted protective DNS project — designed to give
people visibility and control over what their networks resolve.**

Block malware, phishing and command-and-control at the resolver. See which
device asked for what, and why it was stopped. Then look at the traffic itself
and see what reputation feeds cannot tell you.

**Free & Open Source · No Account · No Trial · No Subscription**

[![Go](https://img.shields.io/badge/Go-1.25.13+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache--2.0-BFED6D)](LICENSE)
[![CI](https://github.com/jameshoulder/dnsdaddy/actions/workflows/ci.yml/badge.svg)](https://github.com/jameshoulder/dnsdaddy/actions/workflows/ci.yml)

</div>

---

> ⚠️ **Experimental proof of concept — not independently audited and not
> currently represented as production-grade security software.** Review the
> code and test it in environments you control before relying on it.

## What this is

DNS Daddy is a hobby / learning project: a single Go binary that answers DNS
for a network, blocks known-malicious domains using public
threat-intelligence feeds, and records what happened in plain English. It
ships with its own dashboard and a documented REST API.

It started as a personal project built while studying cybersecurity at
Master's level, as a way to learn DNS internals, Go, and secure-by-default
system design in practice. Large parts of it were written with extensive
AI assistance ("vibe coded") — that made it possible to build something this
size as a side project, but it also means it has **not** had the kind of
independent, adversarial security review that production security software
needs before you should trust it with anything that matters.

**This is not currently represented as a finished, audited, or
enterprise-ready product.** It is free, open source (Apache-2.0), and
self-hosted only — there is no paid tier, no account, no trial, and no
licence fee, now or planned. It is intended primarily for:

- learning and experimentation,
- labs and homelabs,
- security research, and
- peer review — **if you have security experience and are willing to poke
  holes in this, that is genuinely wanted.** Issues and PRs pointing out
  flaws (design or implementation) are one of the most useful contributions
  this project can receive right now.

If you are looking for something audited and vendor-supported for a
production network, this is not (yet) that. If you want to learn how a small
protective-DNS resolver is built, read the code, break it, and tell me what
you find, you are exactly who this is for.

## Why not just use Quad9 or Cloudflare?

Public resolvers block known-bad domains and that is genuinely worth having.
What they cannot tell you is:

- which device made the request,
- why it was blocked,
- whether one endpoint has been quietly beaconing to the same infrastructure
  for three weeks,
- or any kind of local, inspectable record of what happened.

DNS Daddy answers all of those, and lets different sites, VLANs, and roaming
laptops carry different policies.

## What you get

| | |
|---|---|
| **Threat blocking** | Malware, phishing, C2, and cryptomining on by default. Newly registered domains, ads, adult, and gambling available and off by default. |
| **Plain-English logs** | Every query records what happened and why: *"Domain is on a phishing list"*, not an error code. |
| **Per-network policies** | Match clients by CIDR, or give roaming devices a DoH URL that carries their policy anywhere. |
| **Instant allow-listing** | Clear a false positive from the dashboard. It applies on the next query — the answer cache is purged, so no waiting for a TTL. |
| **Encrypted upstream** | Forwards over DNS-over-TLS by default, so your ISP cannot read or tamper with what DNS Daddy passes on. |
| **DoH and DoT** | Serves RFC 8484 DNS-over-HTTPS and DNS-over-TLS as well as plain DNS. |
| **Behavioural detection** | Six experimental detectors — DNS tunnelling, beaconing, NXDOMAIN bursts, unusual TXT, DGA-like domains, resolution failures. They alert and explain; they never block. |
| **Findings you can check** | Every detection publishes the measurements behind it, with bands and weights, so the score can be reproduced on paper. |
| **DNSSEC visibility** | Records the upstream's validation verdict per query. Not local validation — and the docs say so. |
| **SIEM-ready** | Newline-delimited JSON with a documented, versioned schema. Wazuh, Elastic, Splunk and Sentinel configurations included. |
| **Reports you can forward** | A Markdown summary written for someone who does not run the network. |
| **Open by construction** | Documented OpenAPI spec, Prometheus metrics, every threat feed listed by URL in [`internal/catalog`](internal/catalog/catalog.go). |

## See it working

The fastest way to understand what this does is to run the lab. It brings up an
isolated network with its own resolver, its own upstream and seven synthetic
clients, and produces findings in about a minute:

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
docker compose --profile lab up --build
# dashboard: http://127.0.0.1:8081   password: dnsdaddy-lab-demo-password
```

```
$ dnsdaddy-lab -scenario all -speed 10
▶ dns-tunnelling — 384 queries over 6m0s (replayed in ~36s)
▶ nxdomain-anomaly — 719 queries over 6m0s
▶ normal-dns — 117 queries over 6m0s
▶ high-entropy-subdomains — 522 queries over 6m0s
...

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
malicious infrastructure involved because there is none to involve.

The two `no findings` lines are the interesting ones.
[`high-entropy-subdomains`](labs/high-entropy-subdomains.md) generates labels
that are genuinely random — indistinguishable from a tunnel's payload by
entropy alone — and asserts that nothing fires.

Everything is seeded, so the same command produces the same traffic every time.
See [labs/README.md](labs/README.md).

> **Screenshots welcome.** There are none in this repository yet, and a
> pull request adding a few of the dashboard would be a genuinely useful
> contribution.

## Install

### Docker (recommended)

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
cp .env.example .env
$EDITOR .env            # set DNSDADDY_ALLOWED_CLIENT_CIDRS — see below
docker compose up -d
docker compose logs dnsdaddy | grep password
```

> **Set `DNSDADDY_ALLOWED_CLIENT_CIDRS` before you rely on this.** The built-in
> default serves loopback and the private ranges only. On a VPS your clients
> arrive from public addresses, so leaving it unset means every real query is
> answered `REFUSED` — while the dashboard still reports itself healthy.

**The dashboard is published on `127.0.0.1:8080` only.** `http://<server>:8080`
will not connect from another machine, and that is deliberate: it keeps an
authenticated management API off the public internet in plaintext. To reach it:

- **From the server:** `curl http://127.0.0.1:8080/api/v1/health`
- **From your laptop, no public DNS name:** SSH tunnel, then browse to
  `http://127.0.0.1:8080`
  ```bash
  ssh -L 8080:127.0.0.1:8080 you@your-server
  ```
- **Properly, with a domain:** put Caddy in front for HTTPS —
  [`deploy/Caddyfile.example`](deploy/Caddyfile.example) and
  [docs/deploy.md](docs/deploy.md#5-put-tls-in-front-of-the-dashboard).

Do **not** change the port mapping to `8080:8080` to make it reachable. Docker's
port publishing bypasses `ufw`, so that exposes the management API to the whole
internet over plain HTTP.

Then sign in and go to **Threat feeds → Refresh now**.

To survive reboots, enable Docker and the Compose unit:

```bash
sudo systemctl enable docker
sudo cp deploy/dnsdaddy-compose.service /etc/systemd/system/
sudo $EDITOR /etc/systemd/system/dnsdaddy-compose.service   # set WorkingDirectory
sudo systemctl daemon-reload && sudo systemctl enable --now dnsdaddy-compose
```

Check the whole service — container, API, DNS, and HTTPS — with:

```bash
./deploy/healthcheck.sh
```

### systemd

```bash
curl -fsSL https://raw.githubusercontent.com/jameshoulder/dnsdaddy/main/deploy/install.sh | sudo bash
```

Creates a service account, frees port 53 from `systemd-resolved`, installs a
hardened unit, and starts it.

> Pick **one** of Docker or systemd. Both bind port 53 and port 8080, and
> running both leaves whichever started second failing on "address already in
> use". If you use Docker, make sure the native service is not also enabled:
> `sudo systemctl disable --now dnsdaddy`.

### From source

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
make build          # → bin/dnsdaddy
make run            # local dev on 127.0.0.1:5353, data in ./tmp
```

Go 1.25.13+, no cgo, no npm. The dashboard is embedded in the binary.

## First 30 minutes

1. **Install** — above. From the server, confirm
   `curl http://127.0.0.1:8080/api/v1/health` returns `"status":"ok"`.
   `"degraded"` means it is resolving but has no blocklist yet — carry on to
   step 2, then re-check.
2. **Load feeds** — Threat feeds → Refresh now. Expect a few hundred thousand domains.
3. **Test on one device** before touching anyone else's DNS:
   ```bash
   dig @<server> example.com          # NOERROR
   dig @<server> <a-domain-you-blocked>   # NXDOMAIN
   ```
4. **Point a test VLAN at it**, watch the Query log fill, and leave it a day.
5. **Then** change your DHCP scope or firewall for everyone, and block outbound
   port 53 to everything except DNS Daddy so devices cannot route around it.

Setup instructions for pfSense, OPNsense, UniFi, FortiGate, Windows Server, and
roaming clients are in **[docs/integrations.md](docs/integrations.md)**.

## Detection, and what it deliberately does not do

Blocking a domain because it is on a threat feed is a solved problem, and DNS
Daddy does it. The more interesting question is what you can tell from the
traffic itself when no feed has heard of the domain yet.

Six detectors watch the query stream and raise explainable findings:

| | Looks for |
|---|---|
| `dns_tunnel` | DNS being used as a data carrier |
| `dga_like` | Algorithmically generated rendezvous domains |
| `nxdomain_anomaly` | A host working through a list of names that do not exist |
| `txt_anomaly` | TXT records used for something other than mail policy |
| `dns_beaconing` | Queries arriving on a machine's schedule, not a person's |
| `resolution_failure` | Domains that have stopped resolving upstream |

**None of them block anything, and that is the design rather than an unfinished
feature.** These are heuristics that infer intent from traffic shape. They have
false positives — that is inherent, not a tuning problem — and a false positive
turned into a block is a working service silently broken at a time nobody chose.
Blocking stays with the threat feeds, where a human established the domain was
malicious. Detection observes, scores, explains and alerts.

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

*(Real output from the `dns-tunnelling` lab scenario, below — not a mock-up.)*

The contributions sum to the score, so an analyst can check the arithmetic.
**No single measurement can raise a finding** — the tunnelling detector requires
at least three of seven signals, which is the concrete answer to "high entropy
means malicious". It does not.

**See it happen, offline, in about a minute:**

```bash
docker compose --profile lab up --build
# dashboard: http://127.0.0.1:8081   password: dnsdaddy-lab-demo-password
```

Seven scenarios on an isolated network, with their own synthetic upstream.
Nothing leaves the machine and no malicious infrastructure is involved — every
name is under `.example` or `.test`. Two of the seven are designed to produce
**no** findings, and they are the useful ones: a detection demo that only ever
shows detections teaches you nothing about the false positives you will actually
spend your time on.

Full detail: **[docs/detection/README.md](docs/detection/README.md)** ·
**[labs/README.md](labs/README.md)**

## Will it run on a $5 box?

Yes — that is the design target. A 1 GB / 1 vCPU Nanode is the reference
deployment.

| | |
|---|---|
| Binary | ~13 MB, static, no cgo |
| Memory | ~14 MB before any feed loads; roughly **165–215 bytes per blocked domain** depending on how long the names in your feeds are, so a 500,000-domain index costs somewhere around 80–105 MB. Budget 250 MB total. |
| Disk | Query logs at ~100 bytes a row. 1M queries/day at the default 7-day retention is about 700 MB. |
| Load | The hot path does no database work and no allocation on a blocklist miss. |

Statistics are rolled up hourly and kept for 90 days independently of the raw
query log, so you can cut retention to a day without losing your charts.

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
The dashboard shows the effective configuration read-only.

## API

Every resolver serves its own OpenAPI 3.1 specification at `/openapi.yaml` —
generate a client against the exact build you are talking to.

```bash
# Create a token from Settings → API tokens, then:
curl -H "Authorization: Bearer dnsd_…" https://dns.example.co.uk/api/v1/overview

# This month's evidence pack, ready to forward
curl -H "Authorization: Bearer dnsd_…" \
  'https://dns.example.co.uk/api/v1/reports/summary?days=30&format=markdown'

# Behavioural findings as NDJSON, for a SIEM
curl -H "Authorization: Bearer dnsd_…" \
  'https://dns.example.co.uk/api/v1/findings/export?hours=24'

# What this build says about its own detectors — generated from the running
# code, so it cannot drift from what it does
curl -H "Authorization: Bearer dnsd_…" https://dns.example.co.uk/api/v1/detectors
```

Prometheus metrics are at `/metrics`.

## Documentation

**[docs/](docs/) is a growing DNS-security knowledge base**, not just operating
instructions — the concepts as well as the configuration, because a control you
do not understand is one you cannot judge.

| | |
|---|---|
| **[docs/capabilities.md](docs/capabilities.md)** | **Available / experimental / planned. Start here.** |
| [docs/threat-model.md](docs/threat-model.md) | Assets, boundaries, actors, threats, mitigations, residual risk |
| [docs/detection/](docs/detection/) | Detection engineering, the finding schema, ATT&CK policy, tunnelling in depth |
| [docs/threat-hunting/](docs/threat-hunting/) | Six hunts you can run against telemetry this actually produces |
| [docs/dns-security/](docs/dns-security/) | Protective DNS, DNSSEC, DoH/DoT and bypass |
| [labs/](labs/) | The offline lab and its seven scenarios |
| [docs/siem.md](docs/siem.md) | Wazuh, Elastic, Splunk, Sentinel |
| [docs/roadmap.md](docs/roadmap.md) | What might come next, and what would have to be true first |
| [docs/deploy.md](docs/deploy.md) | Nanode walkthrough, TLS, firewalling, backups, upgrades |
| [docs/integrations.md](docs/integrations.md) | pfSense, OPNsense, UniFi, FortiGate, Windows, roaming clients, blocking DoH bypass |
| [docs/threat-intel.md](docs/threat-intel.md) | Every default feed, where it comes from, and how to handle a false positive |
| [docs/privacy.md](docs/privacy.md) | What is stored, for how long, and how to store less |
| [docs/architecture.md](docs/architecture.md) | How a query flows through the system, and why it is built this way |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and house style |

## Where the blocking comes from

No black-box intelligence. Every default feed is a public, no-registration
source listed with its URL in
[`internal/catalog/catalog.go`](internal/catalog/catalog.go), including
abuse.ch URLhaus, Phishing Army, The Block List Project, HaGeZi, and
CoinBlockerLists. You can disable any of them and add your own.

Downloaded feeds are cached to disk, so a restart rebuilds the index locally in
seconds — the resolver is protecting traffic before it makes a single HTTP
request, and a provider being down never leaves a booting server unprotected.

Full detail, including how to handle a false positive: **[docs/threat-intel.md](docs/threat-intel.md)**.

## Honest limitations

Worth knowing before you rely on this:

- **Forwarding, not recursive.** DNS Daddy forwards to upstream resolvers
  rather than walking the root zone itself.
- **It does not validate DNSSEC.** It asks the upstream for its verdict and
  records it per query, which is a strictly weaker statement — a lying upstream
  will happily claim an answer was validated. Local validation is on the
  roadmap. [docs/dns-security/dnssec.md](docs/dns-security/dnssec.md) is
  explicit about what the telemetry is and is not worth.
- **Behavioural detection is experimental and alert-only.** The thresholds come
  from synthetic traffic. Nothing is blocked on a heuristic, and a slow tunnel
  or a word-list DGA will not be caught at all —
  [docs/capabilities.md](docs/capabilities.md) lists what each detector misses.
- **Browser DoH bypasses it.** Any device can resolve over HTTPS directly to a
  public resolver and skip you entirely. Mitigations are real but need
  configuring; see [docs/integrations.md](docs/integrations.md#stopping-doh-bypass).
- **One server is one server.** Nothing here does clustering or anycast. Run
  two and give clients both addresses.
- **No SSO, RBAC, or multi-tenancy.** A single admin password plus API tokens.
- **`safeSearch` is accepted by the API but not enforced.** It is stored on the
  policy and returned again; the resolver never reads it, so setting it changes
  nothing. It is marked `deprecated` in the OpenAPI schema and says so in its
  own description, rather than being removed — see
  [docs/roadmap.md](docs/roadmap.md#safesearch-enforcement).
- **No per-client rate limiting.** One authorised client can saturate the
  resolver.
- **DNS rebinding is not mitigated.** Private addresses are not filtered out of
  upstream answers.

**[docs/capabilities.md](docs/capabilities.md) is the full picture** — what is
available, what is experimental, and what is only planned. If you find a claim
anywhere in this repository that page does not support, that is a bug worth
reporting.

Also tracked in [issues](https://github.com/jameshoulder/dnsdaddy/issues).

## Security testing and review

**None of this makes DNS Daddy secure, audited, certified, or free of
vulnerabilities.** It is still an experimental, AI-assisted proof of concept
that has had no independent adversarial review. Automated tools find the bugs
they have rules for; they do not find design flaws, and a clean run is evidence
of nothing much. This section describes what has actually been done, so you can
judge it for yourself rather than take a badge on trust.

**Running in CI on every change** — [`security.yml`](.github/workflows/security.yml):

| | |
|---|---|
| [CodeQL](https://codeql.github.com/) | `security-extended` query set |
| [Semgrep](https://semgrep.dev/) | `p/golang`, `p/github-actions`, `p/secrets`; a finding fails the build |
| [gosec](https://github.com/securego/gosec) | Go security linter, medium severity and above |
| [govulncheck](https://go.dev/blog/govulncheck) | Advisories actually reachable from this code, standard library included |
| [Trivy](https://trivy.dev/) | Container image and filesystem scanning |
| Fuzzing | Domain normalisation and suffix matching, the parsers every query hits before authentication |
| SBOM | CycloneDX, so an operator can answer "am I affected?" without waiting for me |

Dependencies and pinned action SHAs are monitored by Dependabot, with a
seven-day cooldown on routine version bumps so a freshly poisoned release is
not pulled in on the day it lands. Security updates are exempt from that
cooldown and still arrive immediately.

**One advisory is knowingly outstanding.** Run `govulncheck ./...` yourself and
it will report *"1 vulnerability in modules you require, but your code doesn't
appear to call"*. That is
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) — `golang.org/x/crypto/openpgp`
is unmaintained and unsafe by design, and it has no fixed version. DNS Daddy
requires `golang.org/x/crypto` for `bcrypt`, which is what hashes the admin
password; it never imports `openpgp`, so the vulnerable code is not built into
the binary. It is listed here rather than left for you to find, because "zero
findings" that quietly excludes a category is worse than a number with an
explanation.

**Semgrep findings are triaged, not just counted.** DNS Daddy has been scanned
with [Semgrep](https://semgrep.dev/) and the findings assessed against the
actual code and data flow rather than the rule name. The review produced real
fixes, most notably remediation of a **Markdown injection** issue in generated
reports: feed, network, location and policy names reached the rendered report
unescaped. It also produced contextual false positives — binary DNS wire
responses, Prometheus text output and a static embedded OpenAPI document are all
flagged by an HTML-escaping rule that does not apply to them, and escaping any of
the three would corrupt the protocol rather than protect anyone. Those are
documented with narrow, line-specific suppressions naming the exact rule and the
tests that justify it; no rule is disabled repository-wide.

That review was originally a point-in-time scan, which turned out to be its own
lesson. When the tool was re-run during a later audit, **three of the
suppressions were no longer suppressing anything** — Semgrep honours the
annotation only on the matched line or the one immediately above it, and an
intervening comment had quietly disabled two of them. Nothing noticed, because
nothing re-ran the tool. Semgrep is now in CI for exactly that reason.

The full triage — every finding, its classification, what was changed, what was
found to be wrong on re-inspection, and the residual risk that was *not* fixed
— is in
[docs/security/semgrep-triage-2026-07-29.md](docs/security/semgrep-triage-2026-07-29.md).
It is kept in the repository for scrutiny, on the view that showing the
reasoning is worth more than treating a green scanner as proof of security.

## Contributing and security review

This is a solo, experimental project and it would benefit enormously from
outside eyes — especially from people with real security review experience.
If you find a design flaw, a logic bug, or something that just looks wrong,
please open an issue or a PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for how
the code is organised, and [SECURITY.md](SECURITY.md) for how to report
anything sensitive privately.

There is no roadmap promise and no commercial edition — this is free,
self-hosted, open-source software, full stop.

## ☕ Support the project

DNS Daddy is free, open source and self-hosted. There are no subscriptions, no
paid tiers and no licence fees, and buying a coffee unlocks precisely nothing —
there is no supporter-only build, no supporter-only feature, and no private
support queue. Everything is in this repository under Apache-2.0, for everyone,
including the people who never send a penny.

If you find the project useful and fancy supporting the hosting, testing and
caffeine behind it, you are welcome to
[buy me a coffee](https://buymeacoffee.com/jameshoulder). You absolutely don't
have to, and it buys no guarantees — this is still an unaudited proof of
concept built in someone's spare time, and a coffee does not change that.

Code reviews, bug reports, documentation improvements and pull requests are
every bit as appreciated — genuinely more so, if you have security experience
and are willing to
[poke holes in it](#contributing-and-security-review). Code, bug reports and
coffee, all gratefully accepted.

## Project status

**Actively developed, experimental, unaudited, and free — permanently.**

| | |
|---|---|
| Maintained by | One person, in spare time |
| Licence | Apache-2.0, no commercial edition planned or possible |
| Independent security review | **None.** This is the caveat that qualifies every other line. |
| Core DNS resolution | Stable. Tested, fuzzed, and unchanged in shape since the first release. |
| Behavioural detection | **Experimental.** Thresholds from synthetic traffic; no measured false-positive rate. |
| API | Versioned at `/api/v1`, with an OpenAPI spec served by each build |
| Finding schema | Version 1.0. Additive changes only within 1.x. |
| Breaking changes | Recorded in [CHANGELOG.md](CHANGELOG.md) |

What would most improve this project is not a feature. It is somebody running
the detectors on a real network and reporting what fired and whether it was
real. See [docs/roadmap.md](docs/roadmap.md).

## Licence

[Apache-2.0](LICENSE).
