<div align="center">

# DNS Daddy

**An experimental, self-hosted protective DNS resolver.**

Block malware, phishing, and command-and-control at the resolver. See which
device asked for what, and why it was stopped.

**Free & Open Source · No Account · No Trial · No Subscription**

[![Go](https://img.shields.io/badge/Go-1.25.12+-00ADD8?logo=go&logoColor=white)](https://go.dev)
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
| **Reports you can forward** | A Markdown summary written for someone who does not run the network. |
| **Open by construction** | Documented OpenAPI spec, Prometheus metrics, every threat feed listed by URL in [`internal/catalog`](internal/catalog/catalog.go). |

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

Go 1.25.12+, no cgo, no npm. The dashboard is embedded in the binary.

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

## Will it run on a $5 box?

Yes — that is the design target. A 1 GB / 1 vCPU Nanode is the reference
deployment.

| | |
|---|---|
| Binary | ~18 MB, static, no cgo |
| Memory | ~35 MB idle; roughly **55 bytes per blocked domain**, so a 500,000-domain index costs about 30 MB. Budget 150 MB total. |
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
```

Prometheus metrics are at `/metrics`.

## Documentation

| | |
|---|---|
| [docs/deploy.md](docs/deploy.md) | Nanode walkthrough, TLS, firewalling, backups, upgrades |
| [docs/integrations.md](docs/integrations.md) | pfSense, OPNsense, UniFi, FortiGate, Windows, roaming clients, blocking DoH bypass |
| [docs/threat-intel.md](docs/threat-intel.md) | Every default feed, where it comes from, and how to handle a false positive |
| [docs/privacy.md](docs/privacy.md) | What is stored, for how long, and how to store less |
| [docs/architecture.md](docs/architecture.md) | How a query flows through the system, and why it is built this way |
| [SECURITY.md](SECURITY.md) | Threat model and vulnerability disclosure |
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
  rather than walking the root zone itself. It does not validate DNSSEC — it
  passes signatures through and relies on the upstream to validate.
- **Browser DoH bypasses it.** Any device can resolve over HTTPS directly to a
  public resolver and skip you entirely. Mitigations are real but need
  configuring; see [docs/integrations.md](docs/integrations.md#stopping-doh-bypass).
- **One server is one server.** Nothing here does clustering or anycast. Run
  two and give clients both addresses.
- **No SSO, RBAC, or multi-tenancy.** A single admin password plus API tokens.
- **`safeSearch` is accepted by the API but not yet enforced.** It is in the
  policy model; the resolver does not act on it.

Tracked in [issues](https://github.com/jameshoulder/dnsdaddy/issues).

## Contributing and security review

This is a solo, experimental project and it would benefit enormously from
outside eyes — especially from people with real security review experience.
If you find a design flaw, a logic bug, or something that just looks wrong,
please open an issue or a PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for how
the code is organised, and [SECURITY.md](SECURITY.md) for how to report
anything sensitive privately.

There is no roadmap promise and no commercial edition — this is free,
self-hosted, open-source software, full stop.

## Licence

[Apache-2.0](LICENSE).
