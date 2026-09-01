# Deployment acceptance matrix

A checklist for verifying DNS Daddy on a clean machine, and a record of what
has actually been run.

It exists because "it works on the developer's box" is not a test, and because
the failure that prompted the August 2026 audit
([audit-2026-08.md](audit-2026-08.md)) was a deployment failure that no unit
test could have caught — the code was correct and the shipped configuration was
not.

> **Current status: partly executed.** Several rows have now been run against
> a real Docker daemon in clean Debian 13 and Ubuntu 24.04 containers — see
> [What was actually tested](#what-was-actually-tested) below for the exact
> environment and results. What remains untested is everything that needs a
> machine with a public address: real ACME issuance, a real LAN with a second
> physical client, and hypervisor networking. Running any of those rows and
> recording the outcome is still the most useful contribution available.

---

## What automated testing already covers

Do not re-test these by hand; CI does them on every push.

| Guarantee | Where |
|---|---|
| Compose's client ACL default matches the binary's | `config.TestComposeClientACLDefaultMatchesBuiltIn` |
| `.env.example` ships no active client ACL | `config.TestEnvExampleDoesNotNarrowTheClientACL` |
| An open-resolver configuration refuses to start | end-to-end smoke test in `ci.yml` |
| A real resolver blocks, resolves, and detects a tunnel | end-to-end smoke test in `ci.yml` |
| Cross-compilation for amd64, arm64, armv7 | build matrix in `ci.yml` |

What CI cannot cover is everything below: real network interfaces, real
hypervisor networking, real firewalls, and a real port 53.

---

## How to run a row

For each row, from a **freshly provisioned machine**:

1. Record the exact OS image and version.
2. Follow the documented install path verbatim — no improvisation. **If you
   have to invent a step, that is the finding.** Record it.
3. Run `dnsdaddy doctor` (or `docker compose exec dnsdaddy dnsdaddy doctor`)
   and paste the output.
4. From a **second machine** on the client network, run both:
   ```bash
   dig @<resolver-ip> example.com
   dig @<resolver-ip> +tcp example.com
   ```
5. Confirm the query appears in the dashboard's Query log **attributed to the
   second machine's real address**, not to a gateway.
6. Restart the host. Confirm the resolver comes back and the query history
   survived.
7. Record failures and what you did about them.

Redact public addresses and domain names before posting output anywhere.

---

## A · Native Linux

| # | OS | Method | Client | Status |
|---|---|---|---|---|
| A1 | Ubuntu 24.04 LTS | `deploy/install.sh` (systemd) | same subnet | ☐ not run |
| A2 | Ubuntu 24.04 LTS | direct binary, no systemd | localhost | ☐ not run |
| A3 | Debian 12 | `deploy/install.sh` (systemd) | same subnet | ☐ not run |
| A4 | Ubuntu 24.04 LTS | `install.sh` on a host where systemd-resolved holds :53 | same subnet | ☐ not run |

**A4 is the important one.** systemd-resolved binds `127.0.0.53:53` on most
Ubuntu installs. The installer is supposed to handle it; verify that it does,
that the machine still resolves names for itself afterwards, and that
`dnsdaddy doctor` says something useful if it does not.

## B · Docker

| # | Host | Method | Client | Status |
|---|---|---|---|---|
| B0 | Ubuntu 24.04 + Docker | `./deploy/install-docker.sh` | same subnet | ☐ not run |
| B1 | Ubuntu 24.04 + Docker | `./deploy/install-docker.sh`, no edits | same subnet | ☐ not run |
| B4 | Ubuntu 24.04 + Docker | `./deploy/install-docker.sh --lan` | browser on another machine | ☐ not run |
| B2 | Debian 12 + Docker | same | another private subnet, routed | ☐ not run |
| B3 | Ubuntu + Docker | same, then `docker compose down && up -d` | same subnet | ☐ not run |
| B5 | Ubuntu 24.04 + Docker | dashboard-managed access: add a network, tick *Allow*, query; untick, query | same subnet | ☐ not run (resolver half covered in CI) |
| B6 | Ubuntu 24.04 + Docker | `./deploy/install-docker.sh --upgrade` over a B0 install | same subnet | ☐ not run |
| B7 | Ubuntu 24.04 + Docker | `./deploy/install-docker.sh --uninstall`, then re-install | same subnet | ☐ not run |

**B1 is the regression test for the audit's headline finding.** The documented
path with no edits must produce a resolver that serves the LAN. Check
specifically that the Query log attributes queries to **real client addresses**
and not to a Docker bridge address — if every client shows as `172.x.x.x`,
Docker is translating the source and per-client attribution is lost.

**B0 is the guided installer**, and has never been executed against a real
Docker daemon — only its `--dry-run` path has. Its detection routines (host
address, port 53 and 8080, systemd-resolved) and everything after the checks
are unverified on real hardware.

**B4 checks the LAN dashboard.** `--lan` must make `http://<lan-ip>:8080`
reachable from another machine on the same network, and must leave it
unreachable from anywhere else. Confirm the login works and the session
persists. Confirm too that `--lan` refuses outright on a host whose primary
address is public.

**B5 is the regression test for this pass's headline change.** Adding a network
and ticking *Allow this network to use DNS Daddy* must make its clients resolve
**without any restart**, and unticking it must produce `REFUSED` on the very
next query. Then restart the stack and confirm the permission survived. On a
VPS, repeat with a public `/32` and check the acknowledgement is demanded once
and remembered afterwards.

The *resolver* half of this is now covered by CI, against the real binary over
a real UDP socket rather than in-process: the end-to-end job starts a second
instance whose ACL deliberately excludes loopback, asserts `REFUSED`, grants
access through the API, asserts the very next query is answered, revokes it,
asserts `REFUSED` again, restarts and asserts the permission survived — and
checks that a public range is refused with 409 until acknowledged and that a
default route is refused outright. What CI cannot cover, and what B5 is still
for: the browser doing it rather than curl, Docker's port publishing and source
translation in the path, and a real client on a real subnet.

**B6 checks the upgrade path.** Data, `.env` and dashboard-managed permissions
must all survive; the run must wait for health and run `dnsdaddy doctor`. Seed
it first with a hand-set `DNSDADDY_DASHBOARD_BIND` and confirm it is left
alone, then with one carrying the installer's `# managed by` marker on a public
address and confirm it is closed.

**B7 checks uninstall.** `--uninstall` must leave the volume intact, and
re-running the installer must bring the deployment back with its history,
policies and permissions. `--purge` must refuse without an interactive
confirmation.

**B3 checks persistence.** Networks, policies, query history and findings must
survive. `docker compose down -v` would delete them, which is the point of
testing `down` without it.

## C · Virtual machines

The audit's reported failure happened in a VM, and VM networking is where
assumptions break. Record the hypervisor and the adapter mode in every row.

| # | Hypervisor | Networking | Client | Status |
|---|---|---|---|---|
| C1 | Proxmox / KVM | bridged | same subnet | ☐ not run |
| C2 | VirtualBox | NAT + port forward | host | ☐ not run |
| C3 | VirtualBox | bridged | same subnet | ☐ not run |
| C4 | Hyper-V | external switch | same subnet | ☐ not run |
| C5 | VMware | NAT | host | ☐ not run |

**Bridged rows (C1, C3, C4): the thing to verify is client attribution.** The
VM should see each client's real address. If it does, per-network policy and
behavioural detection work. Confirm in the Query log.

**NAT rows (C2, C5): the thing to verify is that the source address is
translated, and to record what it is translated to.** Under NAT the hypervisor
gateway replaces the client address, so DNS Daddy sees one address for every
client. That is not a bug in DNS Daddy and it cannot be worked around — but it
means per-client visibility is unavailable, which an operator needs to know.

Record the observed address (VirtualBox NAT typically presents `10.0.2.2`).
**These observations are the input to a future automatic NAT warning**, which
is listed as a known gap in the audit precisely because guessing at it without
data would be worse than saying nothing.

## D · Public VPS

| # | Provider | Method | Client | Status |
|---|---|---|---|---|
| D1 | any 1 GB / 1 vCPU | Docker Compose + Caddy, per `docs/deploy.md` | your own public IP | ☐ not run |
| D2 | same | same, from a **non-permitted** public address | a different network | ☐ not run |
| D3 | any | `--vps` (option 2, SSH tunnel) | your own laptop | ☐ not run |
| D4 | any | `--https` with a hostname (option 3) | a browser | ☐ not run |
| D5 | any | `--https` with the raw public IP (option 3) | a browser | ☐ not run |
| D6 | any | `--https` where issuance fails, e.g. 443 blocked at the cloud firewall | a browser | ☐ not run |

**D5 is the row that closes the last open question.** Caddy 2.11 and newer
*will* ask Let's Encrypt for an IP-address certificate — verified against the
real binary, see "What was actually tested" below — but completing the order
needs ports 80 and 443 reachable from the internet at that address, which no
environment available to the author has. What must be true if it succeeds:

- the browser shows no certificate warning, and the issuer is Let's Encrypt,
  not Caddy's internal CA (`openssl s_client -connect <ip>:443 | openssl x509
  -noout -issuer -dates`);
- the certificate's validity is about 160 hours, not 90 days — that is the
  `shortlived` profile, and it is the only one Let's Encrypt issues IP
  certificates under;
- renewal happens by itself: leave it a few days and check the dates moved.

And if it fails, the same five things as D6 must hold.

**D6 is the failure property, and is testable anywhere.** Block 443 inbound at
the provider's firewall, run `--https` with a real hostname, and check:

- the installer says so, naming the reason;
- `/etc/caddy/Caddyfile` is back to whatever it was before, or gone if there
  was nothing;
- `.env` no longer carries `DNSDADDY_SECURE_COOKIES=always`;
- `curl http://<public-ip>:8080` is refused — the dashboard is on loopback;
- the SSH tunnel command printed at the end works, **and login succeeds through
  it**.

That last one is the whole reason the `.env` revert exists. With
`secure_cookies=always` left behind the browser accepts the cookie over the
tunnel and never sends it back, and login fails with nothing to explain it.

**D4 is the one that should succeed.** Verify additionally that the certificate
is publicly trusted (a browser, not `curl -k`), that HSTS is present, and that
`http://<hostname>` redirects to HTTPS.

**D2 must fail, and must fail legibly.** A source address not in
`dns.allowed_client_cidrs` must be answered `REFUSED`, and
`dnsdaddy_client_refused_total` must increment. A VPS deployment that serves
anyone who asks is an open resolver, and it will be found and abused within
days.

Also verify on D1: HTTPS responds, the certificate is valid, the session cookie
carries `Secure`, and **`<server>:8080` is not reachable from the internet**.

## E · Constrained hardware

| # | Machine | Check | Status |
|---|---|---|---|
| E1 | 1 GB / 1 vCPU VPS | resident memory with the default feeds loaded | ☐ not run |
| E2 | Raspberry Pi 3 or 4 | as above, plus cache-hit and cache-miss latency | ☐ not run |

The README's resource claims should be checked against these rather than
asserted. If a row disagrees with the README, the README is wrong.

---

## What was actually tested

Run on 2026-08-31 against a real `dockerd` 29.3.1 in clean `debian:13` and
`ubuntu:24.04` containers, from a clean clone of this branch. **Containers, not
VMs**: there is no hypervisor available here, so anything depending on a real
NIC, a real LAN or a public address is still untested and is marked so.

Kernel 6.18.44. Docker Engine 29.3.1, Compose v5.1.1, Caddy v2.11.4 (built from
source; the distribution package is 2.6.2 — see below).

### Confirmed by inspecting real sockets and real Docker bindings

| What | How it was checked | Result |
|---|---|---|
| Option 2 binds loopback only | `docker inspect .NetworkSettings.Ports` | `8080/tcp -> 127.0.0.1:8080` |
| :8080 is unreachable off-host | `curl http://<host-ip>:8080` | connection refused |
| No IPv6 exposure | `/proc/net/tcp6` | no entry for 8080 |
| Option 1 binds one named address | `DNSDADDY_DASHBOARD_BIND=<lan-ip>` | `/proc/net/tcp` shows only that address; **not** `0.0.0.0` |
| Standalone binary defaults to loopback | real process, `/proc/net/tcp[6]` | `127.0.0.1:8080`, tcp6 none |
| Public health tier | through the published port | `{"status":"ok"}` and nothing else |
| Loopback health tier | `docker exec … wget` | full detail |
| Header spoofing | `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: ::1` | still `{"status":"ok"}` |
| ACL enforcement | narrowed to `127.0.0.0/8`, queried from the bridge | **REFUSED** |
| ACL restored | widened again, same client | admitted (SERVFAIL — no upstream here) |
| Open-resolver refusal | empty ACL, non-loopback listener | refuses to start, names the setting |
| Login / CSRF / logout | real HTTP against the container | 200 / 403 cross-origin, 201 same-origin / 401 after logout |
| Cookie attributes over plain HTTP | `Set-Cookie` header | `HttpOnly; SameSite=Lax`, no `Secure` — correct for the tunnel |
| Port 53 conflict | a process named `systemd-resolved` holding 53 | detected, named, refused to act, printed the DNSStubListener recipe |

### The HTTPS failure path, end to end

Ran `--https` with a hostname that does not resolve here, with a pre-existing
Caddyfile in `/etc/caddy`. Afterwards:

* `.env` carried `# disabled by install-docker.sh (dashboard kept on loopback)`
  against `DNSDADDY_BASE_URL`, `DNSDADDY_SECURE_COOKIES` and
  `DNSDADDY_TRUSTED_PROXY_CIDRS`;
* Docker binding still `127.0.0.1:8080`; the host's routable address refused;
* the pre-existing Caddyfile was **byte-identical** to before, with a
  timestamped backup beside it;
* **login through the tunnel posture succeeded**, with no `Secure` flag on the
  cookie.

### The shipped container image, built and run

Built from the repository's own `Dockerfile` on `golang:1.27.0-alpine` — the
base image PR #41 moved to — and run against a named volume:

| What | Result |
| --- | --- |
| Image build | succeeds; 41.7 MB final image |
| Container start | reaches the `HEALTHCHECK`'s `healthy` state |
| Login and a write | password login succeeds; creating a network returns 201 |
| `docker restart` | the network and its CIDR survive; the effective ACL comes back as the union of the configured defaults and the added range |
| Session across a restart | the cookie stays valid — sessions live in the database, not in memory |
| `GET /api/v1/health` over the published port | `{"status":"ok"}` and nothing else, because the peer is the bridge rather than loopback |
| Dashboard route walk against the container | all 11 routes, no console errors — which is the check that the `go:embed` assets actually ship |

Not verified here: `apk` cannot reach the Alpine CDN from this sandbox, so the
runtime stage was built through a local CA and proxy shim. That affects
*fetching* packages, not the Dockerfile's content — the shipped `Dockerfile` was
not modified, and `.dockerignore`'s exclusion of `*.crt` was left in place.

### Client access control, against a live resolver

Not a unit test: a real `dnsdaddy serve` with `dns.allowed_client_cidrs` set to
loopback only, queried over UDP from a second address on this host.

| Step | Result |
| --- | --- |
| Query from an address outside the ACL | `REFUSED` |
| Query from inside the ACL | reaches resolution (`SERVFAIL` here — no upstream in the sandbox — which is the point: it is not `REFUSED`) |
| `POST /networks` with a globally routable range, no acknowledgement | `409`, naming the exact public ranges |
| Same request with `publicAck` | `201` |
| Query from that range afterwards, no restart | permitted |
| `PATCH allowResolver:false`, no restart | `REFUSED` again |
| Re-grant, no restart | permitted again |

### Health detail, from a genuinely remote peer

Earlier rounds tested this with `httptest`, which serves on loopback, so the
peer was always entitled and the assertion could not fail. Repeated against a
listener bound to `0.0.0.0` and reached from a non-loopback address:

| Request | Response |
| --- | --- |
| From loopback | full detail |
| From a non-loopback peer | `{"status":"ok"}` |
| Non-loopback peer sending `X-Forwarded-For: 127.0.0.1` | `{"status":"ok"}` |
| Non-loopback peer sending `X-Real-IP: 127.0.0.1` | `{"status":"ok"}` |
| A *trusted* proxy sending `X-Forwarded-For: 127.0.0.1` | `{"status":"ok"}` |

The last row is the design: entitlement is decided by the socket peer, never by
a header, so no proxy configuration can unlock it.

### Raw-IP HTTPS: what was verified, and what was not

An earlier round of this work verified only that CertMagic's `ACMEIssuer.PreCheck`
returns "proceed" for a public IP, and treated that as evidence the path
worked. It was the wrong layer to test. A real attempt against
`172.236.31.102` then failed, which is what prompted testing the whole path
rather than one gate in it.

**Verified, against Let's Encrypt staging, with the same stack the VPS runs**
(Caddy 2.11.4 and CertMagic v0.25.3, both read out of the binary rather than
assumed):

| Step | Result |
| --- | --- |
| `caddy adapt` on the generated IPv4 Caddyfile | selects `{"module":"acme","profile":"shortlived"}` for the IP subject — not the internal CA |
| `caddy validate` on all four generated shapes | hostname, IPv4, IPv6, and the post-success HSTS variant all valid |
| ACME account registration | succeeds |
| **Order creation with an IP identifier** | **accepted** — `/acme/order/332335443/47741991763` |
| Challenges offered for the IP | `tls-alpn-01`, then `http-01` |
| Challenge outcome | `urn:ietf:params:acme:error:connection` — `"172.236.31.102: Connection refused"` |

So Let's Encrypt accepts IP identifiers under the `shortlived` profile and
Caddy 2.11.4 asks for them correctly. The order was created; only the callback
failed, because the challenge could not reach the address. That is a firewall,
not a capability gap.

Confirmed in the CertMagic source rather than from a changelog:
`acmeissuer.go:350-375` maps `api.letsencrypt.org` to *IP certificates
supported*, so the `"cannot have public IP certificate"` error reported in
[caddy#7399](https://github.com/caddyserver/caddy/issues/7399) comes from an
older CertMagic than the one we ship against.

**Now verified: an actual issued certificate, on a real VPS.**

Staging proved the order was accepted but not that a certificate arrived,
because that needs ports 80 and 443 reachable from the internet at the address
being certified. That has since been done, once, on a real deployment:

| | |
| --- | --- |
| Host | Debian GNU/Linux 13 (trixie), Linux 6.12 |
| Docker | 26.1.5, Compose 2.26.1 |
| Caddy | 2.11.4, installed from the upstream repository |
| Target | the VPS's own public IPv4 address, no hostname |

What was observed on that deployment:

- Let's Encrypt issued a **publicly trusted certificate for the raw IPv4
  address** under the `shortlived` profile;
- the certificate verified against the system CA store with ordinary `curl` —
  not `curl -k`, which proves nothing;
- the certificate matched the address being used;
- HSTS was enabled, and plain HTTP redirected to HTTPS with a 308;
- Caddy reached DNS Daddy on `127.0.0.1:8080`;
- **host port 8080 was not reachable from outside**, checked from off the host;
- the DNS UDP and TCP listeners, the dashboard health endpoint and the threat
  feeds were all working.

So the architecture in row D4 is proven end to end:

    Internet → :443 (Caddy, TLS) → 127.0.0.1:8080 → container :8080

**What this does not establish.** One host, one distribution, one cloud
provider. Nothing here says Ubuntu, RHEL, Alpine, or any particular provider's
firewall behaves the same way, and a certificate that issued once is not a
guarantee about rate limits or profile availability later.
[vps-validation.md](vps-validation.md) remains the script for repeating it.

**Do not point installer development at production Let's Encrypt.** Repeated
runs against a live CA burn the duplicate-certificate and failed-authorisation
limits for the identifier, and those limits are measured in days. The staging
endpoint exists for this; the installer's own test suite reaches no ACME server
at all, and feeds captured journal text through the same `journalctl` the
diagnosis reads.

Also found: `apt-get install caddy` on Debian 13 gets **Caddy 2.6.2** when the
upstream repository is unreachable, and 2.6.2 rejects the `profile`
subdirective outright. The installer now checks the version first.

### Still untested

Everything needing a public address or real hardware: ACME issuance (D4, D5),
a second physical client on a LAN (A*, B*, C*), hypervisor networking (C*),
IPv6 at runtime — this host has no IPv6 stack, so IPv6 is covered by unit tests
over the classification logic rather than by a live socket — and constrained
hardware (E*).

---

## Fresh-VM procedures, copy and paste

Nothing below has been run by the author — there is no hypervisor in the
environment this was written in. They are written out so that running one is a
matter of pasting rather than of working out what was meant.

### Debian 13 (trixie), minimal netinst

```bash
# --- as root on a fresh VM -------------------------------------------------
apt-get update
apt-get install -y ca-certificates curl git

# Docker, from Docker's own repository rather than Debian's older packaging.
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy

# See what it would do before it does it. This changes nothing.
./deploy/install-docker.sh --dry-run

# Then one of the three modes:
./deploy/install-docker.sh --lan                                  # option 1
./deploy/install-docker.sh --vps                                  # option 2
DNSDADDY_HTTPS_HOSTNAME=dns.example.com ./deploy/install-docker.sh --https   # option 3, hostname
DNSDADDY_HTTPS_HOSTNAME=ip             ./deploy/install-docker.sh --https   # option 3, detected public IP
```

Debian 12 (bookworm) works the same way; substitute the codename, which the
`$VERSION_CODENAME` expansion above already does.

### Ubuntu 24.04 LTS, cloud image

```bash
# --- as root on a fresh VM -------------------------------------------------
apt-get update
apt-get install -y ca-certificates curl git

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
./deploy/install-docker.sh --dry-run
```

**Ubuntu needs one extra thing.** `systemd-resolved` holds port 53 on almost
every Ubuntu install. The installer detects it, names it, and refuses to change
it for you — altering how a remote machine resolves names is how people lose
remote machines. Do it yourself first:

```bash
mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/dnsdaddy.conf
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl restart systemd-resolved

# Confirm 53 is free, and that this machine can still resolve names:
ss -lnup 'sport = :53'
getent hosts deb.debian.org
```

Then run the installer as above.

### What to check afterwards, in every mode

```bash
# 1. The resolver answers, and the ACL is what you think it is.
docker compose exec dnsdaddy dnsdaddy doctor

# 2. The management port is NOT on a public address. From another machine:
curl --max-time 5 http://<server-public-ip>:8080/    # must fail to connect

# 3. From the server itself, liveness only:
curl -s http://127.0.0.1:8080/api/v1/health
#    Through the published port this returns {"status":"ok"} and nothing else.
#    For the detail, ask from inside the container, where the peer is loopback:
docker compose exec dnsdaddy wget -qO- http://127.0.0.1:8080/api/v1/health

# 4. DNS actually resolves, from a second machine you have permitted:
dig @<server-ip> example.com
dig @<server-ip> +tcp example.com

# 5. And an unpermitted source is refused rather than served:
#    (run from a network you have NOT added under Networks)
dig @<server-ip> example.com     # expect: status: REFUSED
```

Record what happened in the tables above, including anything you had to work
out that this page did not tell you.

---

## Recording a result

Open a pull request editing this file: change the status box, and add a section
below with the OS image, the exact commands, the `dnsdaddy doctor` output, and
anything you had to work out for yourself.

**Rows that fail are more valuable than rows that pass.** A row that fails
identifies a real product defect; a row that passes only confirms an
expectation. If you had to read the source, ask somebody, or invent a step to
get through it, say so — the installation experience is part of the product,
and a step you had to invent is a step the documentation is missing.
