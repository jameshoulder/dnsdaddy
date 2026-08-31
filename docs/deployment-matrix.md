# Deployment acceptance matrix

A checklist for verifying DNS Daddy on a clean machine, and a record of what
has actually been run.

It exists because "it works on the developer's box" is not a test, and because
the failure that prompted the August 2026 audit
([audit-2026-08.md](audit-2026-08.md)) was a deployment failure that no unit
test could have caught — the code was correct and the shipped configuration was
not.

> **Current status: none of the matrix below has been executed on real
> hardware or real VMs.** The rows are the tests, not the results. Running any
> row and recording the outcome is one of the most useful contributions
> available to this project right now.

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

**D5 is expected to fail today, and the point is *how* it fails.** Caddy
refuses IP-address subjects before sending the ACME order
([caddyserver/caddy#7399](https://github.com/caddyserver/caddy/issues/7399)),
so on current releases there is no certificate to be had. What must be true
afterwards:

- the installer says so, naming the reason;
- `/etc/caddy/Caddyfile` is back to whatever it was before, or gone if there
  was nothing;
- `.env` no longer carries `DNSDADDY_SECURE_COOKIES=always`;
- `curl http://<public-ip>:8080` is refused — the dashboard is on loopback;
- the SSH tunnel command printed at the end actually works, and login succeeds
  through it.

That last one is the whole reason the `.env` revert exists. With
`secure_cookies=always` left behind, the browser accepts the cookie over the
tunnel and never sends it back, and login fails with nothing to explain it.

**D6 is the same property reached a different way**, and is the row to run if
you cannot easily reproduce D5. Block 443 inbound at the provider's firewall,
run `--https` with a real hostname, and check the same five things.

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
