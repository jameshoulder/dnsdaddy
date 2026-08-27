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
| B1 | Ubuntu 24.04 + Docker | `cp .env.example .env && docker compose up -d`, no edits | same subnet | ☐ not run |
| B2 | Debian 12 + Docker | same | another private subnet, routed | ☐ not run |
| B3 | Ubuntu + Docker | same, then `docker compose down && up -d` | same subnet | ☐ not run |

**B1 is the regression test for the audit's headline finding.** The documented
path with no edits must produce a resolver that serves the LAN. Check
specifically that the Query log attributes queries to **real client addresses**
and not to a Docker bridge address — if every client shows as `172.x.x.x`,
Docker is translating the source and per-client attribution is lost.

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

## Recording a result

Open a pull request editing this file: change the status box, and add a section
below with the OS image, the exact commands, the `dnsdaddy doctor` output, and
anything you had to work out for yourself.

**Rows that fail are more valuable than rows that pass.** A row that fails
identifies a real product defect; a row that passes only confirms an
expectation. If you had to read the source, ask somebody, or invent a step to
get through it, say so — the installation experience is part of the product,
and a step you had to invent is a step the documentation is missing.
