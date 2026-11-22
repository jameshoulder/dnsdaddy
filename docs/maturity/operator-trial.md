# Independent operator trial (cohort preparation)

This is the reproducible first-trial path for a security-minded homelab
operator using Docker on a small Linux host with one noncritical client. The
question under test is whether DNS Daddy helps them understand a confusing DNS
decision or client behaviour well enough to keep using it.

**Recruitment target:** five independent testers. This document does not claim
those testers already exist.

**Source revision for this trial text:** use the git revision that contains
this guide and the `operator-smoke` Makefile target (for example the merge
commit of the operator-validation PR, or the branch tip while that PR is open).
Confirm both `docs/maturity/operator-trial.md` and `make operator-smoke` exist
at the checked-out revision before starting. Prefer a released tag when one
ships the same behaviour; do not invent a fictional release.

## Prerequisites (timed separately from time-to-first-query)

- Linux host with Docker Engine and Compose v2
- Ability to set DNS on **one** noncritical client (not the whole LAN)
- Record the client's **original DNS settings** before changing anything
- Open management access path (SSH tunnel or LAN) without publishing the
  dashboard publicly unless that is an explicit choice

## One controlled path

1. **Install** with [`deploy/install-docker.sh`](../../deploy/install-docker.sh)
   or Compose from the revision under test. Do not invent a release artifact.
2. **Management access:** note dashboard URL/port vs DNS UDP/TCP ports. Capture
   the initial admin password handling the installer prints; change it.
3. **Permissions:** inspect configured and effective source permissions,
   including Default ad-hoc access. Grant **one** explicitly permitted test
   client (/32 or /128). Do not widen ACLs to make diagnostics pass.
4. **External-client UDP and TCP:** from that client, query the published DNS
   address over UDP and TCP. Expect answers when permitted and `REFUSED` when
   the grant is removed.
5. **Synthetic decision:** use the isolated lab profile / existing fixtures
   (`make lab` or documented lab traffic) to produce one deterministic block or
   finding, then open Investigate / Map / decision evidence. Do not disable
   validation, switch saved modes, edit router/DHCP DNS for the whole site, or
   open firewall ports merely to pass onboarding.
6. **Rollback:** restore the client's original DNS settings. DNS Daddy may keep
   running for further lab use.

## Readiness evidence (keep these separate)

| Evidence | Means | Does not mean |
| --- | --- | --- |
| Configuration checked | `dnsdaddy doctor` / Setup shows expected listeners and ACL sources | Firewall or NAT is correct |
| Listener observed | Process is bound / published as configured | Remote clients can reach it |
| Query received | Live activity or logs show an arrival | Client got the bytes |
| Response produced | Handler completed an answer or refusal | Delivery across NAT |
| External client confirmed | The permitted client itself received UDP and TCP answers (or REFUSED when denied) | All devices on the LAN work |

Server-local counters never prove client delivery, NAT mapping or firewall
reachability.

## Failure guidance (reuse existing diagnostics)

| Symptom | Likely meaning | Where to look |
| --- | --- | --- |
| `REFUSED` | Source not permitted | Networks / effective ACL / Default ad-hoc; [resolver-access-recovery.md](../resolver-access-recovery.md) |
| `SERVFAIL` | Upstream/validation/policy failure path | doctor UPSTREAM, mode, Live experimental semantics |
| Timeout | Nothing answered on the path used | Port publish, host firewall, wrong DNS IP |
| Port conflict | Another process holds :53 or the dashboard port | doctor port-conflict attribution |
| Incomplete address discovery | Container/NAT limits | Setup server-address labels; enter the real host/public IP |

Direct self-forwarding is reported only where provable. Suspicious indirect
topology is labelled uncertain — never auto-corrected by widening access.

## Optional coexistence recipe (inline trial, not passive monitoring)

```
Lab client → DNS Daddy (native transport profile + Forward mode) → existing Pi-hole → existing upstream
```

| Hop | Client identity | Notes |
| --- | --- | --- |
| Lab client → DNS Daddy | Preserved at DNS Daddy | Grant only the lab client |
| DNS Daddy → Pi-hole | Pi-hole sees DNS Daddy's address | Upstream block attribution is limited; Pi-hole per-client groups collapse |
| Local names | Prefer one owner for local zones | Duplicate authority creates loops; see [pi-hole.md](../pi-hole.md) |

Native **Live** bypasses this forwarding path. The encrypted outbound profile
uses only its approved endpoints. **AdGuard is unverified** until tested. Two
DNS addresses on a client are not deterministic failover.

## Environment record (fill per rehearsal)

| Field | Value |
| --- | --- |
| Revision / artifact | |
| Host OS / Docker versions | |
| Topology | single lab client / optional Pi-hole hop |
| Mode / transport | Forward + native (default for this trial) |
| Test date / method | |
| UDP permitted result | |
| TCP permitted result | |
| REFUSED when denied | |
| Synthetic investigation useful? | |
| Limitations / consent | |

Untested real-host steps must be marked untested. Do not claim a 1 GB / 1 vCPU
soak unless that environment was measured.

## Bounded smoke vs long soak

- **Bounded smoke (CI-safe):** `make operator-smoke` exercises claims, support
  export and schema-generation unit tests only.
- **Long soak (explicit, not CI):** run the trial path for ≥24h on the intended
  host class, record CPU/RSS/disk, attempted/completed/failed queries and any
  feed-refresh/recovery exercises in
  [compatibility-evidence.json](compatibility-evidence.json). Do not claim the
  soak ran unless an ledger entry exists with provenance.
