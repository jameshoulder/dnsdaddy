# Public update — v0.2.0-alpha.1

Draft posts for the alpha release. **Nothing here has been posted.** Read them
as a starting point, and change anything that does not sound like you.

Rules applied to all three: no "production ready", no "enterprise ready", no
"Cisco replacement", no claim of an audit, and no implication that green CI
means the software is secure.

---

## 1 · GitHub release

> **DNS Daddy v0.2.0-alpha.1 — maturation release**
>
> This release is less about features and more about making DNS Daddy
> dependable and understandable.
>
> The headline is unglamorous. **The documented Docker install refused every
> client on a LAN, and reported itself healthy while doing it.** `.env.example`
> shipped an active client ACL under a heading that read "REQUIRED on a public
> VPS" — which a LAN operator reasonably skips — and the documented first step
> copies that file into place. Every private address was excluded, so every
> real query was answered `REFUSED` while the dashboard, the health endpoint
> and the container health check all stayed green.
>
> The underlying problem was worse than the bug: the resolver had no way to
> tell an operator it was running but not serving anyone. It counted exactly
> the failure, on exactly the failing path, and read that counter nowhere.
>
> **What is new**
>
> - `dnsdaddy doctor` — reads your configuration, reads the database, and sends
>   real DNS queries at your own listeners and through each upstream. It tells
>   `REFUSED` (running, declining this address) apart from silence, names the
>   process holding port 53, and exits non-zero so it can gate a deployment.
> - `GET /api/v1/diagnostics`, and configuration problems shown on the
>   dashboard above everything else.
> - `DNSDADDY_DASHBOARD_BIND`, so a LAN dashboard no longer means choosing
>   between an SSH tunnel and publishing an admin API on every interface.
> - A guided Docker installer, and onboarding that says when nothing has used
>   the resolver yet.
>
> **Also fixed:** link-local IPv6 clients were refused and misattributed;
> upstream checks proved a socket opened rather than that DNS was answered;
> stale threat intelligence could be reported as fresh; and `doctor` itself was
> applying migrations to the database it claimed not to touch — caught in
> review, not by me.
>
> **What this release is not.** There has still been no independent
> professional security review. The deployment matrix — Docker, native, five VM
> networking arrangements, a public VPS — is written down and every row is
> marked *not run*. The behavioural detectors have no measured real-world
> false-positive rate.
>
> If you run it somewhere real and it breaks, that is the most useful thing
> that could happen to this project right now.
>
> Full notes: `docs/releases/v0.2.0-alpha.1.md`
> What is checked and what none of it proves: `docs/assurance.md`

---

## 2 · LinkedIn

> I spent the last development cycle on DNS Daddy doing less feature work and
> more boring engineering. It was easily the most useful thing I have done on
> the project.
>
> DNS Daddy is a self-hosted protective DNS resolver — it blocks malicious
> domains, records what happened in plain English, and keeps the telemetry on
> your own hardware. This release is an alpha.
>
> The finding that shaped it: I tried to deploy it in a Linux VM, added my
> network in the dashboard, and clients still could not use it. I could not
> tell why. That turned out not to be my mistake — the documented install
> shipped a configuration that excluded every private address, so every client
> on the LAN was refused while every health surface I had reported green.
>
> Two lessons I would not have got from writing another feature.
>
> **The install is part of the product.** The bug was not in the resolver. It
> was in a file the documentation tells you to copy, under a heading that told
> LAN users it did not apply to them. There are now tests that pin the shipped
> Docker configuration to the binary's own defaults, so the two cannot drift
> apart again.
>
> **"Running" is not "working", and software should be able to tell you which.**
> The resolver was already counting the exact failure on the exact failing code
> path — and displaying that number nowhere. So the bulk of this release is
> `dnsdaddy doctor`: a command that reads your configuration, sends real
> queries at your own listeners, and explains in plain English why DNS is not
> working. It distinguishes "refused because you are not on the allow list"
> from "nothing is listening" from "systemd-resolved already owns port 53" —
> distinctions an operator otherwise spends an evening on.
>
> An automated reviewer then found three real problems in that work, including
> that my diagnostic command was quietly applying database migrations to the
> deployment it claimed not to touch. Fixed, with tests that fail without the
> fix.
>
> What I am not claiming: it has had no independent security review, the
> deployment matrix across VM platforms has not been executed, and the
> behavioural detectors have no measured false-positive rate on real traffic.
> Those are written down in the repository rather than left for someone to
> discover.
>
> It is AI-assisted, and I treat that as implementation support rather than as
> review. The evidence is in the repo: tests, a threat model, an audit
> document, and a page on what the automated checks do *not* prove.
>
> If you run a homelab, a small network, or review Go for a living, I would
> value you trying to break it.
>
> Apache-2.0, no account, no cloud tenant, no paid tier.

---

## 3 · Reddit — r/homelab, r/selfhosted, r/netsec

Low-hype, specific, and asking for something. Adjust per subreddit; r/netsec
wants the security angle and no product pitch at all.

> **DNS Daddy alpha — self-hosted protective DNS. I found a bug in my own
> install docs and spent the release fixing what let it hide.**
>
> DNS Daddy is a single Go binary: protective DNS with per-network policies,
> plain-English query logs, threat feeds you can inspect, and some
> alert-only behavioural detection. Self-hosted, no account, Apache-2.0.
>
> **It is not a Pi-hole replacement.** Pi-hole is better at ads and trackers
> and I am not trying to compete with it. If you want both, put DNS Daddy in
> front with Pi-hole as its upstream — DNS Daddy keeps per-client identity,
> Pi-hole keeps blocking ads. The reverse order collapses every device onto one
> source address and costs most of what DNS Daddy is for. That is written up
> with the reasoning in `docs/pi-hole.md`.
>
> **What actually happened this cycle.** I deployed it in a VM, added my
> network, and clients could not resolve. The `.env.example` the docs tell you
> to copy had an active client ACL under a "REQUIRED on a public VPS" heading,
> and it excluded every RFC 1918 address. Every LAN client got `REFUSED`, and
> the dashboard, `/api/v1/health` and the Docker health check all said fine.
>
> So the release is mostly diagnostics:
>
> - `dnsdaddy doctor` — sends real DNS queries at your own listeners and each
>   upstream, and says which of "nothing is listening", "systemd-resolved has
>   port 53", "you are not in the allow list" and "the upstream is dead" is
>   happening. Exits non-zero, so you can put it in a script.
> - The dashboard now shows configuration problems above everything else.
> - `DNSDADDY_DASHBOARD_BIND=<your-lan-ip>` so you can actually open the
>   dashboard on your LAN without publishing an admin API on every interface.
>
> Also fixed: link-local IPv6 clients were being refused by an ACL that
> explicitly listed `fe80::/10` (zoned addresses never match a `netip.Prefix`),
> and upstream health checks were doing a UDP "connect", which succeeds without
> sending a packet.
>
> **What I want.** People running it on real networks. The deployment matrix in
> the repo lists Ubuntu, Debian, Proxmox, Hyper-V, VMware, VirtualBox and a
> cloud VPS, and every single row is currently marked *not run*. A row that
> fails is more useful to me than a row that passes — and if you have to invent
> a step to get through it, that step is missing from my docs.
>
> **Caveats, up front:** alpha, no independent security review, detectors have
> no measured false-positive rate on real traffic, and it is AI-assisted. I
> disclose that and back the claims with tests and an audit doc rather than
> asking you to take it on trust. Green CI is not a security argument and I do
> not present it as one.
>
> Happy to answer anything, including hostile questions about the AI part.
