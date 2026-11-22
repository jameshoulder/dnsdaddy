# Maturity programme

This directory records how DNS Daddy intends to mature for human validation.
It is a programme of evidence, not a claim that the product is certified,
audited or production-ready for regulated environments.

**Authoritative inventory:** [capabilities.md](../capabilities.md)  
**Compliance crosswalk:** [trust/compliance-roadmap.md](../trust/compliance-roadmap.md)  
**Product roadmap:** [roadmap.md](../roadmap.md)  
**P0 milestone:** [Verified Trust](verified-trust.md) — prove the resolver with a regenerable conformance package

Nothing here turns a planned control into a present capability. Shipping a
toggle is not ISO 27001, Cyber Essentials, HIPAA or SOC 2. Those are
organisational assurance engagements with defined scopes, evidence and
independent assessors.

## Active P0: Verified Trust

Ship a reproducible demonstration that Daddybound correctly validates signed
and unsigned answers, rejects bogus DNSSEC, reports crypto/transport failures,
cannot silently downgrade encrypted upstreams, fits target hardware limits and
exposes enough evidence for an independent reviewer. Regenerate the laboratory
package with `make daddybound-report`. Details and checklist:
[verified-trust.md](verified-trust.md).

## What the maturity UX pass delivered in the product

| Area | Change | Boundary |
| --- | --- | --- |
| Daddybound transparency | Overview and Daddybound show live mode, trust-anchor, answer-path/observer and stored-evidence signals | Not a readiness score or independent review |
| Findings / Investigate | Workflow cards and evidence-lane navigation | Findings remain alert-only |
| Encrypted DNS examples | Cloudflare DoH2 + DoH3; Quad9 DoQ (Cloudflare publishes no DoQ) | Draft fill only; consent, test and apply remain explicit |
| Theme | Charcoal default with an ivory light mode toggle | Preference only; no remote assets |
| Ad-hoc access | Top-bar control for Default-network ad-hoc DNS access | Never widens the client ACL |
| Public IP approval | Structured acknowledgement dialog and clearer Setup copy | Firewall remains the operator's responsibility |

## Privacy-first posture (ethical operator defaults)

Prioritise controls that reduce what leaves the host and what is retained:

1. **Local-first telemetry** — query logs, findings and Daddybound observations stay on the operator's hardware unless they configure an export or webhook.
2. **Explicit egress consent** — encrypted forwarders, external reputation APIs and enrichment require acknowledgement before names are shared.
3. **Minimisation switches** — retention windows, client-attribution logging and learning privacy skips already exist; the next P1 item in the compliance roadmap is a live privacy view of *effective* settings.
4. **No phone-home** — no account requirement, usage telemetry or proprietary default scoring service.
5. **Subject rights engineering** — scoped export / restriction / erasure jobs remain planned work; do not claim GDPR/HIPAA readiness from retention toggles alone.

## Post-quantum stance

"Ahead of the curve" for DNS Daddy means an honest crypto inventory and a
migration plan, not a marketing claim that DNS is already post-quantum safe.

| Layer | Today | Next evidence |
| --- | --- | --- |
| TLS to encrypted forwarders | TLS 1.3 via the Go stack and OS trust store | Track Go/BoringCrypto PQ-hybrid releases; document cipher suites actually negotiated |
| DNSSEC algorithms | Classical public-key DNSSEC as deployed on the public Internet | Follow IETF DNSSEC algorithm updates; unsupported algorithms stay Indeterminate (no silent downgrade) |
| Stored credentials / backups | Authenticated encrypted archives with operator-held keys | Document algorithms, rotation and recovery; prefer libraries over bespoke crypto |
| Roaming agents (future) | Not shipped | Require PQ-aware TLS profiles and pinned trust before any agent GA |

Do not label ordinary AES/TLS use as "FIPS validated" or "post-quantum
complete". Measure what the binary negotiates; publish that measurement.

## Web3 / decentralised naming

Daddybound's own roadmap keeps ENS, Ethereum naming and CCIP Read **out of
scope** for foreseeable milestones. That boundary stands.

If decentralised naming is revisited later, it must be:

- **opt-in**, never a default dependency for resolution;
- validated with the same honesty rules as DNSSEC (no silent insecure fallback);
- privacy-reviewed for any chain RPC egress;
- incapable of becoming a required network path for basic protective DNS.

Shipping Web3 "by default" would contradict the self-hosted, inspectable,
offline-capable product position.

## Roaming client agents

[roadmap.md](../roadmap.md) already treats a signed Windows/macOS stub as a
separate later project. Network DoH tokens remain the roaming primitive today.

Agent development should begin as a **design + threat-model track**, not a
hurried binary:

1. Threat model: stolen agent, malicious update, DoH token extraction, captive
   portal, split DNS, clock skew, local privilege escalation.
2. Trust: signed updates, reproducible builds, pinned server identity, short-lived
   client credentials, remote revocation.
3. Transport: DoH (and later DoQ where appropriate) with TLS 1.3, no plaintext
   fallback, certificate validation only.
4. Privacy: local query minimisation, operator-controlled retention, no
   unexpected cloud tenancy.
5. Platform packaging: separate code signing and notarisation per OS; no shared
   admin password embedded in the agent.
6. Evidence gate: independent review of the agent trust path before calling it
   generally available.

## Standards expected by ISO 27001, Cyber Essentials / Plus, HIPAA, SOC 2

Use [trust/compliance-roadmap.md](../trust/compliance-roadmap.md) as the
engineering crosswalk. Summary for human validators:

| Framework | What code can contribute | What only an organisation can finish |
| --- | --- | --- |
| ISO/IEC 27001 | Access control, secure development, recovery, vulnerability records | ISMS scope, SoA, internal audit, certification |
| Cyber Essentials / Plus | Hardening guidance, patch evidence, access boundaries | Organisational assessment against NCSC requirements |
| SOC 2 | Logging, change history, availability and confidentiality evidence | CPA attestation over a defined system |
| HIPAA | Encryption in transit/at rest options, access logs, retention | Covered-entity/BA agreements, workforce processes, required safeguards assessment |
| GDPR / UK GDPR | Minimisation, retention, export/erasure design | Lawful basis, DPIA, controller/processor roles |

**Readiness for human validation** means: claims match the binary, experimental
features stay labelled, release evidence is reproducible, restoration is tested,
and the highest-risk paths have been reviewed by a competent human. It does not
mean badges on the README.

## Operator validation cohort (current pass)

Prepare a first cohort of **five independent testers** (recruitment target, not
existing usage). Structured claims, trial path, support export, upgrade
rehearsal and an empty evidence ledger live here:

| Document | Role |
| --- | --- |
| [../product-claims.json](../product-claims.json) | Reviewed structured claims source |
| [../product-claims-table.md](../product-claims-table.md) | Generated table (`dnsdaddy claims export`) |
| [../website/product-claims.json](../website/product-claims.json) | Static site import at build time |
| [operator-trial.md](operator-trial.md) | One reproducible Docker + single-client trial |
| [support-export.md](support-export.md) | `dnsdaddy support` allowlisted local package |
| [upgrade-recovery-rehearsal.md](upgrade-recovery-rehearsal.md) | Client rollback vs upgrade vs offline restore |
| [compatibility-evidence.json](compatibility-evidence.json) | Empty ledger until real evidence arrives |
| [evidence-gated-backlog.md](evidence-gated-backlog.md) | Follow-ons that wait for cohort evidence |
| [verified-trust.md](verified-trust.md) | P0 Daddybound laboratory package |

## Suggested validation sequence

1. Freeze a revision and run the checks that already exist today (`go test ./...`,
   dashboard tests, CI workflows, `dnsdaddy doctor`, `make claims-check`). The
   roadmap's Phase 2 release-assurance *bundle* is still planned work — create
   those artefacts as they are defined; do not treat the proposal as a runnable
   checklist yet.
2. Walk [operator-trial.md](operator-trial.md) on a lab client; record results in
   the compatibility ledger only when real.
3. Exercise Forward / Learn / Live and encrypted transports on constrained hardware.
4. Walk Findings → Investigate → policy change on labelled lab traffic.
5. Verify backup/restore and management-journal behaviour
   ([upgrade-recovery-rehearsal.md](upgrade-recovery-rehearsal.md)).
6. Commission an independent review of authentication, ACL, feed ingestion and
   the DNS answer path.
7. Only then discuss organisational certification scopes.

## Non-goals for this programme

- Claiming certification from documentation alone
- Heuristic blocking before published false-positive rates
- Mandatory SSO, multi-tenancy or hosted accounts
- Default Web3 resolution
- Clustering via shared live SQLite
