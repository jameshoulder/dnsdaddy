# DNS Daddy trust and assurance

DNS Daddy is an AI-assisted, open-source DNS security project. It is experimental
and has not had an independent professional security audit. This page is an
evidence index, not a certification, legal opinion or promise of production safety.

| Question | Evidence and limits |
|---|---|
| What can it actually do? | [Capabilities](docs/capabilities.md), with available, experimental and planned features separated. |
| What data does it process and send? | [Privacy and outbound traffic](docs/privacy.md) and the [data inventory](docs/trust/data-inventory.json). |
| What security checks exist? | [Engineering assurance](docs/assurance.md), the exact commit's CI results and retained scan artifacts. A configured workflow is not a passed check. |
| What vulnerabilities are published? | [Public register](docs/trust/vulnerabilities.json) and [triage process](docs/trust/vulnerability-management.md). The initial inventory is **not assessed**, not "zero vulnerabilities". |
| What remains unresolved? | [Risk register](docs/trust/risks.json) and [prioritised compliance roadmap](docs/trust/compliance-roadmap.md). |
| How was AI used? | [AI assistance and human accountability](AI_ASSISTANCE.md). No automated tool can sign a human review. |
| What do ATT&CK labels establish? | [Mapping policy](docs/detection/mitre.md): investigation hypotheses, not confirmed compromise or certified coverage. |
| Where should a vulnerability be reported? | [Security policy](SECURITY.md). Do not disclose an unpatched vulnerability in a public issue. |

## The boundary between software and compliance

The project supplies controls and evidence that may help an operator meet its
obligations. Installing it does not make an organisation GDPR compliant, ISO 27001
certified or the subject of a SOC 2 report. Applicable jurisdictions, controller /
processor roles, people, contracts, configuration and actual operation all matter.
No certification or independent assurance report is claimed by this repository.

A self-hosted installation's DNS logs are not automatically sent to the maintainer.
That is not the same as "nothing leaves the host": DNS upstreams receive questions;
enabled feeds receive download requests; deliberately enabled providers and webhook
receivers receive their configured data. See the privacy guide for each path.

## Current resolution disclosure

Fresh installations start in **Forward**, internally `off`, with Cloudflare DoH
forwarders. Forward, Learn and Live are distinct from the native/encrypted transport
selection. Native Live uses plaintext authoritative DNS; encrypted forwarding
protects the configured transport leg, not secrecy from the chosen provider.
Daddybound Live's local DNSSEC validation exists but remains experimental.
Existing saved choices and explicit configuration pins are preserved.

## How to evaluate a particular version

Record the tag and full commit, effective configuration, deployment model, test
commands/results, unresolved findings and reviewer scope. The
[review record](docs/trust/review-template.md) is intentionally unsigned. A passing
scanner, an AI review, a GitHub "Verified" commit and a human security assessment
are different kinds of evidence and must not be substituted for each other.

This baseline was prepared against `e397bb503ce8e93cdb419c3e432269a61c7bc181` on
1 October 2026. It is not a continuous assessment of every subsequent release.
