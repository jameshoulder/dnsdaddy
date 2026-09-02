# DNS Daddy documentation

Two things live here: how to run DNS Daddy, and how DNS security works. They
are mixed together on purpose — a control you do not understand is a control
you cannot judge, and most of what makes protective DNS useful (or useless) is
in the concepts rather than the configuration.

**Start with [capabilities.md](capabilities.md)** if you want to know what this
software actually does before reading anything else. It is the single source of
truth for what is implemented, what is experimental, and what is only an
intention, and everything else here is expected to agree with it.

---

## Running it

| | |
|---|---|
| [deploy.md](deploy.md) | Nanode walkthrough, TLS, firewalling, backups, upgrades, uninstall |
| [deployment-matrix.md](deployment-matrix.md) | Acceptance checklist for clean machines, VMs and VPSes — and what has actually been run |
| [integrations.md](integrations.md) | pfSense, OPNsense, UniFi, FortiGate, Windows, roaming clients, stopping DoH bypass |
| [pi-hole.md](pi-hole.md) | Running alongside Pi-hole: which order, and what each one costs |
| [threat-intel.md](threat-intel.md) | Every default feed, where it comes from, and handling a false positive |
| [privacy.md](privacy.md) | What is stored, for how long, and how to store less |
| [architecture.md](architecture.md) | How a query flows through the system, and why it is built this way |
| [siem.md](siem.md) | Getting findings into Wazuh, Elastic, Splunk or Sentinel |

## Security

| | |
|---|---|
| [capabilities.md](capabilities.md) | **Available / experimental / planned.** Read this first. |
| [assurance.md](assurance.md) | What is checked, by what, and what none of it proves |
| [threat-model.md](threat-model.md) | Assets, boundaries, actors, threats, mitigations, and residual risk |
| [audit-2026-08.md](audit-2026-08.md) | August 2026 maturation audit: findings, fixes, and where a reviewer should start |
| [roadmap.md](roadmap.md) | What might come next, and what would have to be true first |
| [../SECURITY.md](../SECURITY.md) | Reporting a vulnerability |
| [security/](security/) | Point-in-time security review records |

## Detection engineering

| | |
|---|---|
| [detection/README.md](detection/README.md) | The pipeline, design principles, finding schema, and every detector |
| [detection/dns-tunnelling.md](detection/dns-tunnelling.md) | The tunnelling detector in depth |
| [detection/mitre.md](detection/mitre.md) | ATT&CK mapping policy, every mapping, and the ones deliberately left off |
| [threat-hunting/README.md](threat-hunting/README.md) | Six hunts you can run against telemetry this produces |
| [external-apis.md](external-apis.md) | Bring your own intelligence: external reputation and enrichment APIs, and exactly what enabling them changes about your threat model |

## DNS security concepts

| | |
|---|---|
| [dns-security/README.md](dns-security/README.md) | Why DNS is a security control point, and what protective DNS is |
| [dns-security/dnssec.md](dns-security/dnssec.md) | Authenticity and integrity — and what DNS Daddy can honestly tell you |
| [dns-security/encrypted-dns.md](dns-security/encrypted-dns.md) | DoH, DoT, and clients that route around you |

## Hands on

| | |
|---|---|
| [../labs/README.md](../labs/README.md) | An offline lab with seven scenarios, two of which are supposed to find nothing |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Development setup and house style |

---

## A note on how this is written

DNS Daddy is an unaudited, AI-assisted personal project, and the documentation
tries to be useful rather than reassuring. Where something does not work, the
page says so. Where a control has a residual risk, the page states it rather
than stopping at the mitigation. Where a detector will miss something, that is
in the detector's own documentation and not only in the caveats.

That is partly ethics and partly self-interest: the value of a project like
this is peer review, and nobody reviews something that has already told them
everything is fine.

If you find a claim here that the code does not support, that is a bug worth
[reporting](https://github.com/jameshoulder/dnsdaddy/issues).
