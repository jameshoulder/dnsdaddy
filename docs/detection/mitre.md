# MITRE ATT&CK mapping

ATT&CK is a knowledge base of adversary behaviour, not a certification scheme.
A mapping states which investigation hypothesis is relevant to a finding. It does
not establish compromise, prove prevention or measure validated detection coverage.

## Current policy

Every current behavioural mapping has `hypothesis: true` and an explicit rationale.
The underlying observations may be established measurements; the interpretation
that an adversary performed a technique is not. DNS shape, timing and response codes
cannot prove a process's intent or decode a command channel. Multiple heuristics
firing can strengthen a hypothesis without confirming it.

| Finding | Relevant hypothesis | What still needs confirmation |
|---|---|---|
| `dns_tunnel_suspected` | T1071.004, Application Layer Protocol: DNS | Actual C2 channel and adversarial use; DNSBL, CDN and telemetry can share the observed shape. |
| `dns_tunnel_suspected` | T1048.003, Exfiltration Over Unencrypted Non-C2 Protocol | Outbound data, applicable unencrypted non-C2 protocol and channel role; not inferred merely from the resolver's transport setting. |
| `dns_tunnel_suspected` | T1132.001, Data Encoding: Standard Encoding | Actual encoding and malicious context; an alphabet-like label alone is not proof. Where `encoded_label_ratio` did not contribute, this is only a triage possibility. |
| `dga_like_domains` | T1568.002, Dynamic Resolution: Domain Generation Algorithms | Algorithmic generation and adversarial rendezvous intent; random-looking names and NXDOMAINs are not sufficient. |
| `nxdomain_burst` | T1568.002 | Distinguish a DGA from broken search suffixes, configuration and other failed lookups. |
| `dns_beaconing_suspected` | T1071.004 | Distinguish command polling from legitimate periodic software. |
| `txt_activity_anomaly` | T1071.004 | Inspect record and endpoint context; unusual TXT use alone does not establish attacker content. |
| `resolution_failure_burst` | None | An operational failure is not itself evidence of an adversary technique. |

Detectors remain experimental and alert-only. This mapping change does not change
thresholds, enforcement, scoring, DNS answers or the recorded measured signals.

## Historical records and integrations

Older findings may contain `hypothesis: false` for tunnelling, encoding or DGA-like
mappings. That earlier representation overstated the inference. Existing evidence
is not silently rewritten; downstream tools must account for producer version and
this correction. In particular, a historical false value is not confirmation of
an attack. New catalogue entries and produced findings are protected by
`internal/detect/mitre_assurance_test.go`.

Do not calculate a coverage percentage from attached IDs. Build a versioned
validation record with representative benign/malicious corpora, false-positive and
false-negative measurements, tuning conditions and explicit limitations. Endpoint,
network and analyst evidence may confirm a case; a label in a resolver finding does
not. A human finding review does not change this detection into an enforcing control.

T1041 is not added speculatively alongside T1048.003: channel role needs evidence.
T1090, T1573 and infrastructure acquisition/compromise techniques are not claimed
from query shape. DNS transport and spoofing mitigations belong in the threat model,
not an inflated list of detected techniques. DNS telemetry is only one data source.

Sources, consulted 1 October 2026:
[ATT&CK](https://attack.mitre.org/),
[T1071.004](https://attack.mitre.org/techniques/T1071/004/),
[T1048.003](https://attack.mitre.org/techniques/T1048/003/),
[T1132.001](https://attack.mitre.org/techniques/T1132/001/),
[T1568.002](https://attack.mitre.org/techniques/T1568/002/).
