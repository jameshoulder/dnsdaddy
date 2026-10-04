# Roadmap

[Capabilities](capabilities.md) is the authoritative inventory of available,
experimental and planned functionality. This roadmap separates the implemented
baseline from future work; it does not turn a proposal into a capability.

**No dates or delivery promises.** This is a single-maintainer, free,
self-hosted Apache-2.0 project. Each pass should remain reviewable, with tests
before changes to the DNS answer path. A clean scanner result is not a review.

## Implemented baseline — do not rebuild these

These items were incorrectly listed as future work in the old roadmap. The
roadmap was stale; the features already existed in the code and capabilities map.

| Status | Existing capability | Scope and evidence |
|---|---|---|
| Available | Per-client query rate limiting | Bounded attributed-client buckets, limiting and overflow counters; see [capabilities](capabilities.md). This is resource protection, not heuristic threat blocking. |
| Available | DNS rebinding protection | Forwarded/native answer checks with explicit internal and split-DNS exceptions; see [capabilities](capabilities.md). |
| Available | Optional signed HTTPS webhooks | User-owned receiver/signing secret, persistent bounded outbox and retries; see [webhooks](webhooks.md). |
| Available | Encrypted backup and offline restore | Consistent snapshot, key/configuration material, verified restore into a new directory; see [recovery](recovery.md). |
| Available | Finding review and domain/client investigation | Versioned review beside original findings, recorded history and read-only current-policy preview; see [capabilities](capabilities.md). |
| Available | Optional external API providers | Deliberate configuration/consent, encrypted credentials and SSRF controls; see [external APIs](external-apis.md). No provider is required for basic resolution. |
| Available | Optional encrypted outbound profile | Approved DoQ, HTTP/3 DoH and HTTP/2 DoH with TLS 1.3 and no plaintext fallback; see [encrypted DNS](encrypted-dns.md). These are outbound transports, not new inbound listeners. |
| Available | OpenAPI, Prometheus and NDJSON exports | Existing management/measurement surfaces and bounded paginated exports; see [exports](exports.md). |
| Experimental | Daddybound Live local DNSSEC enforcement | Implemented with native recursion or approved encrypted forwarding. Production reliability is not established; see [Daddybound](daddybound/README.md). |
| Experimental, alert-only | Behavioural detectors and local learned baselines | Implemented measurements and fitted local state; no published real-traffic false-positive rate and no heuristic blocking. See [detection](detection/README.md) and [learning](learning.md). |

Fresh installations without an explicit resolver-mode override start in Forward (off); upgrades preserve saved mode choices, and explicit configuration takes precedence.

## Phase 1 decision — claims match the binary

`SECURITY.md` previously claimed fresh installations selected Live and used DoT
forwarders. The binary instead records Forward (`off`) for a fresh database and
ships Cloudflare HTTPS forwarding URLs. This pass corrects the documentation,
not the resolver default or an operator's stored settings.

**Safe Search is not enforced.** Keep `safeSearch` stored and round-tripping
for v1 compatibility, explicitly deprecated in both OpenAPI schemas and never
presented as an actionable dashboard control. The UI/API already omitted the
toggle and documented the no-op; this pass strengthens the read-only notice and
regression tests. `true` does not restrict results for any search engine.

CNAME-based Safe Search enforcement is **not implemented** by this pass. A future
proposal would need documented provider hostnames, unsupported-engine behaviour,
DNSSEC/cache/alias semantics, answer-path tests and separate review. Do not make
a stored boolean look like enforcement while that work is absent.

## Planned — subsequent scoped passes

The following are planned work, not current capabilities. Stop after each phase,
report what changed and what remains experimental, and update the capability map
only when implementation and tests justify changing an item's status.

### Phase 2 — release assurance artefacts

Plan a release checklist with revision/toolchain records, scanner outputs, SPDX
SBOM, container digest and a documented signing/verification step. Existing CI,
CycloneDX generation and release checksums are inputs, not proof that the proposed
release bundle already exists. Separate tested, scanned and independently reviewed
evidence; never add an audit badge on the strength of automation. Extend bounded
fuzz coverage for DNS wire messages, DoH bodies, feed lines and backup archives.

### Phase 3 — feed supply chain and management history

Extend feed refresh evidence with source URL, checksum, parser rejects and
last-success age, preserving the last good snapshot when verification fails.
Existing cached-feed fallback is not a claim of signed publisher provenance.

Extend the existing durable intent/outcome management journal with a hash chain
and redacted values. Specify what tampering can be detected and which trusted
checkpoint is needed; do not describe a local hash chain as protection against
a compromised host. Preserve refusal of a management write when its initial
journal entry cannot be saved.

### Phase 4 — investigation depth

Plan a registered-domain first-seen index independent of query-log retention,
one row per domain, explicitly local observation rather than threat intelligence.
Extend existing decision records rather than replace them, including versioned
allowed/blocked evidence, selected policy, category, feed and block mode.

Plan minimal, confidence-labelled device identity from observed source addresses,
configured networks and operator names, with optional deliberately configured
lease-file/reverse-DNS input. Unknown must remain a valid result. No active
network discovery, MAC-OUI inference, ARP/NDP sweeps or new raw-socket privileges.

Plan opt-in, bounded answer telemetry for record type, address, TTL and a hash.
Full TXT contents would require a separate explicit setting and documented privacy
trade-off. Do not silently collect more browsing data to populate a dashboard.

### Phase 5 — deployment and authentication guidance

Document Daddybound graduation evidence without promoting Live: comparison with
a known-good validator, investigation of disagreements/local-bogus cases, and
latency/resource measurements on the 1 vCPU target. Per-network validation modes
are proposed work, not a present control.

Document browser/firewall DoH-bypass controls and a clients-seen-resolving export
for inventory comparison. Do not build a flow collector or infer identity merely
from the absence of DNS queries. Existing network DoH tokens are the roaming
primitive; a signed Windows/macOS stub is a separate later project.

Design a read-only export token scope and optional TOTP unless each is demonstrably
a small additive change compatible with current authentication. Preserve bcrypt
and login rate limiting. No mandatory SSO or enterprise tenancy model.

## Planned — coherent stateful DNS lifecycle

The resolver already has cached answers, in-flight work and reusable encrypted
connections. Do not rebuild those merely to call the product stateful.

A subsequent scoped implementation should connect admission, policy revision,
cache/resolution, validation, response production and transport-write outcomes.
Separate client identity, connection state and DNS transaction state. Bound both
waiting and active work; define cancellation, cleanup, revocation and overload.
A produced answer is not proof of remote receipt. Diagnostic sampling must not
become the authority for a security decision. This lifecycle is **planned**, not
implemented by the Phase 1 claims pass.

## Evidence before promotion

The most valuable missing input is measured behaviour on real traffic, with
labelled ground truth, denominators, false alerts, misses and drift reported.
Synthetic tests establish internal behaviour, not a production false-positive
rate. Independent adversarial review and constrained-hardware measurements are
separate requirements, not scanner results under another name.

**Behavioural detectors remain alert-only.** A published real-traffic false-positive
rate is a hard precondition for even considering enforcement and does not exist
yet. This roadmap is not permission to add blocking from a heuristic. Stronger
DGA models and general threat classifiers also remain research proposals; the
existing local baseline is not a calibrated maliciousness probability.

## Scope that stays small

Run **two independent resolvers and give clients both addresses** for the documented
availability approach. Maintain their policies deliberately; do not share a live
SQLite file or promise clustering, replicated detection state or seamless failover.
Multi-tenancy and mandatory SSO are outside this pass.

No hosted service, paid tier, supporter-only feature, account requirement, licence
check, usage telemetry or phone-home. Default feeds remain public and inspectable
in [the catalogue](../internal/catalog/catalog.go). No proprietary default threat
feed or required black-box scoring service. Optional operator-configured external
integrations retain their existing explicit-consent and disclosure boundaries.

## Contributing evidence

Reproducible failures, well-described benign detector alerts and independent code
review are more useful than another unmeasured feature. Use
[SECURITY.md](../SECURITY.md) for sensitive reports and
[CONTRIBUTING.md](../CONTRIBUTING.md) for development guidance.
