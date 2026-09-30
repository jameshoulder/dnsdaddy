# ADR 0004: encrypted record acquisition with local Daddybound validation

**Status:** implemented, experimental. Extends [ADR 0003](0003-daddybound-native-live.md).

## Decision

Transport and local validation are independent settings. Native remains the
default transport. An explicit encrypted profile acquires records from
operator-approved DoQ, DoH/HTTP3 and DoH/HTTP2 recursive endpoints. Live binds
the same local validator to the exact records returned from that acquisition
path. Learn uses a separate sampled lookup; Off performs no local validation.

Authoritative servers do not universally offer an authenticated encrypted
service that an iterative resolver can simply select on port 443. Changing a
destination port is insufficient. Opportunistic authoritative encryption also
has different authentication and failure semantics. This decision implements
strict encrypted forwarding, with a disclosed recursive provider as a trust
and privacy relationship, rather than making a universal encryption claim
about native iteration.

Every endpoint needs a configured identity, strict TLS 1.3 authentication and
literal bootstrap targets. Protocol and endpoint failover are explicit and
ordered. No environment proxy, redirect, implicit provider, plaintext retry,
HTTP/1.1 downgrade or zero-RTT query is permitted. Trusted roots remain an OS
deployment responsibility. User-provided API credentials are a separate
feature, not part of DNS transport.

## Preserved local trust

An upstream AD flag cannot confer Daddybound trust. Live fetches needed
DNSSEC material, pins the client projection and validates those exact RRsets
against current local anchors. The existing conservative proof policy,
alias/negative-answer handling, CD semantics and resource limits remain.
Private-zone validation policy is not generalized by this change.

The statistical learner cannot modify transport approval, certificate
verification, DNSSEC proofs or root trust. Historical observations distinguish
`native`, `native_live`, `encrypted_forwarded` and `encrypted_live`; older
`forwarded` observations retain their legacy provenance. Live query sources
are `native` or `encrypted_forwarded`, while Off/Learn client answers retain
`upstream`. Blank legacy query sources mean unknown. Each record keeps the
source captured for its operation, even during a profile change.

## Lifecycle and privacy boundary

Settings are validated and persisted before publication. Immutable route
generations isolate cache and in-flight work. Old native, forwarder and
background DNS paths are cancelled and drained before successful activation
returns. When local validation is active, the RFC 5011 manager is retained
while refresh ownership is handed over, preserving hold-down state and
preventing parallel refresh writers. With no explicit configuration pin,
invalid saved state is an error, never permission to select native; valid
explicit configuration can override the stored selection for recovery.

The process hostname resolver follows the selected encrypted bundle so feed,
provider and webhook hostname resolution cannot reintroduce ordinary OS DNS
under this profile. Those background hostname results have authenticated
transport but do not pass through the client Live validator. HTTPS endpoint
verification and existing destination controls retain their separate roles.
Other processes and the provider's onward authoritative traffic are outside
the boundary.

## Consequences and evidence

Operators gain modern encrypted transports while retaining local DNSSEC
validation. They must choose a provider, disclose names to that provider,
maintain bootstrap addresses and accept failure when approved encrypted
routes are unavailable. Strict negotiation can reject services accepted by
more permissive clients. Read-only UI/status does not probe; an explicit
bounded test discloses only its fixed question.

The homepage also exposes authenticated local server-address evidence for
client setup. Restricted interface enumeration can fall back to the accepted
management socket's local address without trusting request headers or
contacting an IP-discovery service. The UI distinguishes this from a
reachable LAN/NAT endpoint.

Deterministic TLS/QUIC, DNSSEC, lifecycle, diagnostics and browser fixtures
cover defined failure boundaries. They do not establish production readiness,
field interoperability or target-device throughput. See the
[operator guide](../encrypted-dns.md), [capabilities](../capabilities.md) and
[validation limitations](../daddybound/validation-lab.md).
