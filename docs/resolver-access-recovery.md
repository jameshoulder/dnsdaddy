# A query counter is not a working DNS answer

## Recover an intended client from Overview

The **Client access** section now reports the source address DNS Daddy actually
received, its current permission and what happened after a retry. When a known
client is refused, choose **Review access**, confirm the exact address, then
**Allow this address**. Retry a lookup from the device. The status distinguishes
**Permitted — waiting for retry**, **Answer produced after refusal**, **Policy
block after admission**, and **Resolution error after admission**.

Do not approve an address merely because it appears. UDP source addresses can
be spoofed; routers, NAT and Docker gateways can collapse several clients into
one address. A /32 is one source address, not necessarily one device. Tokenised
DoH authenticates separately and does not need a public source-IP permission.
The review never automatically permits a gateway or all internet clients.

The grant uses the existing authenticated, audited Networks API and its live
reload. It preserves the policy currently matched for the source, and grants
only the observed IPv4 /32 or IPv6 /128. An existing enabled single-address
network with the same policy can be permitted; a broader network is not opened
as a shortcut. Fresh evidence is read before sending a grant. Uncertain network
writes are not automatically retried because they may already have committed.
Concurrent administrator edits still require review; this is not a cross-request
transaction or an authenticated device-enrolment protocol.

## Why counters moved while charts stayed empty

The client ACL rejects a request before upstream resolution, policy processing,
query logging and behavioural learning. Anonymous received/refused counters
still increment. That is different from an allowed client getting SERVFAIL, a
DNSSEC validation failure, or a domain blocked by local policy. EDNS-capable
clients now also receive a Prohibited extended error explaining source admission.

An older onboarding warning used the cumulative refusal counter. The dashboard
now shows recent activity and per-source recovery instead. Lifetime counters
remain intact as history; they are not reset to manufacture a healthy display.
A public resolver can legitimately serve permitted clients while refusing other
traffic. A rejected internet scan is not proof that an enrolled device failed.

## Privacy and denial-of-service bounds

Refusal diagnostics are memory-only, capped at 64 source records and eligible
for five minutes after the latest refusal. Successful queries do not extend the
retention. Expired entries are omitted and erased on the next read or observation;
this is not a promise of periodic secure memory wiping. Only a refusal creates a
source record. Domains, query contents, tokens and reverse lookups are excluded.

Query logging, client-address logging and the matched policy's query privacy
must allow collection. Current per-policy privacy is also checked before API
disclosure. Turning logging off is not bypassed to populate charts. Anonymous
traffic counts continue independently. Missing detailed history may therefore be
an intentional privacy setting rather than a broken database.

The collector does not wait on its reporting mutex: contended observations are
dropped and counted. Capacity replacements are counted too. It does no disk or
network I/O. These sampled diagnostics are not exact historical analytics.

## Feed-independent core and encryption boundaries

Resolving an admitted query, applying custom local domain policy and reporting
its outcome do not require a downloaded blocklist or an external intelligence
API. Feedless tests cover the full refusal -> approval -> answer -> history path.
Threat feeds add known-domain reputation; without reputation data or validated
behavioural evidence, the software must not claim to recognise all malicious
names. A valid DNSSEC signature establishes authenticity, not harmlessness.

Daddybound is this project's resolution/validation engine, not a new encryption
protocol. DoH uses HTTPS; DoT uses TLS; DoQ uses QUIC. Selecting a DNS server IP
in ordinary port-53 settings does not configure an encrypted client. TLS needs
server identity/certificate validation and a client configured for that transport.
Native iteration to authoritative DNS and encrypted forwarding are different
outbound modes. This repair does not change a saved mode or add plaintext fallback.

The added TLS test runs the actual DoH handler through a TLS 1.3 test server
with certificate verification and token authentication; it does not provision a
public certificate or change the shipped reverse-proxy TLS policy. Incoming
encrypted defaults, certificate lifecycle and independent recursive transport
remain separate deployment work. It would be misleading to claim this patch
provides universal end-to-end encryption or eliminates all DNS infrastructure
and cryptographic-library dependencies.

Primary protocol references: [DoH, RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)
and [DNSSEC services, RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html).

## Regression evidence and upgrade safety

- `internal/dnsserver/access_integration_test.go`: real seeded store/handler,
  local upstream, empty feed index, positive answers and qname-backed history,
  narrow permission, local policy and cache-safe revocation; verified TLS DoH.
- `internal/api/access_activity_test.go`: authenticated disclosure, live grant
  state versus policy block, and policy-privacy changes.
- `internal/web/access.browser.test.cjs`: actual UDP/TCP sockets from an initially
  rejected source, browser confirmation, the actual Networks API, real answers
  and query history without feeds; another source remains refused.
- Bounded collector race tests, browser-logic tests and served OpenAPI assertions.

The SQL column is `query_log.qname`; the Go/API field is `Domain` / `domain`.
The initial privacy assertion incorrectly queried `domain`. It was corrected,
not removed, and positive allowed/blocked rows are checked alongside absent
refused rows. No database migration or data deletion is required for that test fix.

The image build now updates inherited Alpine packages within its existing release
before adding tools. This addresses outdated system libraries reported by the
container scan, without adding ignore rules. Fresh builds and scan results remain
necessary; a cached image does not update itself. Staticcheck warnings about the
existing encrypted HTTP/2 implementation require a separately verified migration,
not disabling TLS verification or silencing the security gate.

No install automatically grants the operator's unknown live source. No production
server was probed or changed by these repository tests. Review the complete CI and
security results before merging or deploying; a passing unit test is not a live
VPS connectivity test or an independent security audit.
