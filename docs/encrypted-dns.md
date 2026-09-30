# Encrypted DNS transport

DNS Daddy can acquire DNS answers and supporting DNSSEC records through your
approved **DNS over QUIC (DoQ), DNS over HTTPS over HTTP/3, or DNS over HTTPS
over HTTP/2** endpoints. Daddybound can still validate the exact returned
records locally in Live mode. Transport and Off/Learn/Live are separate choices.

Native transport remains the default when no transport is saved or pinned.
Existing mode selections are preserved; a fresh installation still selects
Daddybound Live. No public resolver is silently chosen for encrypted transport.
Read [ADR 0004](decisions/0004-encrypted-forwarding.md) for the architecture and
[privacy.md](privacy.md) for the full data-flow inventory.

## What is encrypted

| Connection | Effect of selecting encrypted transport |
| --- | --- |
| Devices to DNS Daddy | Unchanged by the outbound setting. Configure the existing client-facing DoH/DoT service or a private tunnel when this connection needs encryption. |
| DNS Daddy to approved recursive resolvers | Authenticated TLS 1.3 for client answers, supporting validation queries, active trust-anchor refresh and the daemon's background hostname lookups. No plaintext DNS fallback. |
| The recursive provider to root, TLD and authoritative servers | Outside this connection's protection and DNS Daddy's control. The provider may use ordinary DNS. |

DNSSEC authenticates signed DNS data. It does not encrypt names. TLS protects
the selected connection and authenticates its configured server; it does not
make every DNS answer signed or trustworthy. The provider receives the query
names and supporting lookups, and can retain metadata under its own policy.
The native iterative implementation continues to use UDP/TCP port 53 when
native transport is selected. Changing the port number alone cannot make that
traffic encrypted.

### Supported outbound protocols

| UI protocol | Configuration value | Normal destination | Required negotiation |
| --- | --- | --- | --- |
| DoQ | `doq` | UDP 853 | QUIC with TLS 1.3 and `doq` |
| DoH · HTTP/3 | `doh3` | UDP 443 | HTTP/3 over QUIC with TLS 1.3 and `h3` |
| DoH · HTTP/2 | `doh2` | TCP 443 | HTTP/2 with verified TLS 1.3 and `h2` |

An explicitly configured nonstandard port is supported; DoQ on UDP 53 is
rejected. A DoH URL does not prove that the service supports HTTP/3. Select
only protocols that your resolver actually supports. HTTP/3 and DoQ can avoid
TCP's cross-stream head-of-line blocking, but their performance depends on the
network and server; this build makes no universal latency claim.

Add a separate HTTP/2 entry when you want an approved TCP route after a QUIC
failure. Entries are tried in their displayed order. The client does not use
HTTP redirects, HTTP/1.1, alternate services, an environment proxy or provider
discovery to reach a different service. Zero-RTT queries are disabled.

## Configure it in the dashboard

1. Open **Daddybound → DNS transport** and select **Encrypted forwarding**.
2. Add the resolver's supported protocol and address. DoQ takes a host or
   `host:port`; DoH takes its complete `https://host/path` endpoint URL.
3. Provide literal bootstrap IPs for a named endpoint. Obtain them from the
   resolver operator or your own deployment configuration. The client never
   asks ordinary DNS how to find its encrypted resolver.
4. Check the TLS identity. It normally defaults to the address's hostname.
   A named DoH URL must authenticate that same hostname. A literal-IP address
   can use the resolver's certificate hostname in **TLS server name**.
5. Add and order any approved fallback entries. Check the disclosure
   acknowledgement after completing the endpoint draft.
6. Optionally select **Test endpoints**. This sends a fixed root (`.`) DNSKEY
   question through the draft endpoints. It changes no settings or trust
   anchors. An entry that was not attempted has not been tested; ordered
   failover stops after an accepted response. This checks the exchange and
   response, not the provider's accuracy or a local DNSSEC proof.
7. Select **Apply DNS transport**. The current Off/Learn/Live choice remains
   selected. Live continues to validate locally over the new record source.

Reading status, loading the page and editing a draft never run a connectivity
test. Applying a valid profile permits ordinary resolution and, when the mode
requires it, supporting lookups and trust-anchor refresh. Opening a page in a
running Live system does not stop the system's already-scheduled work.

If every approved endpoint fails, the request fails; the client does not
silently contact a legacy forwarder or an authoritative server. Correct an
expired certificate, wrong hostname, stale bootstrap IP, unsupported protocol,
incorrect clock or blocked egress port instead of bypassing authentication.

To return to native transport, deliberately select and acknowledge it. Saved
endpoint entries can remain available for a future switch. In native Live,
answers come from direct authoritative iteration. In native Learn and Off,
client answers use the existing `dns.upstreams` configuration; native Learn
also performs independent native observations. Native background hostname
lookups use the system's configured DNS servers.

## Pin a deployment in YAML

Explicit `dns.resolution_transport` or `DNSDADDY_RESOLUTION_TRANSPORT` pins the
transport and makes the dashboard selector read-only. The environment value
overrides YAML. A nonempty `encrypted_upstreams` list in YAML requires an
explicit transport value. Omitting the transport and list lets the dashboard
manage the selection.

The following is a **template with reserved documentation names and IPs**.
Replace all endpoints and bootstrap addresses with your actual resolver's
values. These addresses are not a working public service.

```yaml
dns:
  resolution_transport: encrypted
  encrypted_upstreams:
    - protocol: doq
      address: dns.example.net:853
      server_name: dns.example.net
      bootstrap_ips: [203.0.113.53, "2001:db8::53"]
    - protocol: doh3
      address: https://dns.example.net/dns-query
      bootstrap_ips: [203.0.113.53, "2001:db8::53"]
    - protocol: doh2
      address: https://dns.example.net/dns-query
      bootstrap_ips: [203.0.113.53, "2001:db8::53"]
  local_dnssec_validation: enforce
  timeout: 4s
```

Retain the existing `dns.upstreams` configuration for native Off/Learn mode;
it is not an encrypted-profile fallback. Pinning the mode with `enforce` is
separate from pinning transport. Leave the mode unset if you want its saved
installation/dashboard choice to remain effective.

Certificates use the operating system's trusted root store. There is no
dashboard certificate-verification bypass or trust-on-first-use setting.
Private deployments must install and maintain an appropriate trust root in
the host or container through their deployment process. DoH endpoint URLs
cannot contain user credentials, query strings or fragments. Provider API
keys and arbitrary authorization headers are not supported by this DNS
transport; External APIs is a separate feature.

## Local validation and learning

| Daddybound mode with encrypted transport | Client behavior | Recorded evidence |
| --- | --- | --- |
| Live (`enforce`) | Daddybound acquires records from approved encrypted endpoints and validates the exact packet projection it returns. | `encrypted_live` observation; `encrypted_forwarded` query validation source. |
| Learn (`observe`) | The approved encrypted forwarder supplies the client answer. A bounded independent lookup is validated afterward. | `encrypted_forwarded` observation; the client query retains `upstream` validation provenance. The observation cannot authenticate the earlier forwarded packet. |
| Off (`off`) | The approved encrypted forwarder supplies the client answer. No local validation runtime or anchor refresh is started. | Existing upstream telemetry where enabled, without a claim of local validation. |

For Live, a provider's AD flag is not evidence of local validation. The
validator requests the material it needs with DO/CD, checks the signed chain
against current local trust anchors, and binds verification to the returned
RRsets. Alias chains, negative answers, DNSKEY/DS material and denial proofs
share the existing validator's policy and finite-work limits. Secure,
authenticated-negative and proved-Insecure outcomes remain distinct.

Bogus, Indeterminate, exhausted capacity and operational failure produce
SERVFAIL with their distinct reasons. A proved unsigned delegation can return
an Insecure answer with AD clear. A client's CD flag skips DNSSEC checking
for that request while preserving local policy, access control, rate limiting
and rebinding protection. An unsupported/private validation arrangement is
not automatically treated as trustworthy; general private trust-zone policy
and native conditional forwarding are not added by this transport.

The on-device statistical learner is independent of TLS and DNSSEC. It can
record changing traffic patterns as findings. It cannot disable certificate
checks, approve a new resolver, create a trusted key or turn a failed DNSSEC
proof into Secure.

Background A/AAAA hostname lookups used by the daemon's HTTP clients follow
the same encrypted bundle, including supporting connections for feeds,
providers and webhooks. Those hostname responses are **transport-authenticated,
not independently DNSSEC-validated by the Live client path**. Destination
HTTPS certificate checks and provider/webhook destination restrictions still
apply. This profile does not change other processes' DNS, host network
configuration or applications' own encrypted-DNS behavior.

## Failure handling, state and operational evidence

Configuration is validated without sending queries. A transport change is
persisted before it becomes active. Old native operations, Learn work,
forwarder races and process DNS bridges are cancelled and drained before the
change succeeds; retired encrypted transport bundles close their connections.
Inactive legacy forwarders are not an approved fallback. Cache and concurrent
query grouping use an immutable route generation; a result from an old profile
cannot satisfy a request on a new one. Historical query/observation provenance remains tied to
the path that actually processed it.

One RFC 5011 manager carries current anchors and hold-down state between
active transports. The old refresh owner stops before the new one starts.
Transport configuration never turns an observed root key into immediate
trust. Preserve the managed anchor file with your normal recovery package.

Dashboard choices are stored in SQLite under `dns.transport.v1`, independently
of `dnssec.mode`. Without an explicit configuration pin, an unreadable or
malformed saved profile fails startup; it does not reset to native. A failed
pre-publication save leaves the previous runtime active. Explicit valid
configuration can pin a repaired deployment.
Settings and relevant state are included in the existing
[backup and restore workflow](recovery.md); private CA installation in the OS
root store remains a deployment responsibility.

| Limit | Value |
| --- | ---: |
| Approved endpoint entries | 16 |
| Literal bootstrap IPs per entry | 8 |
| Active encrypted exchanges per transport bundle | 128 |
| Active exchanges per endpoint | 32 |
| DNS wire message | 65,535 bytes |
| Decoded HTTP response headers | 16 KiB; trailers are rejected |
| Encrypted exchange timeout | `dns.timeout`, maximum 30 seconds |
| Forwarded Live/learn operation | 64 wire queries and 1 MiB retained wire material, alongside shared validator limits |
| Background DNS bridge | 64 active connections, finite frames and deadlines |
| Simultaneous dashboard endpoint tests | 1 |

These are implementation bounds, not a measured requests-per-second capacity
or latency promise. Endpoints reuse an owned connection per protocol entry;
reconnect attempts are bounded and back off after failures. An operation can
need multiple exchanges, so query counts and user requests are different
denominators. Failover shares the overall exchange deadline across the
remaining approved entries.

The Daddybound page reports the effective transport, independent local mode,
attempts, successes, failures, rejected work, failovers, active work, and the
last observed authenticated TLS connection. A retained TLS version or remote
address is historical evidence, not a current liveness probe. Unobserved
values stay unmeasured. Transport counters reset when their bundle is
replaced; they are not a durable traffic history.

The management API exposes `GET/PUT /api/v1/dns/transport` and
`POST /api/v1/dns/transport/test`; the served [OpenAPI specification](../internal/api/openapi.yaml)
defines request shapes and error semantics. Writes require normal management
authentication and cookie CSRF protection. Prometheus transport metrics use
bounded endpoint indices/protocols, excluding hostname, URL and bootstrap-IP
labels. Management endpoint details are visible only to authenticated admins.

`dnsdaddy doctor -config /path/to/config.yaml` reads the effective saved
transport and mode before probing. An encrypted deployment tests only its
approved encrypted upstreams. A config/read failure disables probes. Native
Live skips inactive legacy forwarders. Local listener checks are separate
client-to-daemon connections and require verified local literal addresses;
the dashboard probe refuses redirects and environment proxies. Doctor's
hostname bridge does not create a separate local DNSSEC verdict.

## Server IPs on the homepage

The **Server IP addresses** card reads authenticated
`GET /api/v1/server-addresses`. It lists OS-visible IPv4/IPv6 addresses,
scope/interface labels and compatible configured UDP/TCP/DoT listener ports,
with copy controls. A suitable LAN address is suggested when available.
Wildcard binds are not presented as client targets. Loopback and link-local
addresses are never recommended for general LAN use.

If interface enumeration is restricted, DNS Daddy can report the actual
server-side local socket address of the dashboard connection and labels the
list incomplete. The endpoint never substitutes the browser/client IP, Host
header, forwarding headers or an external IP-discovery service. This fallback
works without weakening the shipped systemd address-family restrictions.

Container, tunnel and NAT configurations may expose a different host address
or port. The card reports local evidence, not internet reachability or an open
firewall. Setup retains the client-facing connection instructions. Address
inventory is not added to the public login or health response.

## Verification and limits

Transport fixtures use real local TLS/QUIC servers with test-only roots. They
cover protocol negotiation, certificate rejection, framing/question matching,
header/body/trailer bounds, encrypted failover, cancellation, connection reuse
and admission limits. Validator tests cover signed and tampered answers,
aliases, denial proofs, trust changes and finite work. Controller/doctor tests
check persistence failures and plaintext traps. Browser QA exercises the real
app over a loopback-only lab, including deliberate failure and responsive
forms; [screenshot provenance](images/SCREENSHOTS.md) identifies its scope.

These tests establish regression properties. They do not establish field
reliability on every router, provider support, third-party security review,
production detector accuracy or performance on a low-memory target. Keep the
[Daddybound validation limitations](daddybound/validation-lab.md) in view.

## Protocol references

- [RFC 9250: DNS over Dedicated QUIC Connections](https://www.rfc-editor.org/rfc/rfc9250.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 8484: DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc8484.html)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 4033: DNS Security Introduction and Requirements](https://www.rfc-editor.org/rfc/rfc4033.html)
- [RFC 4035: Protocol Modifications for DNS Security](https://www.rfc-editor.org/rfc/rfc4035.html)
- [RFC 5011: Automated Updates of DNSSEC Trust Anchors](https://www.rfc-editor.org/rfc/rfc5011.html)
