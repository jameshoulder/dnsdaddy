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

## Start with a working example

For a first encrypted setup, DNS Daddy includes a complete **Cloudflare DoH
over HTTP/2 + Daddybound Live** example. It uses outbound TCP 443, so it does
not require QUIC or direct access to authoritative servers on port 53. No API
key, account, domain name or server certificate is needed for this outbound
connection. You are explicitly choosing Cloudflare to receive the queries.

| Setting | Example value | What it does |
| --- | --- | --- |
| Transport | `encrypted` | Uses only the configured encrypted forwarders. |
| Protocol | `doh2` | HTTPS over HTTP/2 on TCP 443, with authenticated TLS 1.3. |
| Endpoint | `https://cloudflare-dns.com/dns-query` | Cloudflare's standard public resolver. |
| TLS server name | `cloudflare-dns.com` | The identity the certificate must authenticate. |
| Bootstrap IPs | `1.1.1.1`, `1.0.0.1` | Finds the endpoint without first needing a working DNS resolver. Both IPs belong to the same provider. |
| Daddybound | `Live` / `enforce` | Validates the returned DNS data locally before answering. |

Cloudflare documents its [resolver addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/),
[DoH protocols](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/),
[endpoint and DNS wire format](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/),
and [privacy policy](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/).
The example uses the standard resolver so DNS Daddy remains responsible for
its local filtering policy. The example does not select Cloudflare's Families
filtering service. IPv6-only hosts can replace the bootstrap list with
`2606:4700:4700::1111` and `2606:4700:4700::1001`.

### Already running DNS Daddy

Use **Daddybound → DNS transport → Encrypted forwarding → Add Cloudflare
example**. Review the filled fields, check the sharing agreement, select
**Test endpoints**, then **Apply DNS transport** after a successful test.
Select or keep **Live** in the Daddybound card above it. The example button
only edits the draft; it preserves existing endpoints and does not test,
save, grant consent or change your current Off/Learn/Live setting.

Finish with the client tests below. **Test endpoints checks a root DNSKEY
exchange, not a complete locally validated Live lookup.**

### Try the standalone binary

From the repository root, after installing the build prerequisites:

```bash
make run-encrypted
```

This builds and runs the [complete example configuration](../dnsdaddy.encrypted.example.yaml).
It uses a separate `./tmp/encrypted-example` data directory, loopback DNS on
port **5353**, and the dashboard at `http://127.0.0.1:8080`. It can run without
root. The first-run password is in
`./tmp/encrypted-example/initial-password.txt`.

In a second terminal on the same machine:

```bash
./bin/dnsdaddy doctor -config ./dnsdaddy.encrypted.example.yaml
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com A +tcp
```

The loopback example is for testing on that machine. To serve a LAN, bind a
reachable LAN address, use or publish UDP **and** TCP port 53, and permit that
LAN's client range. The Docker option below already publishes port 53.

### Run the encrypted example in Docker

From the repository root, with Docker Engine and Compose installed:

```bash
docker compose -f docker-compose.yml -f deploy/docker-compose.encrypted.yml up -d --build
docker compose -f docker-compose.yml -f deploy/docker-compose.encrypted.yml exec dnsdaddy dnsdaddy doctor
docker compose -f docker-compose.yml -f deploy/docker-compose.encrypted.yml exec dnsdaddy cat /var/lib/dnsdaddy/initial-password.txt
```

The [encrypted overlay](../deploy/docker-compose.encrypted.yml) mounts the
working example. It keeps the normal data volume and dashboard binding, and
publishes host UDP/TCP **53** to the container's **5353**. The doctor command
above checks DNS from inside the container and is the first readiness check.

Open `http://127.0.0.1:8080` on that host, or use the
[documented SSH tunnel](deploy.md) for a VPS. Grant the intended client
networks as described below before testing the published DNS port. Even a query from the Docker
host to `127.0.0.1:53` can reach the container with the **bridge gateway** as
its source, so host loopback does not automatically mean container loopback.
To identify that gateway:

```bash
docker inspect dnsdaddy --format '{{range .NetworkSettings.Networks}}{{println .Gateway}}{{end}}'
```

If you want host-originated tests, add the actual gateway as a permitted
network using its IPv4 `/32` or IPv6 `/128` prefix. This represents traffic
sharing that Docker gateway, not a separate identity for every source behind
NAT. Then test on the Docker host:

```bash
dig @127.0.0.1 -p 53 example.com A
dig @127.0.0.1 -p 53 example.com A +tcp
```

Use both `-f` arguments for subsequent updates and diagnostics. This
configuration pins transport and
Live in the dashboard. Environment overrides still take precedence: review
any existing `DNSDADDY_RESOLUTION_TRANSPORT`, `DNSDADDY_ENCRYPTED_UPSTREAMS`
or `DNSDADDY_LOCAL_DNSSEC_VALIDATION` settings before using the example.
Removing the overlay returns to the normal configuration and any previously
saved choices; it does not save the example as a dashboard choice.

### Connect one device

1. Open **Setup** and identify the server address and host DNS port. A
   dashboard reached through a reverse proxy or SSH tunnel does not identify
   the DNS address. Container addresses and listener ports can differ from
   the host address and published port.
2. Open **Networks**, add the authorised LAN, VPN range or client IP, and
   enable **Allow this network to use DNS Daddy**. New installations leave
   Default ad-hoc access off, so private addresses are not automatically
   permitted merely because they occur in the configured bootstrap pool.
   A policy name alone does not grant access. Use the client's source as the
   server sees it, which may be a NAT or Docker gateway address.
3. From that device, run the following with the actual server IP. These
   commands assume standard host port 53; change `-p 53` when testing a
   different published port.

```bash
dig @<server-ip> -p 53 example.com A
dig @<server-ip> -p 53 example.com A +tcp
# Windows alternative:
nslookup -port=53 example.com <server-ip>
```

Look for `NOERROR` with an answer, and confirm the query and local DNSSEC
result in the dashboard. In Live, both secure signed answers and proven
unsigned answers can be valid; an unsigned domain does not acquire a DNSSEC
signature because the transport is encrypted. Then configure one device's
normal DNS setting and watch its traffic before changing DHCP for everyone.
Most IP-only device and DHCP DNS settings require port 53.

### If the first lookup fails

| Symptom | Check or correction |
| --- | --- |
| The dashboard opens, but `dig` times out | The web and DNS listeners are separate. Check the host IP, UDP/TCP DNS ports, Docker mappings, firewall and any existing service already using port 53. |
| `REFUSED` | Permit the client's actual source IP or network under **Networks**. New installations keep Default ad-hoc access off. For host-to-Docker tests, the source may be the Docker gateway even when the command targets `127.0.0.1`. |
| The endpoint test fails | Check outbound TCP 443, the system clock and CA certificates. Confirm that the protocol, TLS name and bootstrap IPs match the chosen provider. The Cloudflare example is DoH2, not DoQ. |
| Endpoint test passes, but Live returns `SERVFAIL` | Inspect **Daddybound → Trust anchors, observation health and evidence**, transport errors and the Query log's local DNSSEC reason. The endpoint test did not prove a complete validation chain. A bogus answer is supposed to fail; repeated failures for normal names require investigation. |
| Local tests work but another device fails | Check that the listener binds a reachable interface, that both UDP and TCP reach it, and that the client is permitted. The standalone example deliberately binds loopback. |
| Tests on 5353 work but setting the device's DNS IP does not | Most device settings use port 53. Publish or listen on host UDP/TCP 53, or use a client that supports an explicit port. |
| Native Live times out on a network that permits only web traffic | Native recursion requires direct UDP/TCP 53 access. Deliberately choose and test the encrypted profile using TCP 443 instead. |

Use `dnsdaddy doctor` with the same configuration and environment as the
running service. Repair the reported fault; switching off certificate checks
or adding a plaintext fallback is not part of this setup.

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
2. Select **Add Cloudflare example** to fill a working DoH2 draft, or add
   your resolver's supported protocol and address. DoQ takes a host or
   `host:port`; DoH takes its complete `https://host/path` endpoint URL.
   A DoT endpoint on TCP 853 is not a DoQ endpoint on UDP 853.
3. Provide literal bootstrap IPs for a named endpoint. Obtain them from the
   resolver operator or your own deployment configuration. The client never
   asks ordinary DNS how to find its encrypted resolver.
4. Check the TLS identity. It normally defaults to the address's hostname.
   A named DoH URL must authenticate that same hostname. A literal-IP address
   can use the resolver's certificate hostname in **TLS server name**.
5. Add and order any approved fallback entries. Check the disclosure
   acknowledgement after completing the endpoint draft.
6. Select **Test endpoints** before applying a new provider. This sends a
   fixed root (`.`) DNSKEY question through the draft endpoints. It changes no settings or trust
   anchors. An entry that was not attempted has not been tested; ordered
   failover stops after an accepted response. This checks the exchange and
   response, not the provider's accuracy or a local DNSSEC proof.
7. After a successful test, select **Apply DNS transport**. The current
   Off/Learn/Live choice remains selected. Select **Live** separately if it was
   Off or Learn and you want enforcement. Live continues to validate locally
   over the new record source. The API does not require a prior test; testing
   is the recommended setup sequence.

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

The [complete runnable example](../dnsdaddy.encrypted.example.yaml) includes
the listeners and data directory. To incorporate its outbound settings into
an existing configuration, explicitly select the provider as follows:

```yaml
dns:
  resolution_transport: encrypted
  encrypted_upstreams:
    - protocol: doh2
      address: https://cloudflare-dns.com/dns-query
      server_name: cloudflare-dns.com
      bootstrap_ips: ["1.1.1.1", "1.0.0.1"]
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
