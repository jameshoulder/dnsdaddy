# Resolver admission and rebinding protection

These local controls are enabled by default and work in Daddybound Live,
Learn and Off. They use no provider API and never learn exceptions from
traffic. **Settings → Resolver protection** shows the current configuration,
version and operational counts.

## Per-client rate limiting

The default token bucket permits an average of **50 queries per second**, with
a **100-query burst**, up to **4,096 retained client buckets**, and **300 seconds
of idle lifetime**. The key is the normalized client IP plus the verified
network identity supplied by the resolver transport. IPv4-mapped IPv6 clients
share their IPv4 bucket. Arbitrary forwarding headers are not accepted as an
identity; the existing trusted-proxy and token checks still apply.

The ACL runs first. An admitted query must then obtain a token before policy,
provider work or DNS resolution. Rate-limited requests receive REFUSED, with
an Extended DNS Error for EDNS clients, and increment an aggregate counter.
They do not create one database row per rejected query.

When the client map is full, additional identities share one overflow bucket.
An attacker cannot evict an active client to obtain a fresh per-client burst.
At most eight expired buckets are reclaimed per new identity. The status
distinguishes **rateLimited** (requests refused) from **rateOverflow** (requests
using shared overflow capacity, including those admitted).

The limiter bounds application work on one instance. It cannot stop traffic
from saturating the machine's uplink before DNS Daddy receives it. Users behind
one observed NAT address share a bucket unless the transport supplies a
separate verified network identity.

## DNS rebinding checks

Every resolved message is checked before it is returned, including forwarded
cache hits and native answers. The guard scans A/AAAA records in the answer,
authority and additional sections, plus SVCB/HTTPS IPv4 and IPv6 address hints.
An alias cannot hide a private address in another section. A DNSSEC-authenticated
private address is still subject to this check, and a client's CD flag does
not bypass it.

The classifier covers private, loopback, unspecified, link-local, multicast,
shared carrier space and the listed non-public special-purpose ranges. It
normalizes IPv4-mapped IPv6 and inspects the embedded IPv4 address in the
well-known NAT64 and 6to4 prefixes. Explicit globally reachable protocol
allocations are retained as exceptions to their broad parent allocations.
The static classifications were reviewed against the
[IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IANA IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/)
on 2026-09-29. They are address classifications, not a measurement of the
operator's actual routing table.

A rejected message is replaced with REFUSED. No portion of its answer is
returned and AD is clear. Query history records the rejection reason; where
decision recording and privacy settings permit, the captured local decision
is retained for investigation. EDNS clients also receive the standard
[Extended DNS Error](https://www.rfc-editor.org/rfc/rfc8914.html).

### Internal and split-DNS exceptions

An exception is an explicit configuration change with history:

- **Domain**: `corp.example` permits that original query name and its
  subdomains to return internal addresses. It does not permit an unrelated
  name merely because its CNAME/DNAME target ends in `corp.example`.
- **CIDR**: `10.42.0.0/16` or `fd42:1234::/48` permits answer addresses in
  the chosen network. This is broader than a domain exception; scope it to
  the deployment's actual destinations.

Wildcards, URLs, IP addresses in the domain field, public-suffix domain
exceptions and unrestricted `/0` prefixes are rejected. Each list is bounded
to 256 entries. A version conflict returns HTTP 409; reload before saving so
another operator's configuration is not overwritten.

An exception permits an address; it does not create a DNS zone or a route.
Native Live has no conditional forwarding or automatic access to private
split-DNS zones. For such deployments, use the configured forwarding path in
Learn or Off, with the required rebinding exceptions. Native resolver egress
also has its own restrictions; a response exception does not relax those.

## Configuration and persistence

The YAML defaults are:

```yaml
protection:
  rate_limit:
    enabled: true
    qps: 50
    burst: 100
    max_clients: 4096
    idle_seconds: 300
  rebinding:
    enabled: true
    allow_domains: []
    allow_cidrs: []
```

After a dashboard save, the versioned settings in SQLite take precedence over
these initial YAML values and survive a restart/backup. A save is persisted
before the live snapshot changes. Rebinding-only edits preserve existing
rate buckets, so editing an exception does not refill everyone's allowance.

`GET /api/v1/protection` returns the settings and counters.
`PUT /api/v1/protection` requires the version read by the client and the full
configuration. The API uses the normal authentication, same-origin protection
and configuration journal. Prometheus exposes aggregate counters and capacity
without an unbounded client-IP label.

Tests in [internal/protection](../internal/protection/) cover refill,
concurrency, state overflow, address families, translation prefixes, aliases,
address hints, persistence failures and stale revisions. The
[serving-path tests](../internal/dnsserver/protection_runtime_test.go) exercise
the controls with native answers, forwarded cache hits and CD requests.
