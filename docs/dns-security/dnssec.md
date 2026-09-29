# DNSSEC in DNS Daddy

DNS Daddy reports the source of its validation information and provides three
native modes: **Live**, **Learn** and **Off**. Live is an implemented,
experimental client-serving resolver. Learn collects separate observations
while clients continue using the forwarding resolver.

## What DNSSEC establishes

DNSSEC adds signatures and authenticated delegations to DNS. A validating
resolver checks records against a chain leading to a configured trust anchor.
The result concerns authenticity and integrity of DNS data. It does not prove
a website is harmless, encrypt DNS traffic, or prevent a device from choosing
another resolver. A phishing domain can have valid DNSSEC signatures.

A DNSSEC verdict also depends on the configured trust anchor, supported
algorithms, available proof, time and the records that were actually checked.
An inability to finish checking is not a proof that the zone is unsigned.

The basic protocol is described in [RFC 4033], [RFC 4034] and [RFC 4035].

## Selecting the native mode

| Selection | Client answer path | Validation behavior |
| --- | --- | --- |
| **Live** (`enforce`) | Daddybound's native authoritative recursion | Validates the exact records returned to the client. Bogus, indeterminate and operational failures return SERVFAIL; there is no silent forwarding fallback. |
| **Learn** (`observe`) | Configured forwarding upstream | Resolves allowed questions independently after the client answer is decided, then records the local observation. That observation cannot change the client answer. |
| **Off** (`off`) | Configured forwarding upstream | Native client resolution, background observation and managed-anchor refresh are stopped. |

### Defaults and precedence

Fresh installations default to **Live**. An upgrade preserves the
installation's recorded Off/Learn choice. A recorded dashboard mode overrides
the installation default when the mode is not pinned in configuration.
Explicit `dns.local_dnssec_validation` in YAML or the corresponding environment
configuration pins the choice; remove that explicit setting to manage it from
the dashboard.

For an intentionally fixed forwarding-with-observation setup:

```yaml
dns:
  local_dnssec_validation: observe
```

For an intentionally fixed native setup:

```yaml
dns:
  local_dnssec_validation: enforce
```

A dashboard change uses `PUT /api/v1/dnssec/mode`. Enabling Learn or Live
requires `acknowledgeNativeTransport: true`. Mode, source of the choice,
configuration lock and effective runtime are reported by
`GET /api/v1/dnssec/status`. A failed change does not silently advertise a new
working mode. The management change journal records its persisted outcome.

The fresh-install default is an explicit product choice. It does **not** mean
there is independent or long-running production evidence for this validator.
Existing users are not silently switched from forwarding to Live on upgrade.

## Live: validation governs the native answer

Live performs bounded native recursion over UDP/TCP to authoritative servers.
It does not use the forwarding answer cache. Validation and the returned
Answer/SOA records come from the same native result: an independent successful
lookup is not permission to serve unrelated data supplied in a different
response.

| Outcome | Live client response |
| --- | --- |
| `secure` | The authenticated answer can be served. AD is set only when the client requested AD or DO. |
| `insecure` | A proven unsigned delegation permits an unauthenticated answer, without AD. This is a validated absence of a signing chain, not an error. |
| `bogus` | SERVFAIL with DNSSEC Bogus extended error. The untrusted answer is not served. |
| `indeterminate` | SERVFAIL with DNSSEC Indeterminate extended error. Missing anchors/proofs are not relabelled insecure. |
| Timeout, capacity or internal work failure | Bounded failure returning SERVFAIL; no fallback to an upstream answer. |

A client that explicitly sets **CD** requests DNSSEC checking to be disabled.
Live still uses native resolution and clears AD. Local policy, permitted-client
checks, rate limiting and rebinding protection continue to apply. CD is not an
allow-list or a way to disable other DNS Daddy controls.

The client DO bit controls auxiliary DNSSEC records in the response. When DO
is absent, auxiliary DNSSEC records are stripped unless the client explicitly
queried their type. A valid signature does not grant permission to append
unrelated unsigned data.

Live can increase latency or fail where a forgiving forwarding resolver would
return data. Failures can expose real DNSSEC problems, network egress problems,
resource bounds or implementation defects. Inspect the recorded reason and
runtime counters before assuming an attack or a broken domain.

## Learn: independent observation

Learn is off the client response path. Its fixed worker pool and bounded queue
receive allowed questions after their forwarded answers are decided. A full
queue drops observations rather than delaying the answer. Observed-but-not-
stored losses are counted separately from queries never observed.

The upstream and native observer can encounter different data, cache state,
authoritative responses or moments in time. A disagreement is an investigation
lead; it is not automatically proof that either checked the same records and
was wrong. Status separates populations by resolution source and comparability.

Learn verdicts do not block or rewrite forwarded answers. The local statistical
learner is another separate component: it fits traffic baselines and produces
uncalibrated anomaly findings, without changing answers in any native mode.
See [local traffic learning](../learning.md).

## Native transport and trust-anchor state

Live and the normal native Learn path send **plaintext UDP/TCP port 53**
traffic to root and authoritative servers, with QNAME minimisation. The
configured DNS-over-TLS forwarding upstream does not encrypt or carry this
native traffic. Deployments that permit only encrypted upstream egress must
choose the mode and outbound network rules deliberately. Native root/TLD/
authoritative work has explicit request, delegation, memory and time bounds.

The managed-anchor process starts from the compiled-in root trust anchors, or
`dns.local_dnssec_trust_anchor_file` when explicitly configured. It maintains
RFC 5011 lifecycle state in `daddybound-anchors.json` beside the database.
Losing this file loses persisted lifecycle/hold-down history; it is not a safe
substitute for a planned anchor recovery procedure. Backups include the managed
state and any configured custom anchor file.

`GET /api/v1/dnssec/status` reports each anchor's state, last attempted and
successful refresh, refresh failures, persisted-state failures and effective
mode. These report what the process knows. They do not certify successful
future rollovers or a firewall configuration the process cannot inspect.

See [Daddybound](../daddybound/README.md),
[its security model](../daddybound/security-model.md) and
[encrypted recovery](../recovery.md).

## Forwarded DNSSEC telemetry

In Off/Learn mode, DNS Daddy requests an upstream AD verdict when
`dns.dnssec_telemetry` is enabled. AD in a query asks the upstream to report
that verdict; it does not ask for the full DNSSEC records in the way DO does.
See [RFC 6840] §5.7.

The recorded status is accompanied by `dnssecSource`:

| Forwarded status | Meaning | Limitation |
| --- | --- | --- |
| `validated` | The upstream reported authentication with AD. | DNS Daddy's forwarding path did not verify those signatures itself. |
| `unvalidated` | The forwarded answer carried no positive AD verdict. | Does not distinguish proven unsigned data from an upstream that did not validate. |
| `servfail` | The upstream could not return an answer. | A validation failure is one possible cause among several. |

A malicious upstream can falsely set AD. Forwarded telemetry is only the
upstream's reported conclusion. Native Live provides local validation on a
different client answer path; an observation in Learn does not retroactively
validate the forwarded records.

The AD bit is filtered for clients that did not request AD or DO. A checked
result also does not cryptographically protect the link from DNS Daddy to a
stub client: a hostile local path can alter plain DNS. Use a protected client
transport or validation at the client where that is required.

## Reading the operational evidence

Start with the mode and answer-path report, then inspect the affected query,
its decision record and its correlated native observation where available.
Do not mix native and upstream validation populations into one percentage.

```sh
curl -H 'Authorization: Bearer YOUR_MANAGEMENT_TOKEN' \
  'https://your-server/api/v1/dnssec/status'

curl -H 'Authorization: Bearer YOUR_MANAGEMENT_TOKEN' \
  'https://your-server/api/v1/queries?limit=100' \
  | jq '.queries[] | {domain, dnssec, dnssecSource, action, reason}'
```

There is no universal healthy percentage of signed queries. The mix depends
on the names clients use, mode, cache behavior, logging choices, losses and
time window. A change in a clearly scoped baseline is worth investigation; it
is not a standalone protection score.

The `resolution_failure` behavioural detector identifies repeated SERVFAIL
outcomes. That heuristic does not parse a validation chain and still has a
broader meaning than DNSSEC failure. In Live mode, use the native observation
and decision reason to distinguish validation from operational failure. The
finding itself is an experimental lead and carries no automatic enforcement.

Query-log privacy controls also govern persisted per-query evidence. Status
counters can cover more observations than stored rows, and the interface
reports that distinction. Neither observation nor validation grants permission
to bypass a policy's logging choice.

## Investigating a suspected DNSSEC failure

First inspect the local native result and operational status. For a domain you
are authorised to investigate, an independent validating tool can help compare
the exact chain and authoritative data:

```sh
# Independent validation and a chain trace.
delv +rtrace example.com

# Compare ordinary and checking-disabled requests through the same resolver.
dig +dnssec example.com @YOUR_RESOLVER_ADDRESS
dig +cd example.com @YOUR_RESOLVER_ADDRESS
```

Success with checking disabled is a clue that validation or its supporting
work is involved; it does not by itself identify the broken record or prove
which implementation is correct. Keep timestamps, errors, cache state and
actual returned records when comparing systems. Avoid diagnosing by a lone
AD bit or an unexplained SERVFAIL.

An external service such as [DNSViz](https://dnsviz.net/) can visualise a public
zone's chain, but using it discloses the name to that service. Read-only policy
preview inside DNS Daddy does not perform that external lookup.

## Algorithm policy implemented by this build

Daddybound has an explicit validation policy in
[`internal/daddybound/dnssec/policy.go`](../../internal/daddybound/dnssec/policy.go).
The default permits supported signature algorithms 8 (RSA/SHA-256), 10
(RSA/SHA-512), 13 (ECDSA P-256/SHA-256), 14 (ECDSA P-384/SHA-384) and 15
(Ed25519). Algorithms 5 and 7 remain verifiable capabilities but are not
permitted by the default signing-algorithm policy.

DS digest handling is a separate decision from the DNSKEY/RRSIG algorithm.
The default verifier accepts supported SHA-1, SHA-256 and SHA-384 DS digests.
This describes the checked-in validator policy; it is not a recommendation
for choosing a new zone-signing algorithm. See the current standards and
registries linked by [Daddybound's standards notes](../daddybound/standards.md)
when reviewing or changing that policy.

## Evidence limitations

The repository includes signed offline laboratories, malformed-response tests,
resource bounds and optional differential comparisons. These are useful
implementation evidence. They do not supply independent assurance, weeks of
production reliability, realistic small-device load results, measured
production false-positive rates or a longitudinal root-key rollover study.
Live remains labelled experimental for those reasons even when selected by
default.

## Further reading

- [RFC 4033], [RFC 4034], [RFC 4035] — DNSSEC protocol
- [RFC 6840] — protocol clarifications and AD signaling
- [RFC 5011] — automated trust-anchor updates
- [RFC 9364] — DNSSEC operational background
- [Capabilities](../capabilities.md) — implemented and remaining work
- [Local learning](../learning.md) — statistical baselines are separate evidence

[RFC 4033]: https://www.rfc-editor.org/rfc/rfc4033
[RFC 4034]: https://www.rfc-editor.org/rfc/rfc4034
[RFC 4035]: https://www.rfc-editor.org/rfc/rfc4035
[RFC 6840]: https://www.rfc-editor.org/rfc/rfc6840
[RFC 5011]: https://www.rfc-editor.org/rfc/rfc5011
[RFC 9364]: https://www.rfc-editor.org/rfc/rfc9364
