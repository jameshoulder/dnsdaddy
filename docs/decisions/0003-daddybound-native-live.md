# ADR 0003: native Live answers with exact DNSSEC validation

**Status:** implemented, experimental. Supersedes ADR 0002's refusal of
`enforce`; ADR 0002's independence guarantee continues to apply to Learn.
The native transport described here remains supported. [ADR 0004](0004-encrypted-forwarding.md)
adds independently selected encrypted record acquisition with local validation;
it also defines the transport-aware mode acknowledgement and provenance.

**Default superseded:** the current product starts new installations in
**Forward** (`off`), retaining existing saved choices and the Live behavior
described below. The original fresh-install `enforce` decision in this ADR is
historical. Forward, Learn and Live remain explicitly selectable; see
[current mode defaults](../dns-security/dnssec.md#defaults-and-precedence).

## Decision

Daddybound can supply a real client answer. In Live
(`dns.local_dnssec_validation: enforce`), the DNS handler selects native
recursion before consulting the forwarding cache. Daddybound walks from root
hints to authoritative servers over UDP/TCP 53, projects the response it will
serve, validates those exact RRsets, and decides whether to return the data.
There is no fallback from a failed native request to an upstream resolver.

A newly created installation records `enforce` as its default. Existing
installation records, including `observe` and `off`, are preserved. Older
installations without the first-run record receive `off`; an unreadable record
does not establish that an installation is new. Explicit YAML/environment
modes win and lock dashboard changes. This changes the new-install product
default; it does not establish production readiness.

The dashboard can change an unpinned mode through authenticated
`PUT /api/v1/dnssec/mode`. Enabling either native mode requires the explicit
native-transport acknowledgement. The controller persists the selected mode
in `dnssec.mode` before publishing it, reuses one native runtime between Live
and Learn, and cancels native activity when switched off. A request that
already selected Live cannot silently switch to forwarding during a mode
change. A failed runtime construction is an error, never a downgrade.

## What each mode means

| Mode | Client answer | Native work | Evidence |
| --- | --- | --- | --- |
| Off (`off`) | Configured forwarder and normal local policy | No native runtime or native refresh | Upstream telemetry, if enabled |
| Learn (`observe`) | Configured forwarder and normal local policy | Bounded independent native observations after resolution | `resolution: native`; describes an independent native lookup |
| Live (`enforce`) | Daddybound native recursion and local policy | Native resolution, exact validation, anchor refresh | `resolution: native_live`; describes this native client result |

Historical rows do not acquire a different meaning when the current mode
changes. A Learn observation cannot authenticate the earlier forwarded packet.
Live observations have no upstream comparison. CD requests are counted
explicitly and do not produce a checked DNSSEC observation. Persistence is
asynchronous and bounded; a missing row does not prove validation was absent.

## Binding validation to the returned data

Checking a second answer for the same name is insufficient. It might differ
because a zone changed, an alias crossed a trust boundary, a server was
inconsistent, or an attacker supplied different records.

The native resolver retains each exact reply in the alias chain. It keeps only
the relevant alias at each hop, resolves the next target independently, and
uses that independently obtained target in the final packet. It never
validates a re-fetched target and then returns an older target bundled with
the first response. DNAME CNAMEs are recomputed from the DNAME substitution;
the server's unsigned synthesized target is not trusted. Alias loops,
delegation depth and nameserver-address dependency depth are bounded.

The validator reads the pinned question responses and pinned individual
RRsets. Each successful signature verification produces an in-memory receipt
containing a digest of the exact canonical signed data. The receipt's fields
are private and cannot be populated by the transport layer. A Secure textual
trace is not such a receipt.

The response projection validates the original question, each returned
nonsynthetic Answer RRset, and each returned SOA. These checks share one
lookup and NSEC3 hash budget. An unsigned alias cannot hide a bogus signed
target by terminating the original question's walk early. Every RRset served
under AD must match an authentication receipt; irrelevant Additional data and
unauthenticated surplus denial records are removed. A synthesized CNAME follows
the authenticated DNAME and its constrained TTL.

## DNSSEC and wire outcomes

| Native result | CD=0 client outcome | AD |
| --- | --- | --- |
| Secure answer or authenticated negative answer | Return the projected native packet | Set only if the client sent AD or DO |
| Proved Insecure delegation/opt-out | Return the native packet | Clear |
| Bogus | SERVFAIL; EDNS clients receive EDE 6 | Clear |
| Indeterminate, including no trust anchor or unsupported policy | SERVFAIL; EDNS clients receive EDE 5 | Clear |
| Timeout, unreachable authority, exhausted work/capacity or internal error | SERVFAIL with a distinct operational reason/EDE | Clear |

CD=1 disables DNSSEC checking for that native request. It does not disable
client admission, blocklists, policy, rate limiting or rebinding protection.
The request still follows native recursion, never an upstream fallback, and
AD is clear. Unchecked material is not cached as an authenticated client answer.

DO=0 removes auxiliary DNSSEC records unless the query explicitly requested
their type. Client ID/question, RD and CD are preserved, RA is set, and
authoritative AA and AD are not inherited. Only the client's supported EDNS
settings are retained; authoritative cookies, ECS and other Additional data do
not propagate. EDNS versions above zero receive BADVERS. Native resolution
requires an ordinary IN query with exactly one question and RD=1; RD=0 receives
REFUSED rather than triggering recursion. These rules follow
[RFC 4035 §§3.2.1–3.2.3](https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2),
[RFC 6840 §§5.7–5.8](https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7),
[RFC 6672 §5.3.1](https://www.rfc-editor.org/rfc/rfc6672.html#section-5.3.1)
and the reason codes in [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html).

Daddybound deliberately fails closed for unsupported DNSSEC policy and
indeterminate proofs. This can refuse domains that a different validating
resolver treats as unsigned under RFC 6840. The stricter interpretation is
recorded in [standards.md §5.3](../daddybound/standards.md#53-the-honesty-constraint-on-51-and-52);
it is an interoperability limitation, not evidence of maliciousness.

## Cache and trust lifecycle

Forwarded answer caches and upstream AD bits cannot confer native trust.
Native recursion caches DNS material and referrals, but a CD=0 client answer
is revalidated against the current clock and current anchor snapshot. A
previous Secure status is not reused. Signature expiration and anchor
withdrawal therefore affect subsequent cached-material queries. Numeric
QTYPE values are part of material-cache keys, including unknown record types.

TTL is capped by the received RRset TTL, received RRSIG TTL, RRSIG Original
TTL and remaining accepted-signature lifetime, using DNSSEC serial time
([RFC 4035 §5.3.3](https://www.rfc-editor.org/rfc/rfc4035.html#section-5.3.3)).
No forwarding-cache minimum TTL can extend that lifetime. The anchor manager
starts from local bootstrap trust, authenticates RFC 5011 updates with
existing trust, and persists lifecycle/hold-down state. Missing current trust
produces Indeterminate. A refresh error does not turn signed data into an
unsigned zone, and an observed key never becomes immediately trusted.

## Finite work and availability

The native client has a nonblocking admission limit of 128 active requests,
reduced by `dns.max_inflight` if that value is smaller. Excess requests fail
explicitly rather than waiting in an unbounded queue. The default complete
native request budget is five seconds; `local_dnssec_timeout` may not exceed
one minute. Cancellation is propagated through native network operations.
Panics at the native client seam become counted internal failures.

Validation defaults include 64 supporting lookups across the whole projected
response, 32 projected validation questions, 24 zones, 12 aliases, 16 keys and
16 signatures per relevant RRset, 32 denial records and 4096 total NSEC3 hash
computations. Each recursive lookup also has its own finite network, referral
and nameserver dependency budgets. A supporting lookup can make more than one
wire exchange; the 64 validation-lookups bound is not a promise of 64 packets.

Learn uses its separate bounded worker pool and queue. Configuration accepts
at most 64 workers and 16384 queued observations; defaults remain two workers
and 256 queued observations. Dropped observations/writes and native admission
failures are visible counters with different meanings. Live validation failure
affects DNS availability; Learn observation loss affects sample completeness.

## Scope and remaining evidence

Native transport is plaintext authoritative DNS. Configured DoH/DoT forwarders
do not encrypt it. QNAME minimisation reduces name disclosure but does not
encrypt packets. Native conditional forwarding, private trust zones and split
DNS forwarding are not provided by this implementation. A deployment that
requires a private forwarder must explicitly select Learn or Off for now.

The local statistical learner can collect bounded behavioural baselines and
raise findings. It cannot replace DNSSEC proof, add a trust anchor, train a
signature verifier or turn an Indeterminate/Bogus result into Secure.

Deterministic tests cover real signed native answers, flag combinations,
forged same-packet alias targets, DNAME synthesis, unsigned aliases leading to
bogus signed targets, negative SOA tampering, direct DNSKEY queries, signature
TTL/expiry, anchor withdrawal, cache-mode separation, capacity, timeouts and
panic containment. They establish specific regression properties. They do
not establish weeks of successful service, target-device capacity, public-DNS
coverage, independent security review or rollover behaviour under real-world
timing. Those evidence gaps remain tracked by
[issue #67](https://github.com/jameshoulder/dnsdaddy/issues/67) and the
[validation-lab limitations](../daddybound/validation-lab.md).
