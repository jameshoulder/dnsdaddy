# Daddybound roadmap

Each step lists what it unblocks, because the ordering is a dependency graph
rather than a wish list. Nothing here is a commitment to a date.

## Where the engine stands

Daddybound walks a chain of trust to a signed answer, validates authenticated
denial of existence with NSEC and NSEC3, and reaches all four of RFC 4033's
states. It is honest about everything it cannot do; the list below is what
remains.

## Done: denial of existence (NSEC, NSEC3)

Implemented, with the rules recorded as `R-DEN-01`..`R-DEN-12` and
`R-N3-01`..`R-N3-11` in [standards.md](standards.md) §4.7 and §4.8. What it
unblocked:

- **Insecure is reachable**, and only ever by proving something: an
  authenticated denial record at a delegation showing NS present and DS
  absent, or an authenticated Opt-Out span, within which RFC 5155 §12.2 says
  non-existence cannot be proved and every name is unsigned.
- **The zone-cut ambiguity is closed where a proof is supplied.** A walk that
  finds no DS now reads the parent's signed record instead of assuming. One
  case remains: a response that supplies no proof either way, where the walk
  still assumes "not a zone cut" — an assumption that can only cost a false
  Bogus. See standards.md §5.5.

What it did **not** unblock, contrary to the expectation recorded here before
the work was done:

- **RFC 6840 §5.2 and §5.3 are still not implemented as written.** Both end in
  "the zone is treated as if it were unsigned", and reaching Insecure was
  assumed to be the blocker. It was not. Insecure is a claim that a proof was
  offered, and for an unsupported algorithm or an uncomputable digest no proof
  was offered — the records are present and this build cannot read them.
  Reporting Insecure there would say the parent asserted something it did not,
  and would let an attacker downgrade a zone by publishing a delegation this
  validator cannot evaluate. Daddybound reports Indeterminate with the specific
  reason instead, and standards.md §5.3 now records that as a decision rather
  than a gap.

## Done: aliases and ANY

Implemented, with the rules recorded as `R-ALIAS-01`..`R-ALIAS-07`,
`R-DNAME-01`..`R-DNAME-07` and `R-ANY-01`..`R-ANY-04` in
[standards.md](standards.md) §4.9–§4.11. What it unblocked, and what it
exposed:

- **A chain has a verdict of its own**, the weakest of its hops, and neither
  the first hop's classification nor the last is inherited.
- **The owner-name rule turned out to be a rule**, not one function.
  Aliases make multi-owner answer sections normal, and taking records by
  *type* alone was a false Secure needing no forgery. Fixing it for answers
  left the same hole on the delegation walk, which the live corpus then found.
- **QTYPE=\* was a false Secure.** Type 255 matches no record and appears in
  no type bitmap, so the ordinary answer filter and the ordinary NODATA rule
  are both vacuous for it — and vacuous together they authenticate an absence
  the zone never asserted.

## Done: validating real Internet zones

**Unblocked:** the single largest increase in evidence available.

`make corpus` puts several hundred real names to Daddybound, libunbound and
delv over a public recursive resolver. It found two defects on its first runs,
both in shapes no laboratory scenario reached. See
[validation-lab.md](validation-lab.md).

The corpus harness reads records through a public resolver, so it exercises
the validator on a forwarder's view. Native recursion, below, is what Learn
mode now runs on.

## Done: recursive resolution

**Unblocked:** knowing that what was validated is what the authoritative
servers sent.

`internal/daddybound/recursive` walks from the root hints to the authoritative
servers, and `internal/daddybound/native` hands the validator the exact
replies that walk pinned — so the message validated is the message resolved,
with no second fetch for the two to disagree about. Zone cuts are established
from referrals actually followed, which closes the zone-cut assumption on this
path; reading through a forwarder, which cannot see the path, the one-sided
assumption remains and is measured by a property test. Learn mode drives this
engine for every observed name.

## Done: RFC 5011 trust anchor rollover

**Unblocked:** running against the root without manual intervention when the
root key rolls.

`internal/daddybound/trustanchors` maintains the trust point: a key the zone
announces in a validly signed DNSKEY RRset enters the thirty-day add hold-down
and becomes an anchor after it, a self-signed REVOKE withdraws one, and a
trust point whose every key has been revoked is kept and marked as needing an
operator rather than deleted — so verdicts become Indeterminate, never
Insecure. The compiled-in IANA digests seed the state and are never discarded.
State persists in `daddybound-anchors.json`; `GET /api/v1/dnssec/status`
reports each key's state, the refresh schedule and whether the file is being
written.

## Then: transports

QNAME minimisation (RFC 9156) is in the native resolver. DNS over TLS (RFC
7858), DNS over HTTPS (RFC 8484) and DNS over QUIC (RFC 9250) are not, because
authoritative servers do not offer them: native recursion speaks plaintext
port 53, and the status page says so. Should authoritative encrypted transport
become deployable, it sits behind the `Exchanger` interface and changes nothing
above it.

## Next: aggressive use of NSEC (RFC 8198)

Aggressive negative caching remains unimplemented. Native Live now returns
RFC 8914 Extended DNS Errors for validation and operational failures; clients
without EDNS still receive the corresponding failure RCODE.

## Then: SVCB and HTTPS records (RFC 9460, RFC 9462)

Note the canonicalisation consequence already handled: SVCB is *not* in
RFC 4034 §6.2's enumeration of types whose RDATA names are down-cased, and a
test pins that. Adding support for the type must not change it.

## Much later: ENS and Ethereum naming, DNSSEC ↔ ENS ownership proofs, CCIP Read

Out of scope for the foreseeable milestones and listed only so the boundary is
explicit. Nothing in the engine anticipates them.

## Implemented: experimental native Live

[ADR 0003](../decisions/0003-daddybound-native-live.md) defines the actual
client-answer path. Native Live authenticates exact projected data with
cryptographic receipts, validates signed targets even after an unsigned alias,
caps signature TTLs and returns explicit SERVFAIL for Bogus, Indeterminate and
operational failures. It honors CD/DO/AD, keeps forwarding caches out of the
native trust path and bounds concurrency, recursion and validation work.

Fresh installations select Forward (`off`). Existing recorded modes, including
Live, and explicit configuration choices are preserved. Learn observations remain independent of
forwarded answers; Live observations identify the native result actually used.

## Remaining: operational readiness and private-zone routing

Implementing Live does not close the evidence gate in
[issue #67](https://github.com/jameshoulder/dnsdaddy/issues/67). The previously
recorded laboratory/corpus counts and short Learn run are historical samples,
not a longitudinal Live deployment or an independent security review.

Still needed: extended field time and volume, investigation of disagreements,
clock and rollover events under realistic concurrency, explicit target-device
CPU/memory/latency measurements and wider public-DNS coverage. Deterministic
adversarial client tests now protect specific packet-binding and resource
properties; they do not supply those missing denominators.

Native conditional forwarding and private trust-zone routing are also future
work. Deployments relying on private split-DNS forwarders must currently use
Forward or Learn. Unsupported-policy cases deliberately fail closed and can have
different availability behavior from other validators; see standards.md §5.3.
