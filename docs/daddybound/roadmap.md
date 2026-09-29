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

## Then: aggressive use of NSEC (RFC 8198), extended DNS errors (RFC 8914)

Both depended on denial of existence, which now exists. RFC 8914 in particular would let Daddybound
report its typed reasons over the wire rather than only in a trace.

## Then: SVCB and HTTPS records (RFC 9460, RFC 9462)

Note the canonicalisation consequence already handled: SVCB is *not* in
RFC 4034 §6.2's enumeration of types whose RDATA names are down-cased, and a
test pins that. Adding support for the type must not change it.

## Much later: ENS and Ethereum naming, DNSSEC ↔ ENS ownership proofs, CCIP Read

Out of scope for the foreseeable milestones and listed only so the boundary is
explicit. Nothing in the engine anticipates them.

## The question that gates enforcement

None of the above is what stands between Daddybound and being DNS Daddy's
validator. That gate is evidence, not features:

> What evidence do we have that Daddybound can be trusted, and what evidence
> is still missing before it could enforce DNSSEC for a real deployment?

The current answer is in [validation-lab.md](validation-lab.md) under "What
this evidence does not cover". In short: 78 laboratory scenarios and 612 live
questions, both against two independent oracles, five signature algorithms end
to end, zero false Secures, and two real defects found by the corpus that the
laboratory could not have reached.

That is a great deal more than the milestone before it, and it is still not
enough to enforce anything. What is missing is not a number of scenarios. It
is that Daddybound has never resolved a name for itself, has been compared
against one resolver's view of the DNS, and has not been run anywhere for long
enough for the failure modes that only appear over time — a key rollover
mid-query, a zone that re-signs while a chain is being walked — to have shown
up at all.

Observe mode now exists: the engine runs alongside the resolver on real
traffic, deciding nothing. The first run of it, over 612 real names, produced
the thing no test could — 609 verdicts about names nobody chose, four
disagreements with the upstream, and none of them in the cell that matters
(upstream validated, local bogus).

What is still missing before enforcement is time and volume rather than
features, plus a decided answer to what a client should receive when
validation fails. See issue #63 and its successor.
