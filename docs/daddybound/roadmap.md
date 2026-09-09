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

This is not recursion. Daddybound still validates records something else
supplies; the harness supplies them from a resolver rather than from memory.

## Next: recursive resolution

**Unblocks:** knowing that what was validated is what the authoritative
servers sent.

A recursive resolver of its own would let Daddybound discover records rather
than be handed them, and would strengthen one rule that is currently weaker
than it should be: R-SIG-02's check that the signer's name is the zone
containing the RRset is enforced strictly by the chain walk, and only loosely
by `rrsigAdmissible` on its own, because learning zone cuts needs resolution.

It would also close the last zone-cut assumption. Where a delegation response
supplies no proof either way, the walk assumes the name is not a zone cut —
one-sided, costing a false Bogus and never a false Secure, and measured as
such by a property test.

## Then: RFC 5011 trust anchor rollover

**Unblocks:** running against the root without manual intervention when the
root key rolls.

Trust anchors are configuration today. The DNSKEY revoke bit is observed and
reported and deliberately not acted on: honouring revocation without the rest
of RFC 5011 implements half a protocol whose other half provides the safety.

## Then: transports

DNS over TLS (RFC 7858), DNS over HTTPS (RFC 8484), DNS over QUIC (RFC 9250),
and QNAME minimisation (RFC 9156). These are properties of how records are
fetched rather than of how they are validated, so they sit behind the `Source`
interface and change nothing above it.

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

The next milestone is observe mode: run the engine alongside the resolver, on
real traffic, deciding nothing. That measures the one thing no test can, which
is what it says about names nobody chose.
