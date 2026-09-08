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

- **Insecure is reachable**, by exactly one route: an authenticated denial
  record at a delegation showing NS present and DS absent.
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

## Next: the denial surface that is still missing

**Unblocks:** validating the response shapes a real resolver meets daily.

- **CNAME chasing.** A NODATA proof checks the CNAME bit and refuses to
  conclude when it is set (`R-DEN-03`), which is correct but is not the same as
  following the alias and validating what it points at.
- **DNAME (RFC 6672).** Same shape: `R-DEN-07` refuses to let an NSEC with the
  DNAME bit deny anything beneath it, and nothing follows the redirection.
- **ANY queries (RFC 6840 §4.2).** QTYPE=* has its own validation rules.

## Then: recursive resolution

**Unblocks:** validating a name that exists on the real Internet.

Today Daddybound validates records it is given. A recursive resolver of its
own would let it discover them, and would strengthen one rule that is
currently weaker than it should be: R-SIG-02's check that the signer's name is
the zone containing the RRset is enforced strictly by the chain walk, and only
loosely by `rrsigAdmissible` on its own, because learning zone cuts needs
resolution.

It would also let the differential comparison run against real signed zones
rather than only a laboratory — which is the single largest increase in
evidence available, and is called out as such in the trust assessment.

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

The current answer is in the pull request that introduced v0.1 and in
[validation-lab.md](validation-lab.md) under "What this evidence does not
cover". In short: eighteen hand-built scenarios, two oracles, one algorithm
end to end, and no real zone ever validated. That is enough to justify
continuing. It is nowhere near enough to enforce anything.
