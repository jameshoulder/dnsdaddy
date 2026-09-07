# Daddybound roadmap

Each step lists what it unblocks, because the ordering is a dependency graph
rather than a wish list. Nothing here is a commitment to a date.

## Where v0.1 leaves off

v0.1 walks a chain of trust to a signed answer and is honest about everything
it cannot do. The largest single gap is denial of existence, and it is the
gap that blocks most of the rest.

## Next: denial of existence (NSEC, NSEC3)

**Unblocks:** the Insecure status, and with it every rule that currently
terminates in Indeterminate because it cannot be reached honestly.

Three things become correct rather than approximate:

- **Insecure becomes reachable.** RFC 4033's Insecure requires signed proof
  that no DS exists. Today Daddybound returns Indeterminate wherever a
  complete validator would say Insecure, which is a weaker claim and a true
  one — but it is a limitation, not a design.
- **RFC 6840 §5.2 and §5.3 become implementable.** Both end in "the zone is
  treated as if it were unsigned", which is Insecure. Daddybound cannot claim
  to implement either until it can reach that status. See
  [standards.md](standards.md) §5.3.
- **The zone-cut ambiguity closes.** A chain walk that finds no DS at a name
  cannot tell "not a zone cut" from "insecure delegation" without a proof.
  v0.1 assumes the first, which can only cost a false Bogus — never a false
  Secure — and records every place it assumed. See standards.md §5.5.

Also needed for authenticated NXDOMAIN and NODATA, and for wildcard denial.

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

Both depend on denial of existence. RFC 8914 in particular would let Daddybound
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
cover". In short: fifteen hand-built scenarios, one oracle, one configuration,
one algorithm end to end, and no real zone ever validated. That is enough to
justify continuing. It is nowhere near enough to enforce anything.
