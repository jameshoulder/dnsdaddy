# The Daddybound validation laboratory

## What it is

A complete, signed DNS hierarchy built in memory, and fifteen named ways of
breaking it. It never touches the network, and the same hierarchy can be
served over real DNS so that a reference validator sees exactly the records
Daddybound validated.

```
.                                signed; the trust anchor
  dnsdaddylab.                   delegated with a DS
    example.dnsdaddylab.         delegated with a DS
      www.example.dnsdaddylab.   A 192.0.2.1
```

Three zones is the smallest hierarchy that exercises everything a chain walk
does more than once: two delegations, so a bug that only works for the first
DS is caught, and an answer below a zone apex rather than at it.

## Choices that were not cosmetic

**The name.** `.dnsdaddylab` is not delegated anywhere and has no special-use
registration. An earlier experiment used `.test`, which RFC 6761 §6.2
reserves, and libunbound answered NXDOMAIN for it without querying anything —
the harness looked broken when it was the name that was wrong.

**Ed25519 by default.** It signs deterministically, so a rebuilt hierarchy is
byte-identical down to the signatures. That is what makes a stored signed
message usable as a fixture rather than merely re-generated. Keys derive from
a seed, so the same specification always produces the same key tags. Both
properties are pinned by tests.

**One key per zone, with both the zone and SEP bits set.** A legal
configuration, and a deliberate one: a validator that quietly assumes the
KSK/ZSK split — SEP key signs the DNSKEY RRset, non-SEP key signs everything
else — passes against a two-key laboratory and fails against real single-key
zones. RFC 4034 §2.1.1 forbids branching on the SEP bit at all, and this setup
catches an implementation that does on the first run.

**Signing goes through `github.com/miekg/dns`, not through Daddybound.** This
is the important one. Signing with the code under test would make every
signature verify by construction: a canonicalisation bug would cancel out, the
suite would pass, and the signatures would be ones no other implementation
accepts. Using an independent implementation to sign means Daddybound's
verifier is checked against someone else's reading of RFC 4034 §6 on every
run. The same reasoning applies to the DS digests.

## The scenarios

Each mutation breaks exactly one thing. A scenario that broke two would still
fail, and nobody would notice when one of the two checks stopped working.

| Scenario | Expected | What it would mean if it passed wrongly |
| --- | --- | --- |
| `valid` | Secure | Without it, every other scenario is passed by a validator that never returns Secure |
| `tampered-answer` | Bogus | An on-path attacker rewriting an address. The attack DNSSEC exists to stop |
| `corrupt-signature` | Bogus | One flipped bit, reaching the arithmetic rather than a length check |
| `expired-signature` | Bogus | A replay of data that was once genuine |
| `not-yet-valid-signature` | Bogus | The other boundary, easy to omit because well-run zones never hit it |
| `missing-signature` | Bogus | An absent signature treated as an absent objection |
| `malformed-signature` | Bogus | The parsing path, which hostile input reaches before any check |
| `ds-digest-mismatch` | Bogus | The parent names this key and disagrees about its contents: a substituted key |
| `missing-dnskey` | Bogus | A secure delegation to a zone with no keys |
| `rogue-key-appended` | Bogus | **The P0 case.** A key added to an authenticated apex RRset without re-signing it |
| `foreign-zone-signature` | Bogus | A cryptographically perfect signature made by the wrong authority |
| `unsupported-algorithm` | Indeterminate | Must not be Bogus: the data may be perfect and the validator cannot check it |
| `disallowed-algorithm` | Indeterminate | Must not be Bogus: that would blame the zone for the operator's policy |
| `unsupported-ds-digest` | Indeterminate | RFC 6840 §5.2, same shape |
| `no-trust-anchor` | Indeterminate | Anything else here is invented trust |

`dnsdaddy daddybound scenarios` prints this list with each justification.

### The one worth reading twice

`rogue-key-appended` adds a perfectly good zone key — right flags, right
protocol, supported algorithm, and it genuinely produced the signature on the
answer — to the leaf zone's apex DNSKEY RRset, and leaves the RRset's own
signature in place so it no longer covers the modified set.

A validator that trusts every key in an apex RRset because one of them matched
a DS accepts this. That is a false Secure, and it is why the chain walk checks
the apex DNSKEY RRset's own signature (RFC 4035 §5.2) rather than treating a
DS match as blanket authorisation for the set.

## Non-vacuity

A test that passes for the wrong reason is worse than no test: it reports
safety it is not measuring. Every security property here was checked by
reverting it and confirming that the right scenario — and only the right
scenario — fails.

| Property reverted | Scenario that failed |
| --- | --- |
| Trust every key in an apex RRset without checking its signature | `rogue-key-appended` |
| Drop the signer-is-the-zone rule (R-SIG-02) | `foreign-zone-signature` |
| Skip the DS digest comparison | `ds-digest-mismatch` |
| Drop the inception and expiration checks | `expired-signature`, `not-yet-valid-signature` |
| Use the received TTL instead of the RRSIG's Original TTL | the canonical-form TTL test |
| Remove the RDATA down-casing call from canonical form | *nothing* — see below |
| Fail the chain when the zone budget truncates it | the limits test |

The sixth row is the reason this table exists. Removing the RDATA down-casing
call broke no test at all: the type-list test called the function directly and
never established that anything used it. There is now a test that fails
without the call, and a counterpart pinning SVCB *outside* RFC 4034 §6.2's
enumeration, since inventing membership would produce signed data no signer
ever signed.

## Differential comparison

The same fifteen scenarios run through Daddybound and through libunbound,
both reading the same served hierarchy — not two separately constructed copies
of "the same" zone, because a differential comparison against a separate copy
makes every disagreement ambiguous.

```
CGO_ENABLED=1 go test -tags daddybound_unbound ./internal/daddybound/differential/
```

Without the tag, the test skips. libunbound is an oracle, never a backend, and
no build this project ships can link it.

### Result classes

| Class | Meaning |
| --- | --- |
| `MATCH` | Same status |
| `FALSE_SECURE` | Reference says Bogus, Daddybound says Secure. **P0** |
| `FALSE_BOGUS` | Reference says Secure, Daddybound says Bogus |
| `STATUS_DISAGREEMENT` | Any other difference |
| `KNOWN_GAP` | A disagreement a scenario predicted and justified in writing |
| `REFERENCE_ERROR` | The oracle could not answer. Never counted as agreement |
| `DADDYBOUND_ERROR` | Daddybound produced no result, panic included |

`FALSE_SECURE` is tested first and unconditionally. A known-gap annotation can
rebut a false-Bogus classification — that presumes the oracle is right, and a
citation can rebut the presumption — but it can never rebut a false Secure,
because `Classify` has already returned by then.

### Current result

**Twelve match, three known gaps, zero false secures.**

libunbound reports an unresolved verdict — neither secure nor bogus — for both
RFC 4033's Insecure and its Indeterminate, and cannot say which it meant. The
comparator records that and treats Daddybound's Indeterminate as consistent
with it, because it is: calling that a disagreement would be inventing
evidence the oracle never gave.

### The three gaps

Two are v0.1 admitting it cannot reach Insecure without denial proofs:
`unsupported-algorithm` and `unsupported-ds-digest`, where RFC 6840 §5.3 and
§5.2 say the zone is treated as unsigned. `disallowed-algorithm` is the
oracle applying its own algorithm policy, which it is entitled to do.

The third is the interesting one. On `foreign-zone-signature`, libunbound says
Secure and Daddybound says Bogus.

RFC 4035 §5.3.1 is unambiguous: "The RRSIG RR's Signer's Name field MUST be
the name of the zone that contains the RRset." In this hierarchy
`example.dnsdaddylab.` *is* a zone, delegated with a DS, so an answer inside it
signed by `dnsdaddylab.` violates the rule.

A forwarder cannot establish that zone cut for itself. It takes the zone from
the answer's own signer name — which is the field under attack. Daddybound's
chain walk crosses the delegation and therefore knows better. The disagreement
is a property of how the oracle is configured, not a defect in either
validator, and it is recorded on the scenario with that reasoning attached.

This is what the standards gate is for. The first instinct on seeing a
disagreement with a twenty-year-old validator is to assume the new code is
wrong. Here the RFC settles it, and the rule identifier made it a five-minute
argument rather than a judgement call.

## What the fuzzers cover

Three targets, on the three places attacker-chosen bytes arrive first:
canonical signed-data construction, the RFC 3110 length-prefixed RSA key
decoder, and validation of an arbitrary wire response. Roughly 1.3 million
executions, no crashes.

The third asserts more than "does not panic" — a validator returning Secure
for everything would pass that. Its trust anchor's digest is thirty-two zero
octets, so no DNSKEY can match it and nothing the fuzzer produces may
validate. A Secure verdict there is a forged chain of trust and fails the run.

## What this evidence does not cover

- Fifteen hand-built scenarios against one oracle in one configuration. Not a
  corpus of real signed zones, and not a second independent oracle.
- One algorithm end to end. Ed25519 signs every laboratory zone; RSA and ECDSA
  verification paths are exercised by unit tests and by the relabelling
  scenarios, not by a full signed chain.
- No NSEC or NSEC3, so nothing here says anything about denial of existence.
- No real Internet zone has ever been validated by this engine.
