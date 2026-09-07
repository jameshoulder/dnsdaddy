# The Daddybound validation laboratory

## What it is

A complete, signed DNS hierarchy built in memory, and a set of named ways of
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
| `multi-record-rrset` | Secure | RFC 4034 §6.3 orders an RRset by RDATA, not record length. The MX preferences make the two orders genuinely differ, so a length-based sort declares this correctly signed RRset Bogus |
| `tampered-answer` | Bogus | An on-path attacker rewriting an address. The attack DNSSEC exists to stop |
| `corrupt-signature` | Bogus | One flipped bit, reaching the arithmetic rather than a length check |
| `expired-signature` | Bogus | A replay of data that was once genuine |
| `not-yet-valid-signature` | Bogus | The other boundary, easy to omit because well-run zones never hit it |
| `missing-signature` | Bogus | An absent signature treated as an absent objection |
| `malformed-signature` | Bogus | The parsing path, which hostile input reaches before any check |
| `stripped-signature-unsupported-algorithm` | Bogus | The downgrade attack: the real signature stripped and one naming an unverifiable algorithm left behind. Reporting the validator's own inability would make forged data Indeterminate |
| `stripped-signature-disallowed-algorithm` | Bogus | The same attack with an algorithm policy refuses. Neither capability nor policy may soften a missing signature |
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
| Sort canonical form by packed record instead of RDATA | `multi-record-rrset`, and six of six MX orderings |
| Drop RFC 6840 §5.12's disregard of foreign-algorithm RRSIGs | both `stripped-signature-*` scenarios, and the monotonicity property |
| Skip RFC 6840 §5.2's DS partition | the unusable-digest permutation case |
| Combine failure reasons by position instead of rank | the signature-permutation reason assertion |
| Naive int64 comparison of DNSSEC timestamps | four serial-arithmetic cases, including a signature straddling 2106 |
| Unpin the oracle's clock | three of four time-travel cases |
| Infer an unconfigured policy from map length | the explicitly-empty policy case |
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

The scenarios run through Daddybound and through **two independent reference
validators**, all reading the same served hierarchy — not separately
constructed copies of "the same" zone, because that makes every disagreement
ambiguous.

| Oracle | Version | How it resolves | Clock |
| --- | --- | --- | --- |
| libunbound (NLnet Labs) | 1.19.2 | forwarder | pinned via `val-override-date` |
| `delv` (ISC BIND) | 9.18.39 | own chain walk | wall clock, so fixtures are shifted to surround the run |

```
CGO_ENABLED=1 go test -tags daddybound_unbound ./internal/daddybound/differential/
```

Without the tag the libunbound test skips; without `delv` on PATH the BIND
test skips. Both are oracles, never backends, and no build this project ships
can link or invoke either.

A second oracle is worth more than a second opinion. One reference tells you
whether Daddybound agrees with that implementation. Two independent ones tell
you whether a disagreement is about Daddybound or about a quirk of how the
first is configured — and that distinction has already overturned a conclusion
here. See "the disputed case" below.

### The time model

Daddybound takes its notion of the current time from an injected clock,
because RFC 4035 §5.3.1 phrases both validity checks against "the validator's
notion of the current time". A reference validator on the wall clock is
answering a different question, and signature validity is exactly where that
bites.

Review caught this before it bit. The fixtures expire on 2027-01-01, and from
that date libunbound would have called the `valid` scenario expired while
Daddybound validated it at its June 2026 clock — a permanent `FALSE_SECURE`
in CI produced by nothing but the date the job ran.

Moving the expiry would have deferred the problem. Two mechanisms remove it:

- **libunbound is pinned** to the scenario's instant with `val-override-date`,
  and the adapter refuses to build without one rather than defaulting to
  `time.Now()` and quietly reintroducing the dependence.
- **delv has no clock override**, so instead the *fixtures* move:
  `lab.Scenario.Shifted` rebuilds the same zones, keys and mutations with
  every validity window and the validation instant moved by one offset. The
  scenario is identical in every other respect, so a disagreement remains a
  disagreement about validation.

`TestBothValidatorsJudgeSignaturesAtTheScenarioTime` walks the window's
boundaries deliberately — before inception, after expiration, fifty years
after — and asserts both validators agree at each. Unpinning the oracle fails
three of its four cases *today*, rather than silently on a future date.

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
citation can rebut the presumption — but never a false Secure, because
`Classify` has already returned by then.

A scenario may also declare `NoOracle`, which is not the same as a known gap.
A known gap is a disagreement with a reason; `NoOracle` is the *absence of a
question* — `no-trust-anchor` narrows Daddybound's own anchor set and asks
about a name the hierarchy does not serve, so there is nothing for another
validator to agree or disagree with. Comparing anyway would produce a
reference error that then had to be excused, and excusing reference errors is
how a comparison suite stops meaning anything.

### Current result

**Zero false secures against either oracle.** Of the eighteen scenarios, one
is not comparable and the rest match both references except for the
documented gaps below.

Both oracles report an unresolved verdict — neither secure nor bogus — for
RFC 4033's Insecure and its Indeterminate alike, and cannot say which they
meant. The comparator records that and treats Daddybound's Indeterminate as
consistent with it, because it is: calling that a disagreement would be
inventing evidence the oracle never gave.

### The documented gaps

Two are v0.1 admitting it cannot reach Insecure without denial proofs:
`unsupported-algorithm` and `unsupported-ds-digest`, where RFC 6840 §5.3 and
§5.2 say the zone is treated as unsigned. `disallowed-algorithm` is an oracle
applying its own algorithm policy, which it is entitled to do.

### The disputed case, and how a second oracle changed the answer

On `foreign-zone-signature` both libunbound and delv say Secure; Daddybound
says Bogus. **This is recorded as an open question, not as a Daddybound
correctness win.** The earlier version of this document claimed the latter,
and was wrong.

The scenario: `www.example.dnsdaddylab. A`, which lives in the zone
`example.dnsdaddylab.` (apex SOA, NS and DNSKEY, delegated from
`dnsdaddylab.` with a DS), is re-signed with `dnsdaddylab.`'s key, so the
RRSIG's signer name is the *parent* rather than the containing zone.

The first explanation was that libunbound, running as a forwarder, cannot
establish zone cuts for itself. The queries it made say exactly that — it
asked for `./DNSKEY`, `dnsdaddylab./DS` and `dnsdaddylab./DNSKEY`, and never
asked for `example.dnsdaddylab./DS` at all:

```
www.example.dnsdaddylab.  A       -> NOERROR (2 records)
.                         DNSKEY  -> NOERROR (2 records)
dnsdaddylab.              DS      -> NOERROR (2 records)
dnsdaddylab.              DNSKEY  -> NOERROR (2 records)
```

That explanation does not survive the second oracle. `delv` performs its own
chain walk and *does* fetch `example.dnsdaddylab/DS` in the `valid`
scenario — its trace shows the full descent — yet it still accepts the
ancestor-signed answer here. Both validators take the containing zone from
the RRSIG's signer name rather than re-deriving the cut for every RRset.

So the positions are:

- **For Daddybound's refusal.** RFC 4035 §5.3.1: "The RRSIG RR's Signer's Name
  field MUST be the name of the zone that contains the RRset." Here that zone
  is `example.dnsdaddylab.`, and it is not the signer.
- **Against it.** The ancestor already publishes the child's DS, so it can
  take the child over simply by replacing the delegation. Accepting its
  signature grants it no authority it does not already hold — a plausible
  reason two mature implementations do not spend a query checking.

Daddybound keeps the strict reading, because it errs towards refusal and
cannot produce a false Secure. But two independent implementations disagreeing
is evidence, and the honest classification is unresolved. No legitimate zone
configuration has yet been constructed in which Daddybound's strictness causes
a false Bogus; if one is, the strict reading should be revisited.

The query log that produced the evidence above is part of the lab server
(`Server.Queries`), because "what does this validator know about zone cuts" is
otherwise a matter of opinion, and the only way to settle it is to look at
what was actually asked.

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

- Eighteen hand-built scenarios against two oracles. Better than one, and
  still not a corpus of real signed zones — the scenarios are ones we thought
  of.
- One algorithm end to end. Ed25519 signs every laboratory zone; RSA and ECDSA
  verification paths are exercised by unit tests and by the relabelling
  scenarios, not by a full signed chain.
- No NSEC or NSEC3, so nothing here says anything about denial of existence.
- No real Internet zone has ever been validated by this engine.
