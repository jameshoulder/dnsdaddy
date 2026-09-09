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

There are **77**, and the authoritative list is the code rather than this
document: `dnsdaddy daddybound scenarios` prints every one with the
justification attached to it. A scenario nobody can justify is a scenario
nobody will maintain, so the justification is a field on the scenario and not
a comment near it.

| Family | Count | What it exercises |
| --- | --- | --- |
| `positive` | 10 | Correctly signed data that must validate — including one hierarchy per signature algorithm. Without these, every negative scenario is passed by a validator that never returns Secure |
| `chain-failure` | 19 | Broken or forged chains: signatures, keys, delegation records, algorithm policy |
| `nsec` | 18 | Authenticated denial with NSEC |
| `nsec3` | 16 | The same questions asked of an NSEC3-signed hierarchy |
| `alias` | 14 | CNAME chains and DNAME redirections, including the ones that cross a zone cut or a change in security status |
| `configuration` | 1 | A property of Daddybound's own configuration rather than of any data |

By expected verdict: 38 Bogus, 28 Secure, 7 Indeterminate, 5 Insecure. The
mixture matters as much as the count — a suite of only negatives is passed by
a validator that rejects everything, and a suite of only positives by one that
accepts everything.

Seven scenarios carry a `KnownGap`: a disagreement with a reference validator
that is predicted and argued from the RFC, never "the other implementation
says otherwise". Three carry a `NoOracle`: there is no question to put to
another validator, because the property is about Daddybound's own
configuration or about a behaviour the standards leave to local policy. A
known gap can never absorb a false Secure — the comparator checks for that
class first, and returns before it reaches the annotation.

The ones worth reading are below.

| Scenario | Expected | What it would mean if it passed wrongly |
| --- | --- | --- |
| `rogue-key-appended` | Bogus | **The P0 case.** A key added to an authenticated apex RRset without re-signing it |
| `foreign-zone-signature` | Bogus | A cryptographically perfect signature made by the wrong authority |
| `ancestor-nsec-denying-the-childs-own-data` | Bogus | A parent's genuine delegation NSEC reused to hide an entire signed zone. Every signature verifies |
| `stripped-signature-unsupported-algorithm` | Bogus | The downgrade attack: the real signature stripped and one naming an unverifiable algorithm left behind, so the failure reads as the validator's own inability |
| `nodata-hiding-a-cname` | Bogus | RFC 6840 §4.3: a positive CNAME answer turned into a NOERROR/NODATA by deleting the CNAME. The NSEC's own CNAME bit is what catches it |
| `nxdomain-at-the-root` | Secure | Every query for a top-level domain that does not exist. Building the wildcard name by concatenation gives `*..`, and the proof can never complete |
| `cname-into-an-insecure-zone` | Insecure | A signed alias whose destination is unsigned. Inheriting the first hop's Secure would authenticate an attacker's choice of destination |
| `cname-chain-longer-than-the-hop-limit` | Indeterminate | Reaching a budget is not evidence about the data. Bogus here accuses a deeply aliased zone of forgery |
| `any-answer-with-a-tampered-rrset` | Bogus | RFC 6840 §4.2. Type 255 matches no record, so the ordinary path never looks at the answer at all |
| `unsupported-algorithm` | Indeterminate | Must not be Bogus: the data may be perfect and the validator cannot check it |
| `no-trust-anchor` | Indeterminate | Anything else here is invented trust |

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
| Take the queried *type* from an answer section without checking the owner | the answer-owner test, both halves |
| Take the queried type from a DS or DNSKEY response without checking the owner | the delegation-owner test — and *not* the substitution half of it, which the DS digest already caught |
| Build the root's wildcard by concatenation (`"*." + "."`) | `nxdomain-at-the-root`, and the root name-error unit test |
| Read the synthesised CNAME in a DNAME response instead of the DNAME | every `dname-*` scenario, and the synthesis test |
| Route QTYPE=\* through the ordinary answer path | the empty-ANY test, both tamper tests, and the ANY ordering test |
| Take the first status marker delv prints instead of the weakest | four of the twelve delv-parser cases |
| Try alias hops without a visited set or a hop cap | `cname-loop`, `cname-chain-longer-than-the-hop-limit` |
| Let the good signature be tried before the broken one | *nothing* — see below |

Two rows are the reason this table exists, and they are the two that say
*nothing*.

Removing the RDATA down-casing call broke no test at all: the type-list test
called the function directly and never established that anything used it.
There is now a test that fails without the call, and a counterpart pinning
SVCB *outside* RFC 4034 §6.2's enumeration, since inventing membership would
produce signed data no signer ever signed.

The last row is the same failure in a fixture rather than in a test. The
rollover scenario adds a broken signature alongside a good one to check that a
validator continues past a failure — and the validator sorts signatures
deterministically, so the good one was tried first and the broken one never
touched. The scenario passed while testing nothing, and the result looked
identical either way. It was caught by reading the trace rather than the
verdict; the fixture now forces the broken signature to the front of that
order.

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

**Zero false secures against either oracle**, across 78 laboratory scenarios
and 612 live questions. Three scenarios are not comparable at all, eight carry
a documented gap, and the rest match both references.

`rollover-two-signatures-one-broken` is the one of those three worth naming
here, because it is the only place where the two oracles disagree with each
other about correctly signed data. RFC 4035 §5.3.3 leaves conflict resolution
between multiple RRSIGs to "local resolver security policy"; RFC 6840 §5.4
recommends accepting any valid one, which libunbound does and Daddybound
follows, and warns that a stricter resolver "is also vulnerable to malicious
insertion of gibberish signatures", which is what delv's rejection here
demonstrates. Comparing it would file a policy choice as a false Secure, and
that class must never be manufactured or it stops meaning what it says. The
behaviour is pinned by a unit test instead, and the companion scenario with
nothing valid in it stays fully comparable — both oracles reject that one.

Both oracles report an unresolved verdict — neither secure nor bogus — for
RFC 4033's Insecure and its Indeterminate alike, and cannot say which they
meant. The comparator records that and treats Daddybound's Indeterminate as
consistent with it, because it is: calling that a disagreement would be
inventing evidence the oracle never gave.

### The documented gaps

Two are places where RFC 6840 §5.3 and §5.2 end in "treated as if it were
unsigned" — RFC 4033's Insecure — and Daddybound reports Indeterminate instead:
`unsupported-algorithm` and `unsupported-ds-digest`. That is no longer a
missing capability; denial proofs exist. It is a distinction. Insecure is a
claim that the parent proved no DS exists, and here the DS records are present
and this build cannot evaluate them, which is a fact about the build. Saying
Insecure would report a proof nobody offered, and would let an attacker
downgrade a zone by publishing a delegation this validator cannot read.

`disallowed-algorithm` is an oracle applying its own algorithm policy, which it
is entitled to do: RFC 9905 §2 tells implementations to keep validating RSASHA1
and operators to treat it as unsupported, and the two sides of the comparison
are built to different sentences of the same paragraph.

Two more are denial divergences argued out in `standards.md` §5.6 and §5.7: an
NXDOMAIN forged over an empty non-terminal, where libunbound repairs the
response code and Daddybound — which returns a verdict and not an answer — can
only refuse; and a DS query answered through NSEC3 opt-out, where delv agrees
with Daddybound and libunbound does not.

The eighth is the mirror of that last one, and the only gap where the two
oracles disagree with each other about a denial rather than about policy:
`nsec3-opt-out-span-cannot-prove-a-name-error`. libunbound reports insecure,
delv reports a fully validated name error, and they do so on the live Internet
as readily as on the fixture — darkegy.cam does not exist and .cam signs with
opt-out. Daddybound reports insecure because RFC 5155 §12.2 says non-existence
inside an opt-out span is not provable, which is `R-N3-13` in `standards.md`.
Agreeing with libunbound is a consequence of following that sentence, not the
reason for it.

### The disputed case, and how a second oracle changed the answer

On `foreign-zone-signature` both libunbound and delv say Secure; Daddybound
says Bogus. This was carried as an open question for two milestones and has
now been settled by measurement rather than argument — see `standards.md` §5.8.
The lab records what each validator asks, and delv never asks about the zone
cut it is accepting across: it follows the RRSIG's signer name upwards and
therefore never discovers that the name lies below a delegation. Daddybound
descends the delegations instead, so it has the evidence delv does not. It is
still not a vulnerability in delv, for the reason §5.8 gives.

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

## The real-world corpus

The laboratory establishes that Daddybound reads the standards the way two
other implementations do, on data built to make each rule reachable. What it
cannot establish is that the rules are the right *set* — that no shape
occurring in the wild falls outside every scenario anyone thought to write.
Only real names can answer that, because nobody has to think of them.

`make corpus` puts 612 questions to Daddybound, libunbound and delv over a
public recursive resolver. Two disciplines make the answer worth having, and
both are about the corpus rather than the code.

**The names are not chosen by verdict.** 277 come from the Tranco top-1M,
sampled by rank arithmetic across four bands — nothing inspected before
inclusion, nothing removed after — with query types spread over them and a
`www.` label added to some, which is where CNAMEs live. The rest are named for
a DNSSEC *shape* a ranked sample reaches only by luck: the signed root and TLD
apexes, NSEC versus NSEC3 versus NSEC3 opt-out, DS present and DS absent,
NXDOMAIN and NODATA under signed and unsigned parents, and the well-known
deliberately-broken zones. A majority of the sampled names are unsigned, and
that is the point — an unsigned zone under a signed TLD is the commonest shape
in the DNS, it must come out Insecure rather than Bogus, and a corpus of only
signed names would never test it.

**No expected verdict is stored.** The oracles produce them at run time. A
file of expectations would date the moment a zone re-signed, and worse, would
let a Daddybound change be "confirmed" by editing the file.

It is opt-in and not in CI. It needs the network, a public resolver, both
oracles and several minutes, and its result depends on the state of zones
nobody here controls — every one of which is a reason it must not gate a pull
request. A job that goes red because someone else let a signature expire
teaches contributors to re-run red builds, which costs far more than the run
is worth.

Two things the harness has to get right, both learned the hard way on the
first run:

- **A disagreement is asked again, once, serially, before it is recorded.**
  Not to make failures go away — a second run that agrees is recorded as it
  stands, and a genuine false Secure reproduces every time. It is to stop the
  network being read as a verdict: under concurrency an oracle that loses a
  packet mid-chain prints words indistinguishable from a real refusal. delv
  says "broken trust chain resolving 'org/DS/IN'" whether the DS is missing or
  the query was dropped. The first run produced a FALSE_SECURE against
  iana.org that validates cleanly the moment it is asked on its own.
- **Root anchors are read from the system's managed root key file**, not
  written into source. The root has two KSKs published today and will have one
  again; a hard-coded anchor keeps working right up until the day it silently
  reports the entire Internet Bogus.

### What the first two runs found

FALSE_SECURE was **0** against both oracles on both runs. Everything else was
a finding to investigate individually:

| Defect | Direction | Why the laboratory missed it |
| --- | --- | --- |
| `wildcardAt(".")` built `"*.."` by concatenation, so the wildcard half of a name-error proof could never be satisfied when the closest encloser is the root | false Bogus on every query for a TLD that does not exist | a lab hierarchy delegates out of the root immediately, so no scenario in it ever has the root as a closest encloser |
| DS and DNSKEY records were taken from a response without checking their owner name | false Bogus on three names, all of the shape `www.X` aliased to `X`, where the resolver answered a DS query with the apex's DS | the lab's Source answers exactly the question asked; a real resolver helpfully sends context |

Both are now laboratory scenarios as well, so the shapes are reachable
offline from here on. Neither could have produced a false Secure — the second
is provably one-directional, because RFC 4034 §5.1.4 computes a DS digest over
the DNSKEY's owner name — but a validator that cries wolf gets turned off, and
a validator that is turned off protects nobody.

The remaining divergences are mostly Daddybound reporting Indeterminate
(`cancelled`) where an oracle reported Bogus with "timed out resolving": the
network under four concurrent workers and a delv process per question, not a
reading of the data.

## What the fuzzers cover

Four targets, on the places attacker-chosen bytes arrive first: canonical
signed-data construction, the RFC 3110 length-prefixed RSA key decoder,
validation of an arbitrary wire response, and — since a CNAME or DNAME answer
lets the sender choose where the walk goes next — an arbitrary answer section
injected at one link of a chain. Roughly 3 million executions, no crashes, no
hangs.

The third asserts more than "does not panic" — a validator returning Secure
for everything would pass that. Its trust anchor's digest is thirty-two zero
octets, so no DNSKEY can match it and nothing the fuzzer produces may
validate. A Secure verdict there is a forged chain of trust and fails the run.

## What this evidence does not cover

- The laboratory scenarios are still ones we thought of. The corpus is the
  answer to that and it is a partial one: several hundred names is a sample of
  the DNS, not a survey of it.
- Zones signed by this repository's own signer. Every laboratory zone is
  signed by code in `internal/daddybound/lab`; real zones are signed by BIND,
  Knot, OpenDNSSEC and PowerDNS, and the corpus reaches those only through
  whatever the sampled names happen to use.
- One NSEC3 hash algorithm and a narrow iteration regime per hierarchy. The
  parameter space a real validator meets is wider than the scenarios cover,
  and the corpus samples it rather than enumerating it.
- Aggressive use of NSEC and NSEC3 (RFC 8198), RFC 5011 rollover, and
  recursive resolution: not implemented, so not tested.
- The corpus runs against one public resolver's view. A resolver that
  minimised qnames differently, or cached differently, would hand Daddybound a
  different set of responses for the same names.
