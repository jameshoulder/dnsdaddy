# Daddybound: what it proves, and what it assumes

This document separates the two. Everything in the first list is established by
evidence Daddybound checked; everything in the second is something it takes to
be true without having checked it. The value of the split is that it makes the
second list short enough to argue about.

It is written **after** the denial-of-existence milestone rather than before it.
That ordering is worth stating: the milestone brief asked for this document as a
gate, and writing it afterwards means it describes the engine as built rather
than as intended. Where the two would have differed, a note says so.

## 1. The trust anchor

**Proved:** nothing. A trust anchor is an axiom.

**Assumed:** that the configured anchors are the right ones, and that a key
those anchors later attest to is one the zone's operators meant to publish.

Daddybound never fetches an anchor and never promotes an observed DNSKEY into a
trust anchor on its own word. It does follow RFC 5011 rollover, which is a
narrower thing: a key becomes an anchor only after appearing, continuously for
thirty days, in DNSKEY RRsets signed by a key that was already an anchor. The
compiled-in digests are the root of that and are never discarded. So the
assumption moves from "these anchors" to "these anchors, and whatever they
attest to for thirty uninterrupted days" — which is the window the zone's
operators have to notice a key they did not publish.

A validator with no anchor covering a name returns Indeterminate with
`no_trust_anchor`, which RFC 4033 §5 calls the default operation mode. It does
not guess.

## 2. From the anchor to a zone's keys

**Proved:**

- Some DNSKEY in the zone's apex RRset matches a configured anchor by key tag,
  algorithm and digest (`R-KEY-*`, `R-DS-*`).
- That key's signature over the whole apex DNSKEY RRset verifies. This is the
  step that turns *one* vouched-for key into a trusted key set, and skipping it
  is what lets an attacker append their own key to a legitimate RRset.

**Assumed:** that the cryptographic primitives are sound. Signature arithmetic
comes from Go's `crypto` packages; Daddybound implements none of it.

## 3. Crossing a delegation

**Proved, when a DS RRset is present:** that the DS is signed by the parent's
trusted keys, that it names a key in the child's apex DNSKEY RRset by tag and
algorithm, and that the digest recomputes. Unusable digest types are partitioned
out *before* the RRset is evaluated (RFC 6840 §5.2), so the outcome is a
property of the set rather than of the order it arrived in.

**Proved, when no DS RRset is present and the response carries a denial:** which
of the two possible situations holds. An authenticated record at the cut with NS
set and DS clear is an insecure delegation and produces **Insecure**. Neither
bit set means the name is not a zone cut and the walk continues. The DS bit set
while the DS is absent is a contradiction and produces Bogus. A response whose
rcode is NXDOMAIN establishes no delegation at all, whatever its records say —
a delegation is a name that exists (`R-DEN-13`, `R-N3-12`).

**Assumed, when no DS RRset is present and no denial is supplied:** that the
name is not a zone cut. This is the one substantive assumption left in the walk,
and it is deliberately one-sided — see standards.md §5.5. It can cost a false
Bogus. It cannot manufacture a false Secure, because concluding Secure needs a
signature from a key set this walk has already authenticated, and an attacker
below an insecure delegation does not have one.

## 4. The answer

**Proved for a positive answer:** that the records form one RRset (RFC 2181 §5),
that some RRSIG over it is admissible under RFC 4035 §5.3.1, and that it
verifies against a key in the apex DNSKEY RRset of *the zone the walk is
standing in*.

That last clause is stricter than two reference validators, and the difference
is measured rather than argued: they take the containing zone from the RRSIG's
signer name, which determines where they look and so prevents them from
discovering the cut at all. standards.md §5.8 has the query logs.

**Proved for a wildcard-expanded answer:** additionally, that the name the
wildcard stood in for does not exist (`R-DEN-11`, `R-N3-09`). Without it, one
signed wildcard answer is replayable over every name under its encloser.

**Proved for an absent answer:** that the response's own claim is supported by
authenticated denial records — a name error needs the name covered *and* the
wildcard covered; a NODATA needs the matching record to omit both the queried
type and CNAME. The records must verify; receiving them proves nothing.

**Assumed:** that the Source returned what an authoritative server would have
sent.

Where Daddybound resolves for itself — native mode, and the shadow path in
Learn — it *is* what handed itself the records, having read them from the
authoritative servers, and internal/daddybound/native pins the per-hop replies
so the message validated is the message returned. Where it reads through a
forwarder, it validates what it is handed and can say nothing about the path
those records took.

## 4a. A chain of answers

A CNAME or DNAME answer is not one RRset but a sequence, and what Secure means
for it has to be stated rather than inherited.

**Proved for each hop:** everything in §4, from the trust anchor down — the
target's own chain, not the previous hop's. A target may sit in another zone,
under another anchor, or below a delegation the first name never crossed.

**Proved for the chain:** that its verdict is the weakest of its hops, in the
order Bogus, Indeterminate, Insecure, Secure. That the chain is bounded, by a
hop count and by a visited set, and that reaching either bound is Indeterminate
rather than an accusation.

**Proved for a DNAME:** that the DNAME RRset itself authenticates, and that the
redirection was recomputed from its owner and target. The synthesised CNAME is
never read (RFC 6672 §5.3.1 requires it to be unsigned), so editing it, removing
it or signing it changes nothing — asserted by a test that requires the verdict
to be *identical* in each case rather than merely non-Secure.

**Not proved, for QTYPE=\*:** that the answer is complete. RFC 1034 §6.2.2 lets
a server return a subset of the records at a name and RFC 6840 §4.2 says a
validator must not expect otherwise, so Secure for an ANY query means "every
RRset that arrived is authentic" and says nothing about the ones that did not.
An ANY answer that is *empty* under NOERROR is not provable at all — no type
bitmap can deny type 255 — and is Indeterminate.

**Assumed:** nothing further. In particular the chain's verdict is not the
first hop's and not the last: a signed alias into an unsigned zone is Insecure
however well signed its destination is.

## 5. What the four states mean here

| State | Reached when |
| --- | --- |
| **Secure** | A chain from a configured anchor to the RRset, every signature verified. Or: an authenticated denial establishing the claimed absence. |
| **Insecure** | Two routes, both of them proofs — an authenticated denial at a delegation showing NS present and DS absent, or an authenticated NSEC3 Opt-Out span, within which RFC 5155 §12.2 says non-existence cannot be proved and §7.1 says only unsigned names may be omitted. |
| **Bogus** | A secure delegation was established and the response failed to validate. Never reached before a delegation is established. |
| **Indeterminate** | No anchor covers the name; or a limit was hit; or the answer depends on something this build cannot evaluate. Never a soft yes and never a soft no. |

Insecure is the one worth restating in the negative, because every wrong
implementation of it is a downgrade. It is **not**: a missing signature, an
unsupported algorithm, a policy refusal, a failed validation, an unexpectedly
absent DNSKEY, a timeout, malformed DNSSEC records, an NSEC3 iteration count
above the budget, or "we could not prove Secure". Each of those is Bogus or
Indeterminate.

## 6. Bounded work

Every input arrives from the network, so every loop over one is a loop an
adversary chooses the length of. Chain depth, lookups, signatures per RRset,
keys per zone, denial RRsets per response, NSEC3 iterations per record and
total hash computations per validation are all bounded.

The denial-record bound has a second job beyond stopping the work. Reaching it
must not be reported as a fault in the zone, or a response padded until the
real proof falls off the end would come back Bogus — handing an attacker a way
to fail validation for any name at all. So a proof cut short reports
`resource_limit`, while a contradiction found in a record that *was* read still
stands: padding can hide a proof, and must not be able to hide a lie. Hitting a bound produces Indeterminate with
`resource_limit`: stopping early is not evidence about the data, and answering
Secure after giving up would turn a denial of service into a forgery.

## 7. Enforcement

Daddybound decides nothing for any client. `internal/resolver` and the packages
on the query path cannot import it, and Daddybound cannot import them; both
directions are asserted by a test over the module's import graph rather than
promised in prose. The CLI subcommands build a hierarchy in memory and cannot be
pointed at the Internet.

This is structural, not a setting. It stays that way until the false-Secure
evidence is much stronger than one laboratory and two oracles can make it.

## 8. Measured cost

The bounds in §6 are worth a number as well as an argument. One validation, on
four cores of a 2.8 GHz Xeon, walking the whole chain from the anchor with
nothing cached:

| Shape | Time | Allocated |
| --- | --- | --- |
| signed positive answer | 0.54 ms | 20 KB |
| NSEC name error | 0.84 ms | 111 KB |
| NSEC3 name error | 0.88 ms | 72 KB |
| CNAME chain, three hops | 2.28 ms | 88 KB |
| DNAME redirection | 1.21 ms | 44 KB |
| NSEC3 at the iteration ceiling | 1.29 ms | 100 KB |
| authority section padded past the budget | 3.20 ms | 199 KB |

The last row is the worst an attacker can construct: admissible signatures, so
every padded record reaches the verifier before failing, placed ahead of the
genuine proof so the budget is spent burying it. Its pair — the same padding
*after* a valid proof — still validates, so an answer cannot be denied by
appending to it.

These are not optimisation targets and they are pessimistic: a resolver caches
the DNSKEY and DS records that dominate them. They exist to answer one
question, which is whether a structure the sender chooses can make the work
grow without bound. Reproduce with `go test ./internal/daddybound/dnssec/
-run '^$' -bench . -benchmem`.

## 9. What would change these lists

- A recursive resolver of its own would move §4's "assumed" line: Daddybound
  would then know it saw what the authoritative servers sent.
- Aggressive use of NSEC and NSEC3 (RFC 8198) would let a proof answer a
  question that was not asked, which is a new proof obligation rather than a
  new capability.
- More real signed zones. The live corpus put several hundred names signed by
  people outside this repository through §3, §4 and §4a, and found a defect in
  §4's denial reasoning that no laboratory scenario could have reached — a
  name error whose closest encloser is the root. A larger corpus would test
  more of the same kind.
