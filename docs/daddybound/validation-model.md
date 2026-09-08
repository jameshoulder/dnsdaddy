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

**Assumed:** that the configured anchors are the right ones. Daddybound never
fetches an anchor, never follows RFC 5011 rollover, and never promotes an
observed DNSKEY into a trust anchor. Anchors are code and configuration,
reviewed as changes.

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
while the DS is absent is a contradiction and produces Bogus.

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
sent. Daddybound does not resolve; it validates what it is handed.

## 5. What the four states mean here

| State | Reached when |
| --- | --- |
| **Secure** | A chain from a configured anchor to the RRset, every signature verified. Or: an authenticated denial establishing the claimed absence. |
| **Insecure** | One route only — an authenticated denial at a delegation showing NS present and DS absent. |
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

## 8. What would change these lists

- A recursive resolver of its own would move §4's "assumed" line: Daddybound
  would then know it saw what the authoritative servers sent.
- CNAME, DNAME and ANY validation would each add a proof obligation that is
  currently a refusal to conclude.
- Real signed zones, signed by signers other than this repository's, would test
  §3 and §4 against chains nobody here designed.
