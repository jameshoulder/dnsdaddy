# Daddybound: standards research

Daddybound implements DNS and DNSSEC trust logic from first principles. That
only means anything if the logic is derived from the standards rather than from
another implementation's behaviour. This document is the record of that
derivation: which documents were read, what they were read for, and which
sentence in which section each implemented rule comes from.

It exists so that a disagreement between Daddybound and a mature validator can
be settled by argument from the standard, not by assuming the mature validator
is right. When Daddybound and a reference validator disagree, this document is
where the investigation starts.

**Read date for every source below: 7 September 2026**, except RFC 5155,
RFC 9276 and RFC 4592, added for the denial-of-existence milestone and read on
8 September 2026. Registries change; the IANA tables reproduced here are
snapshots, and §6 says what happens when they move.

## 1. How each source was verified

Three levels are used, and the level is stated for every document. Nothing is
promoted a level because it was "obviously" fine.

| Level | Meaning |
| --- | --- |
| **Verified** | The RFC or registry was fetched from the authoritative publisher and the specific normative sentences Daddybound implements were read in the original text. Quotations below are from that text. |
| **Consulted** | Fetched and read for scope and terminology, but Daddybound implements nothing that depends on its detail, so no rule below cites it as authority. |
| **Scoped only** | Named in the roadmap, not read for the milestone that introduced the row. Nothing in Daddybound may depend on it. |

Authoritative publishers used: `rfc-editor.org` for RFC text, `iana.org` for
registries. No mirror, no summary site, and no other implementation's
documentation was used as the authority for any rule below.

One source was re-read from the raw text after an initial summary looked
self-contradictory — see §5.4. That is the intended failure mode of this
process working.

## 2. Documents

### Verified

| Document | Read for |
| --- | --- |
| RFC 4033 — DNS Security Introduction and Requirements | The four validation states and their exact definitions |
| RFC 4034 — Resource Records for the DNS Security Extensions | RRSIG/DNSKEY/DS wire formats, canonical form and ordering, signed-data construction, key tag |
| RFC 4035 — Protocol Modifications for the DNS Security Extensions | The conditions under which an RRset is authenticated |
| RFC 6840 — Clarifications and Implementation Notes for DNSSEC | Unsupported algorithm and digest handling, multiple RRSIGs, the SEP bit |
| RFC 9905 — Deprecating the Use of SHA-1 in DNSSEC Signature Algorithms | Why implementation support and policy permission are different questions |
| RFC 2181 — Clarifications to the DNS Specification | What an RRset is, and the TTL rule inside one |
| RFC 5155 — DNS Security (DNSSEC) Hashed Authenticated Denial of Existence | NSEC3 hashing, the closest encloser proof, opt-out, and the validator rules in §8 |
| RFC 9276 — Guidance for NSEC3 Parameter Settings | What iteration counts a validator should accept, and why treating a high count as insecure is the wrong refusal |
| RFC 4592 — The Role of Wildcards in the Domain Name System | Closest encloser, and which names a wildcard can and cannot synthesise |
| IANA "DNS Security Algorithm Numbers" | The algorithm registry Daddybound's tables must agree with |
| IANA "Digest Algorithms" (DS RR) | The DS digest registry Daddybound's tables must agree with |

### Consulted

| Document | Why it is not load-bearing |
| --- | --- |
| RFC 1034, RFC 1035 | Daddybound uses `github.com/miekg/dns` for wire parsing and packing. Daddybound implements no message parser of its own, so the base specification informs terminology only. |
| RFC 9904 | Restructures the DNSSEC registries into the "Use for" / "Implement for" columns reproduced in §6. Daddybound reads the registries; it does not implement this document. |

### Scoped only — nothing in Daddybound depends on these

RFC 6891 (EDNS(0)), RFC 7766 (DNS over TCP), RFC 8198 (aggressive NSEC use),
RFC 8914 (extended DNS errors), RFC 7858 (DNS over TLS), RFC 8484 (DNS over
HTTPS), RFC 9156 (QNAME minimisation), RFC 9250 (DNS over QUIC), RFC 9460
(SVCB/HTTPS records), RFC 9462 (discovery of designated resolvers), RFC 5011
(automated trust anchor updates).

RFC 5155 was on this list until the denial-of-existence milestone and has been promoted to Verified for the
denial-of-existence milestone. It is named here as well so the move is visible
rather than silent.

These are the v0.2+ surface. They are listed so the boundary is explicit: if
Daddybound ever appears to implement one of them, either this list is wrong or
the implementation is not derived from anything.

## 3. Validation states (RFC 4033 §5, RFC 4035 §4.3)

Daddybound's `ValidationStatus` is these four states and nothing else. The
definitions are quoted rather than paraphrased because the difference between
Insecure and Indeterminate is exactly the kind of thing a paraphrase loses.

RFC 4033 §5:

> **Secure:** The validating resolver has a trust anchor, has a chain of trust,
> and is able to verify all the signatures in the response.
>
> **Insecure:** The validating resolver has a trust anchor, a chain of trust,
> and, at some delegation point, signed proof of the non-existence of a DS
> record.
>
> **Bogus:** The validating resolver has a trust anchor and a secure delegation
> indicating that subsidiary data is signed, but the response fails to validate
> for some reason: missing signatures, expired signatures, signatures with
> unsupported algorithms, data missing that the relevant NSEC RR says should be
> present, and so forth.
>
> **Indeterminate:** There is no trust anchor that would indicate that a
> specific portion of the tree is secure. This is the default operation mode.

Two consequences, both of which constrain what Daddybound is allowed to
return:

- **Insecure requires signed proof.** RFC 4033's Insecure is not "we did not
  find a signature". It is "we proved, with a signature, that no DS exists".
  Daddybound now implements those proofs (§4.7 for NSEC, §4.8 for NSEC3), and
  exactly one code path returns Insecure: the delegation step, and only when
  an authenticated denial record at the cut has NS set and DS clear. It is not
  returned for a missing signature, an unsupported algorithm, a failed
  validation, an absent DNSKEY, a timeout, malformed records, or any other
  flavour of "we could not prove Secure". Each of those is Bogus or
  Indeterminate. Where a delegation supplies no proof either way, the walk
  assumes the name is not a zone cut and continues — a one-sided assumption
  that can cost a false Bogus and cannot manufacture a false Secure. §5.5 has
  the argument.
- **Bogus requires a secure delegation.** Returning Bogus for a name Daddybound
  never established a secure delegation to would be a fabricated verdict. The
  chain walk therefore tracks whether it is still under a secure delegation,
  and a failure above that point is Indeterminate.

## 4. Rules Daddybound implements

Each rule has a stable identifier. Code that enforces a rule cites the
identifier, so the implementation and this document can be checked against each
other by grep.

### 4.1 RRSIG validity (RFC 4035 §5.3.1)

RFC 4035 §5.3.1 lists the conditions under which an RRset can be authenticated
by an RRSIG. All of the following must hold.

| ID | Rule | Source text |
| --- | --- | --- |
| `R-SIG-01` | Same owner name and class | "The RRSIG RR and the RRset MUST have the same owner name and the same class." |
| `R-SIG-02` | Signer's Name is the zone containing the RRset | "The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset." |
| `R-SIG-03` | Type Covered equals the RRset type | "The RRSIG RR's Type Covered field MUST equal the RRset's type." |
| `R-SIG-04` | Owner label count ≥ RRSIG Labels field | "The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field." |
| `R-SIG-05` | Not expired | "The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field." |
| `R-SIG-06` | Not yet-to-come | "The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field." |
| `R-SIG-07` | Signer's Name, Algorithm and Key Tag select a key in the apex DNSKEY RRset | "The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset." |
| `R-SIG-08` | That key has the Zone flag set | "The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set." |
| `R-SIG-09` | The cryptographic signature verifies over the canonical signed data | RFC 4034 §3.1.8.1, see `R-CANON-*` |

`R-SIG-05` and `R-SIG-06` are the reason Daddybound takes an injectable clock.
A validator whose notion of the current time cannot be controlled cannot be
tested for either boundary, and both boundaries are inclusive per the quoted
text.

`R-SIG-07` selects a *set* of candidate keys, not a single key. The key tag is a
16-bit checksum, not an identifier: two DNSKEYs in one RRset can share a tag.
Daddybound therefore tries every DNSKEY matching name, algorithm and tag, and
only concludes failure when all of them fail. RFC 4034 Appendix B describes the
tag as computed from the RDATA, with no uniqueness claim attached.

### 4.2 Multiple RRSIGs (RFC 6840 §5.4)

| ID | Rule | Source text |
| --- | --- | --- |
| `R-SIG-10` | Any one valid RRSIG authenticates the RRset; Bogus only when all fail | "a resolver SHOULD accept any valid RRSIG as sufficient, and only determine that an RRset is Bogus if all RRSIGs fail validation." |

This is a security-relevant asymmetry and it is easy to get backwards. The
tempting implementation — fail the RRset on the first RRSIG that does not
verify — is wrong, and wrong in the *safe* direction (false BOGUS). The
opposite error, accepting an RRset because one RRSIG merely existed, is the
P0 direction. Daddybound's step trace records the outcome of every RRSIG
considered, so which of the two happened is visible after the fact.

### 4.3 DNSKEY (RFC 4034 §2.1.1, §2.1.2; RFC 6840 §5.10)

| ID | Rule | Source text |
| --- | --- | --- |
| `R-KEY-01` | Protocol field must be 3 | "The Protocol Field MUST have value 3, and the DNSKEY RR MUST be treated as invalid during signature verification if it is found to be some value other than 3." |
| `R-KEY-02` | Zone flag is bit 7 and is required for a zone-signing key | "Bit 7 of the Flags field is the Zone Key flag" (RFC 4034 §2.1.1); required by `R-SIG-08` |
| `R-KEY-03` | The SEP bit must not change validation behaviour | "validators MUST NOT alter their behavior during the signature validation process in any way based on the setting of this bit." (RFC 4034 §2.1.1); RFC 6840 §5.10: "the SEP bit setting has no effect on how a DNSKEY may be used—the validation process is specifically prohibited from using that bit." |

`R-KEY-03` is worth stating as a rule precisely because "KSK signs the DNSKEY
RRset, ZSK signs everything else" is such a common description of how DNSSEC
works operationally. It is a convention of zone signing, not a validation rule,
and a validator that enforces it rejects valid zones. Daddybound records the
SEP bit in its trace as an observation and never branches on it.

### 4.4 Delegation Signer (RFC 4034 §5.1, §5.1.4)

| ID | Rule | Source text |
| --- | --- | --- |
| `R-DS-01` | DS RDATA is Key Tag (2), Algorithm (1), Digest Type (1), Digest (variable) | RFC 4034 §5.1 |
| `R-DS-02` | `digest = digest_algorithm( DNSKEY owner name \| DNSKEY RDATA )`, DNSKEY RDATA being `Flags \| Protocol \| Algorithm \| Public Key`, owner name in canonical form | RFC 4034 §5.1.4 |
| `R-DS-03` | A DS matches a DNSKEY only when key tag, algorithm and the recomputed digest all agree | Follows from `R-DS-02`: the tag and algorithm select candidates, the digest decides |

The digest is computed over the canonical owner name — down-cased, uncompressed
— and not over whatever casing arrived on the wire. A validator that digests
the wire-form name fails against any resolver that randomises query case, which
is the majority of them. This is called out because it is a defect that only
appears against real traffic and not against a lab that echoes case exactly.

### 4.5 Canonical form and signed data (RFC 4034 §3.1.8.1, §6)

| ID | Rule | Source text |
| --- | --- | --- |
| `R-CANON-01` | `signature = sign(RRSIG_RDATA \| RR(1) \| RR(2)...)`, where RRSIG_RDATA is the RRSIG RDATA with the signature field omitted | RFC 4034 §3.1.8.1: "signature = sign(RRSIG_RDATA \| RR(1) \| RR(2)... ) where \"\|\" denotes concatenation" |
| `R-CANON-02` | Each RR contributes owner name, type, class, **the RRSIG's Original TTL**, RDLENGTH and RDATA | RFC 4034 §3.1.8.1 and §6.2 |
| `R-CANON-03` | Owner names are fully expanded, uncompressed and down-cased | RFC 4034 §6.2 |
| `R-CANON-04` | Domain names inside RDATA are down-cased for the specific RR types the RFC enumerates, and only those | RFC 4034 §6.2 |
| `R-CANON-04a` | That list is corrected by RFC 6840 §5.1: HINFO is removed, NSEC is removed, RRSIG is kept | RFC 6840 §5.1 |
| `R-CANON-05` | RRs within the RRset are sorted by treating RDATA as unsigned octet sequences | RFC 4034 §6.3: "RRs with identical owner, class, and type sort by treating RDATA as unsigned octet sequences." |
| `R-CANON-06` | A wildcard owner appears in its original unexpanded form | RFC 4034 §6.2 |

`R-CANON-02` is the one that produces silent, total failure when missed: the
TTL in the signed data is the RRSIG's Original TTL field, not the TTL the RR
arrived with. Because caching decrements TTLs, an implementation that uses the
received TTL verifies correctly at the instant of signing and fails a second
later, which reads like a flaky network rather than a bug.

`R-CANON-04` is the one that produces *selective* failure — most of a zone
validates and one record type does not. The set of types whose RDATA names are
down-cased is enumerated rather than described, and has not grown with newer RR
types: treating it as "any name-shaped field" breaks types added after RFC 4034
(SVCB and HTTPS being the obvious modern cases), and treating it as "none"
breaks NS, SOA, MX and the rest.

`R-CANON-04a` is the reason reading only RFC 4034 is not enough here. Its
enumeration is wrong in two places, and RFC 6840 §5.1 corrects both:

> When canonicalizing DNS names (for both ordering and signing), DNS names in
> the RDATA section of NSEC resource records are not converted to lowercase.
> DNS names in the RDATA section of RRSIG resource records are converted to
> lowercase.

and

> Section 6.2 of [RFC4034] also erroneously lists HINFO as a record that needs
> conversion to lowercase, and twice at that. Since HINFO records contain no
> domain names, they are not subject to case conversion.

RFC 6840 is explicit that neither predecessor matches deployment — "Current
practice follows neither document fully" — RFC 4034 having said to down-case
both NSEC and RRSIG, and RFC 3755 having said to down-case neither. An
implementation that follows RFC 4034 literally declares correctly signed zones
Bogus, in the *unsafe*-to-operators but safe-to-security direction. Daddybound
implements the corrected list.

Daddybound writes this list out itself rather than delegating it, because it is
trust logic — it decides what bytes a signature covers — and only the
mechanical packing underneath it comes from `github.com/miekg/dns`. The
canonicalisation tests assert the resulting *bytes* against these rules rather
than asserting that a library was called, so a library upgrade that changed
canonical packing fails them. A test that only checked the call happened would
not.

Canonicalisation is Daddybound's trusted computing base. Every verdict is a
statement about bytes produced here; if these bytes are wrong, every downstream
check is answering the wrong question and answering it confidently.

### 4.6 What an RRset is (RFC 2181 §5)

| ID | Rule | Source text |
| --- | --- | --- |
| `R-SET-01` | An RRset is all records sharing owner name, class and type | RFC 2181 §5 |
| `R-SET-02` | TTLs within an RRset must be equal; differing TTLs are deprecated and a receiver treats them all as the lowest | RFC 2181 §5.2: "the TTLs of all RRs in an RRSet must be the same", and the use of differing TTLs "is hereby deprecated" |

`R-SET-02` does not affect the signed data — `R-CANON-02` substitutes the
Original TTL regardless — but it does affect grouping. Daddybound groups
strictly by (name, class, type) and never by TTL, so a response with
inconsistent TTLs forms one RRset and is verified as one, which is what a
signer signed.

### 4.7 Authenticated denial of existence: NSEC (RFC 4035 §5.4, RFC 6840 §4)

RFC 4035 §5.4 is the base rule and RFC 6840 §4 exists because, in its own
words, that section "under-specifies the algorithm for checking nonexistence
proofs". Both are load-bearing here; implementing §5.4 alone produces a
validator an attacker can walk straight through.

| ID | Rule | Source text |
| --- | --- | --- |
| `R-DEN-01` | Every NSEC RRset used in a proof must itself be authenticated by the chain of trust before anything is concluded from it | RFC 4035 §5.4: "security-aware resolvers MUST authenticate the NSEC RRsets that comprise the non-existence proof as described in Section 5.3" |
| `R-DEN-02` | NODATA: an authenticated NSEC whose owner *matches* the queried name proves the type is absent when the type bit is clear in its bitmap | RFC 4035 §5.4: "If the requested RR name matches the owner name of an authenticated NSEC RR, then the NSEC RR's type bit map field lists all RR types present at that owner name, and a resolver can prove that the requested RR type does not exist by checking for the RR type in the bit map" |
| `R-DEN-03` | NODATA: the CNAME bit must also be clear in that same bitmap | RFC 6840 §4.3: "validators MUST check the CNAME bit in the matching NSEC or NSEC3 RR's type bitmap in addition to the bit for the query type" |
| `R-DEN-04` | NXDOMAIN: an authenticated NSEC must *cover* the queried name — strictly between its owner and its Next Domain Name in canonical order | RFC 4035 §5.4: "If the requested RR name would appear after an authenticated NSEC RR's owner name and before the name listed in that NSEC RR's Next Domain Name field according to the canonical DNS name order defined in [RFC4034], then no RRsets with the requested name exist in the zone" |
| `R-DEN-05` | NXDOMAIN: a second proof is required, that no wildcard could have answered | RFC 4035 §5.4: "it is possible that a wildcard could be used to match the requested RR owner name and type, so proving that the requested RRset does not exist also requires proving that no possible wildcard RRset exists that could have been used to generate a positive response" |
| `R-DEN-06` | An **ancestor delegation NSEC** — NS bit set, SOA bit clear, and a signer field shorter than the owner name — must not be used to deny anything below that cut, nor any non-DS type at the owner itself | RFC 6840 §4.1: "Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume nonexistence of any RRs below that zone cut, which include all RRs at that (original) owner name other than DS RRs, and all RRs below that owner name regardless of type" |
| `R-DEN-07` | An NSEC with the DNAME bit set must not be used to deny any subdomain of its owner | RFC 6840 §4.1: "An NSEC or NSEC3 RR with the DNAME bit set MUST NOT be used to assume the nonexistence of any subdomain of that NSEC/NSEC3 RR's (original) owner name" |
| `R-DEN-08` | Insecure delegation: the matching NSEC must have DS clear, SOA clear **and NS set** | RFC 4035 §5.2 requires the absence of DS; RFC 6840 §4.4: "The validator also MUST check for the presence of the NS bit in the matching NSEC (or NSEC3) RR (proving that there is, indeed, a delegation)" |
| `R-DEN-09` | A DS non-existence proof must come from the parent side of the cut, which is the NSEC with the SOA bit clear | RFC 4035 §5.2: "The parent NSEC RR and child NSEC RR can always be distinguished because the SOA bit will be set in the child NSEC RR and clear in the parent NSEC RR. A security-aware resolver MUST use the parent NSEC RR when attempting to prove that a DS RRset does not exist" |
| `R-DEN-10` | The NSEC and RRSIG bits in a bitmap say nothing; a validated NSEC proves both records exist regardless | RFC 4035 §5.4: "Since a validated NSEC RR proves the existence of both itself and its corresponding RRSIG RR, a validator MUST ignore the settings of the NSEC and RRSIG bits in an NSEC RR" |
| `R-DEN-11` | A positive answer whose owner has more labels than its RRSIG's Labels field was wildcard-expanded, and needs its own denial proof that no closer match existed | RFC 4035 §5.3.4: "If the number of labels in an RRset's owner name is greater than the Labels field of the covering RRSIG RR, then the RRset and its covering RRSIG RR were created as a result of wildcard expansion ... it must take additional steps to verify the non-existence of an exact match or closer wildcard match for the query" |
| `R-DEN-12` | The work spent on a proof is bounded, and hitting the bound is not a verdict | RFC 4035 §5.4: "As with all DNS operations, however, the resolver MUST bound the work it puts into answering any particular query" |

Two of these deserve more than a table row.

**`R-DEN-06` is the rule that makes the difference between a proof and a
coincidence.** Every zone cut has two NSEC records at the same owner name: one
published by the parent, describing the delegation, and one published by the
child, describing its apex. Without the ancestor-delegation restriction, a
validator will happily accept the parent's NSEC — which it can authenticate,
because the parent is inside the chain of trust — as proof that a name inside
the child does not exist. The parent has no authority over that name and never
made that claim. The signature is genuine; the conclusion is invented.

**`R-DEN-05` is the rule that is easiest to leave out and hardest to notice.**
A response that proves only that `nope.example.` is missing has not proved
NXDOMAIN, because `*.example.` may exist and would have answered. A validator
that stops after the first covering NSEC accepts a forged NXDOMAIN for every
name in every wildcard-bearing zone.

The closest encloser is what connects the two proofs. Given an authenticated
NSEC covering QNAME, its owner and its Next Domain Name both exist, so every
ancestor of each of them exists too — an ancestor of an existing name is at
worst an empty non-terminal, which still exists. The deepest ancestor QNAME
shares with either of them is therefore the deepest ancestor of QNAME that is
known to exist, and the wildcard that has to be denied is the asterisk label
prepended to it. RFC 4592 §3.3.1 defines the closest encloser, and RFC 5155
§1.3 restates it as "the longest existing ancestor of a name".

### 4.8 Authenticated denial of existence: NSEC3 (RFC 5155, RFC 9276)

NSEC3 replaces *the name sorts between these two names* with *the hash of the
name sorts between these two hashes*, and everything else follows from that
one substitution — including the parts that do not survive it.

| ID | Rule | Source text |
| --- | --- | --- |
| `R-N3-01` | NSEC3 RRs with an unknown hash algorithm are ignored | RFC 5155 §8.1: "A validator MUST ignore NSEC3 RRs with unknown hash types" |
| `R-N3-02` | NSEC3 RRs with a Flags value other than 0 or 1 are ignored | RFC 5155 §8.2: "A validator MUST ignore NSEC3 RRs with a Flag fields value other than zero or one" |
| `R-N3-03` | Closest encloser proof: the longest ancestor X of QNAME matched by an NSEC3, whose next closer name is covered by an NSEC3 | RFC 5155 §8.3, reproduced in full below |
| `R-N3-04` | The NSEC3 matching the closest encloser must be from the right zone: DNAME clear, and NS set only if SOA is set | RFC 5155 §8.3: "The DNAME type bit must not be set and the NS type bit may only be set if the SOA type bit is set. If this is not the case, it would be an indication that an attacker is using them to falsely deny the existence of RRs for which the server is not authoritative" |
| `R-N3-05` | NXDOMAIN: a closest encloser proof for QNAME, plus an NSEC3 covering the wildcard at that encloser | RFC 5155 §8.4: "A validator MUST verify that there is a closest encloser proof for QNAME present in the response and that there is an NSEC3 RR that covers the wildcard at the closest encloser" |
| `R-N3-06` | NODATA, QTYPE ≠ DS: an NSEC3 matching QNAME with both QTYPE and CNAME bits clear | RFC 5155 §8.5: "The validator MUST verify that an NSEC3 RR that matches QNAME is present and that both the QTYPE and the CNAME type are not set in its Type Bit Maps field" |
| `R-N3-07` | NODATA, QTYPE = DS: a matching NSEC3 with DS and CNAME clear; **or**, failing that, a closest provable encloser proof whose next-closer NSEC3 has Opt-Out set | RFC 5155 §8.6 |
| `R-N3-08` | Wildcard NODATA: a closest encloser proof plus a matching NSEC3 for the wildcard, with QTYPE and CNAME clear in it | RFC 5155 §8.7 |
| `R-N3-09` | Wildcard answer: an NSEC3 covering the next closer name to QNAME | RFC 5155 §8.8: "This proves that QNAME itself did not exist and that the correct wildcard was used to generate the response" |
| `R-N3-10` | Insecure delegation: a matching NSEC3 with NS set, DS clear and SOA clear; or no match, plus a closest provable encloser proof whose next-closer NSEC3 has Opt-Out set | RFC 5155 §8.9 |
| `R-N3-11` | Iteration counts are bounded, and a high count is refused rather than computed | RFC 9276 §3.1, and see below |

RFC 5155 §8.3's algorithm, quoted rather than paraphrased because the flag
handling is where implementations go wrong:

> 1.  Set SNAME=QNAME.  Clear the flag.
> 2.  Check whether SNAME exists:
>     *  If there is no NSEC3 RR in the response that matches SNAME ... clear the flag.
>     *  If there is an NSEC3 RR in the response that covers SNAME, set the flag.
>     *  If there is a matching NSEC3 RR in the response and the flag was set, then the proof is complete, and SNAME is the closest encloser.
>     *  If there is a matching NSEC3 RR in the response, but the flag is not set, then the response is bogus.
> 3.  Truncate SNAME by one label from the left, go to step 2.

**Opt-out is where NSEC3 stops proving what NSEC proves.** An NSEC3 with the
Opt-Out bit set asserts only that the *closest provable encloser* exists; names
between it and the next hash may or may not exist, and RFC 5155 §1.3 says so
directly: the closest provable encloser "is only different from the closest
encloser in an Opt-Out zone". Opt-out therefore supports exactly one kind of
conclusion — that a delegation is insecure (`R-N3-07`, `R-N3-10`) — and must
never be read as proving that a name does not exist. A validator that treats
opt-out coverage as a name-error proof will accept a forged NXDOMAIN for any
name in any opt-out zone, which is most of the TLDs.

**Iterations are an attacker-chosen loop count.** The hash iteration count and
the salt both arrive in the response, and each iteration is a hash computation
the validator performs. RFC 9276 §3.1 is unambiguous about what a zone should
publish:

> If NSEC3 must be used, then an iterations count of 0 MUST be used to
> alleviate computational burdens.  Note that extra iteration counts other
> than 0 increase the impact of CPU-exhausting DoS attacks, and also increase
> the risk of interoperability problems.

§3.2 then gives validators two permissions for larger counts, both at the same
threshold:

> Validating resolvers MAY return an insecure response to their clients when
> processing NSEC3 records with iterations larger than 0. ...
>
> Validating resolvers MAY also return a SERVFAIL response when processing
> NSEC3 records with iterations larger than 0.

The 100 and 500 figures that circulate as "the RFC 9276 limits" are not
normative text; they are measurements in Appendix A ("setting an upper limit of
100 iterations for treating a zone as insecure is interoperable ... returning
SERVFAIL beyond 500 iterations appears to be interoperable"). Daddybound cites
them as evidence about the deployed Internet, not as a rule.

Of the two permissions, Daddybound takes the refusal and not the downgrade: a
count above its configured ceiling produces Indeterminate with
`ReasonResourceLimit`, never Insecure and never a verdict. The RFC gives the
reason itself, in §3.2:

> Because treating a high iterations count as insecure leaves zones subject to
> attack, validating resolver operators and validating resolver software
> implementers are further encouraged to lower their default limit for
> returning SERVFAIL when processing NSEC3 parameters containing large
> iteration count values.

Reading an expensive proof as "insecure" would let an attacker downgrade a
signed zone by publishing an expensive NSEC3, which converts a denial-of-service
lever into a security one.

### 4.9 Aliases: CNAME (RFC 1034, RFC 2181 §10.1, RFC 4035 §5.3.4)

A CNAME answer is not one RRset to check. It is a sequence: the alias at the
queried name, then whatever the target resolves to, possibly through more
aliases and possibly through zones of differing security status.

RFC 1034 §4.3.2 step 3a is what produces the shape — a server that finds a
CNAME puts it in the answer, restarts at the target, and appends what it finds
if it is authoritative there. So a single message routinely holds records at
several owner names, only one of which answers the question.

| ID | Rule | Source |
| --- | --- | --- |
| `R-ALIAS-01` | The answer to (QNAME, QTYPE) is the RRset **at QNAME**. Records of the right type at another owner are not the answer. | RFC 1034 §4.3.2 |
| `R-ALIAS-02` | Where QTYPE is absent at QNAME and a CNAME is present, the CNAME is the answer and the chain continues at its target. | RFC 1034 §3.6.2 |
| `R-ALIAS-03` | More than one CNAME at a name is refused. "A CNAME record is not allowed to coexist with any other data", and a fortiori not with a second CNAME. | RFC 2181 §10.1 |
| `R-ALIAS-04` | Each hop is resolved from the trust anchor down, not from the previous hop's zone. A target may be in another zone, under another anchor, or below a delegation the first name never crossed. | RFC 4035 §5.3.1 |
| `R-ALIAS-05` | A wildcard-expanded CNAME owes the same denial proof as any other wildcard-expanded RRset. | RFC 4035 §5.3.4 |
| `R-ALIAS-06` | The chain's verdict is the **weakest** hop: Bogus over Indeterminate over Insecure over Secure. Neither the first hop's classification nor the last is inherited. | RFC 4033 §5, RFC 6672 §5.3.3 |
| `R-ALIAS-07` | Hops are bounded, and a name visited twice ends the chain. Reaching either bound is Indeterminate with a resource reason — a deeply aliased zone is unusual, not forged. | operational |

`R-ALIAS-01` is the one that was a live defect. Filtering the answer section by
*type* rather than by owner accepts any correctly signed RRset of the right
type as the answer to a question it has nothing to do with, and every signature
in the response verifies. No forgery is required.

`R-ALIAS-06` is the definition of what Secure means for a chain, and it is
narrower than "the answer validated". A signed alias into an unsigned zone is
Insecure however well signed its destination is: whoever controls the unsigned
part chooses the destination, and the signature there attests that the
destination is genuine, never that this query should have been sent to it.

### 4.10 Aliases: DNAME (RFC 6672)

A DNAME at an ancestor of the queried name redirects everything beneath it.
The server sends the DNAME together with a CNAME it synthesised, and RFC 6672
§5.3.1 fixes what that CNAME is worth:

> In any response, a signed DNAME RR indicates a non-terminal redirection of
> the query. There might or might not be a server-synthesized CNAME in the
> answer section; if there is, the CNAME will never be signed. For a DNSSEC
> validator, verification of the DNAME RR and then that the CNAME was properly
> synthesized is sufficient proof.

| ID | Rule | Source |
| --- | --- | --- |
| `R-DNAME-01` | The DNAME RRset is authenticated and the redirection recomputed from its owner and target. The synthesised CNAME is not read at all. | RFC 6672 §5.3.1 |
| `R-DNAME-02` | Only whole labels are replaced. A name ending in the owner's *characters* without ending in its *labels* is not redirected. | RFC 6672 §2.2 |
| `R-DNAME-03` | The owner name is not redirected by its own DNAME; only proper subdomains are. | RFC 6672 §2.3 |
| `R-DNAME-04` | Where several DNAMEs could apply, the deepest owner wins. | RFC 1034 §4.3.2 |
| `R-DNAME-05` | Only one DNAME may exist at a name; two are refused rather than chosen between. | RFC 6672 §2.4 |
| `R-DNAME-06` | A substitution producing a name longer than the DNS allows is refused. | RFC 6672 §2.2 |
| `R-DNAME-07` | A chain of DNAME and CNAME redirections is as strong as its weakest link. | RFC 6672 §5.3.3 |
| `R-DEN-07` | An NSEC or NSEC3 with the DNAME bit set may not deny a subdomain of its owner. | RFC 6672 §5.3.2, RFC 6840 §4.1 |

`R-DNAME-01` is the whole difficulty. A validator that treats the synthesised
CNAME as an ordinary alias finds an unsigned RRset and reports Bogus for every
DNAME-using name in the DNS; one that *trusts* it because a signed DNAME sits
nearby has accepted a target the sender chose, authenticated by a signature
over a different record. Not reading it makes tampering with it a no-op rather
than something to detect.

`R-DNAME-02` is where a plausible implementation goes wrong quietly. RFC 6672
§2.2 publishes a substitution table for exactly that reason, and it lists
`ab.example.com.` under a DNAME owned by `b.example.com.` as "<no match>" — a
string-suffix implementation redirects it.

### 4.11 QTYPE=ANY (RFC 6840 §4.2)

> When validating a response to QTYPE=*, all received RRsets that match QNAME
> and QCLASS MUST be validated. If any of those RRsets fail validation, the
> answer is considered Bogus. If there are no RRsets matching QNAME and
> QCLASS, that fact MUST be validated according to the rules in Section 5.4 of
> [RFC4035] ... To be clear, a validator must not expect to receive all
> records at the QNAME in response to QTYPE=*.

| ID | Rule | Source |
| --- | --- | --- |
| `R-ANY-01` | Every RRset at QNAME in the answer is validated. The verdict is the weakest of them. | RFC 6840 §4.2 |
| `R-ANY-02` | An empty answer with NXDOMAIN is proved by the ordinary name-error rules: a name that does not exist has no records of any type. | RFC 4035 §5.4 |
| `R-ANY-03` | An empty answer with NOERROR is **not provable**. A NODATA proof works by showing the queried type is absent from a type bitmap, and no bitmap contains type 255 because no record has it. Reported Indeterminate, never Secure and never Bogus. | RFC 6840 §4.2, RFC 4035 §5.4 |
| `R-ANY-04` | Completeness is not checked. RFC 1034 §6.2.2 lets a server return a subset, so "these are all the records" is not a claim the response makes. | RFC 6840 §4.2 |

`R-ANY-03` is the reason this section exists. Type 255 is a query type, not a
record type, so a validator that runs an ANY query through the ordinary path
finds an answer filter that matches nothing and a NODATA rule that every
bitmap in existence satisfies. Composed, those produce **Secure, and there is
no data here** for a name whose own NSEC — in the same response — lists its
types. An attacker needs only to delete the answer section and forward the
zone's genuine denial records untouched.

`R-ANY-04` is why Secure means less for an ANY query than for any other, and
the implementation is written so the narrower claim is the only one it can
make: every RRset that arrived is authentic, and nothing is said about the
ones that did not.

## 5. Algorithm support versus algorithm permission

This distinction is not Daddybound's invention. It is written into the
standards, and getting it wrong in either direction is a security bug.

### 5.1 Unsupported signature algorithms (RFC 6840 §5.3)

Where a zone's algorithms cannot be validated, "then the zone is treated as if
it were unsigned" — Insecure, not Bogus. An unsupported algorithm is a
statement about the validator, not about the data, and reporting it as Bogus
accuses a correctly signed zone of being forged.

### 5.2 Unsupported DS digest algorithms (RFC 6840 §5.2)

> DS records using unknown or unsupported message digest algorithms MUST be
> treated the same way as DS records referring to DNSKEY RRs of unknown or
> unsupported public key algorithms.

and, when none of a delegation's DS records survive that filter:

> If none are left, the zone is treated as if it were unsigned.

Again Insecure, not Bogus.

### 5.3 The honesty constraint on §5.1 and §5.2

Both rules terminate in "treated as if it were unsigned", which is RFC 4033's
Insecure. Daddybound does **not** return Insecure for them, and now that denial
proofs exist that is a deliberate distinction rather than a missing capability.

Insecure is a claim about the zone: signed proof that no DS exists. An
unsupported algorithm or an uncomputable digest is a fact about *this build*.
The DS records are present; Daddybound simply cannot evaluate them. Reporting
Insecure would say the parent proved something it never asserted, and would
hand an attacker a downgrade: publish a delegation this validator cannot
evaluate and its protection disappears.

So Daddybound returns Indeterminate with a reason naming the unsupported
algorithm or digest — an accurate statement of "this validator could not
determine the status", which is not the same claim as "the zone is unsigned".
The differential suite records the resulting disagreement with reference
validators as a known gap, with this argument attached.

Stating this is the whole point of having the gate. The alternative — returning
Insecure because the RFC's sentence ends in that word, without the proof the
same RFC requires to reach it — would be a fabricated verdict of exactly the
kind this project is supposed to make impossible.

### 5.4 RFC 9905: the clearest statement that support ≠ permission

An initial summarised reading of RFC 9905 appeared to say two contradictory
things about RSASHA1. The raw text resolves it, and the resolution is the
design:

> The RSASHA1 [RFC4034] and RSASHA1-NSEC3-SHA1 [RFC5155] algorithms MUST NOT be
> used when creating DNSKEY and RRSIG records. Validating resolver
> implementations ([RFC9499], Section 10) MUST continue to support validation
> using these algorithms as they are diminishing in use but still actively in
> use for some domains as of this publication. Operators of validating
> resolvers MUST treat DNSSEC signing algorithms RSASHA1 and RSASHA1-NSEC3-SHA1
> as unsupported, rendering responses insecure if they cannot be validated by
> other supported signing algorithms.

Two different actors, two different obligations. The **implementation** MUST
retain the capability. The **operator** MUST refuse to rely on it. Both at
once, for the same algorithm.

An implementation with a single `supported bool` per algorithm cannot express
that, and whichever value it picks violates one of the two MUSTs. Daddybound's
algorithm layer therefore answers two separate questions — *can this build
verify this algorithm* and *does policy permit relying on it* — and the failure
reasons for the two are distinct enough that a trace never conflates them.

RFC 9905 §2 also says of DS records:

> Operators of validating resolvers MUST treat RSASHA1 and RSASHA1-NSEC3-SHA1
> DS records as insecure. If no other DS records of accepted cryptographic
> algorithms are available, the DNS records below the delegation point MUST be
> treated as insecure.

Same shape, same reasoning as §5.3: Daddybound reports Indeterminate with
a specific reason where a complete validator would report Insecure.

## 5.5 The delegation Daddybound still cannot prove, and the direction it errs in

A chain walk descends from the trust anchor towards the answer, asking at each
name whether a DS exists there. When none comes back, two situations have to be
told apart:

- the name is not a zone cut at all — true of nearly every name ever queried;
- the name *is* a zone cut with no DS, an insecure delegation, and everything
  below it is legitimately unsigned.

Daddybound now implements the proofs that separate them (§4.7, §4.8), and where
a response supplies one the answer is decided by evidence: NS set with DS clear
is an insecure delegation and produces Insecure; neither bit set means the name
is not a cut and the walk continues; a DS bit set while the DS is absent is a
contradiction and produces Bogus.

**What remains is the case where the response supplies no proof either way.**
The walk then keeps the assumption it made before any of this existed: treat
the name as not a zone cut, continue in the same zone, and record a step saying
where the assumption was made.

The choice of which way to be wrong is the whole decision, and it is one-sided:

- If the assumption is wrong, the data below is genuinely unsigned, the walk
  finds no signature from a zone it trusts, and the answer is reported **Bogus
  where a complete proof would have given Insecure**. A false Bogus. It refuses
  data that was fine.
- The converse cannot happen. Concluding Secure requires a signature over the
  answer made by a key in an apex DNSKEY RRset the walk has already
  authenticated. An attacker operating below an insecure delegation does not
  have that key, so no assumption made here can manufacture a Secure verdict.

So the cost of the remaining gap is paid in refusals and never in false
Secures, which is the only direction this engine is willing to be wrong in.

Returning Indeterminate instead would be worse rather than more cautious.
Almost no name a walk passes through is a zone cut, so it would turn ordinary
validation into "cannot tell", and an enforcing resolver reading Indeterminate
as "allow" would then accept forged data. An earlier design did exactly that,
carrying the ambiguity to the end of the walk and downgrading any final failure
to Indeterminate; the scenario suite caught it, because the tampered and
corrupt-signature cases both went Indeterminate.

## 5.6 A denial divergence between two mature validators, and which one Daddybound follows

The scenario: an empty non-terminal answered NXDOMAIN instead of NOERROR. The
NSEC records are genuine and verify; only the response code was changed. That
covering NSEC's Next Domain Name lies *below* the queried name, which means the
queried name exists — every ancestor of an existing name exists, at worst as an
empty non-terminal.

Three validators, two answers:

| Validator | Verdict | What it does with the response |
| --- | --- | --- |
| **libunbound 1.19.2** | Secure | Hands the client NODATA. It disbelieved the response code and repaired it. |
| **delv 9.18.39** | Bogus | `resolution failed: insecurity proof failed` |
| **Daddybound** | Bogus, `denial_contradicted` | Refuses the response |

Daddybound sides with delv, and the reason is not that two out of three is a
majority. It is that Daddybound returns a *verdict* and not an *answer*. A full
resolver can do what libunbound does — decline to believe the response code,
substitute the one the records support, and report the records as authentic,
which is both safe and more useful. Daddybound has no answer to substitute. Its
only outputs are the four states, so the only way it can decline to endorse a
claim is to refuse it.

Endorsing it would matter, and RFC 8020 §2 says why:

> When an iterative caching DNS resolver receives an NXDOMAIN response, it
> SHOULD store it in its cache and then all names and resource record sets
> (RRsets) at or below that node SHOULD be considered unreachable.

and, in the same section:

> Another exception is that a validating resolver MAY decide to implement the
> "NXDOMAIN cut" behavior (described in the first paragraph of this section)
> only when the NXDOMAIN response has been validated with DNSSEC.

So a *validated* NXDOMAIN is precisely the thing that licenses erasing a whole
subtree. In this scenario the subtree is not empty — the name below it is what
makes the queried name exist in the first place. A validator that called this
Secure would hand an attacker that licence in exchange for changing one field
of a header, with no cryptography required.

The scenario is annotated as a known gap in the differential suite so the
disagreement is recorded rather than rediscovered. The annotation cannot hide
anything that matters: the comparator classifies a false Secure before it looks
at the annotation, and this divergence is in the other direction.

## 5.7 A second denial divergence, and why the weaker verdict buys nothing

Asked for the DS RRset at a delegation that opt-out left out of the NSEC3
chain, the three validators split again — and differently from §5.6:

| Validator | Verdict |
| --- | --- |
| **delv 9.18.39** | Secure (`; negative response, fully validated`) |
| **Daddybound** | Secure |
| **libunbound 1.19.2** | Neither secure nor bogus: reported as insecure |

The instinct is that libunbound's is the safe answer, because an opt-out record
asserts less than an ordinary one. RFC 5155 §6 is explicit about how much less:

> An Opt-Out NSEC3 RR does not assert the existence or non-existence of the
> insecure delegations that it may cover.

But that sentence is about *insecure* delegations, and the question here is
whether a *secure* one could be hiding in the span. It could not, and the
reason is structural rather than a matter of trust. RFC 5155 §7.1 requires an
NSEC3 RR for every owner name that owns authoritative RRsets; a secure
delegation owns a DS, so its hash is itself an owner name in the chain. Every
record's interval runs from one owner to the next and is therefore open at both
ends — no record's span contains another record's owner hash. An attacker
cannot sign a record that does, and omitting the real record does not help
either: with the matching record gone, nothing covers the next closer name, so
the closest provable encloser proof fails outright rather than succeeding on the
wrong evidence.

So opt-out cannot conceal a secure delegation, and RFC 5155 §8.6 — the section
is titled "Validating No Data Responses, QTYPE is DS" — lists checks which,
when they pass, validate the response. Daddybound reports Secure. The scenario
is annotated as a known gap so the disagreement with libunbound is recorded
rather than rediscovered.

What opt-out genuinely costs is stated by RFC 5155 §12.2, and Daddybound does
not pretend otherwise:

> the primary difference in security when using Opt-Out is the loss of the
> ability to prove the existence or nonexistence of an insecure delegation
> within the span of an Opt-Out NSEC3 RR.

That loss is real and inherent. It is why an opt-out record may establish that a
delegation is insecure (`R-N3-07`, `R-N3-10`) and may never be read as proof
that a name does not exist.

## 5.8 The ancestor-signature disagreement, settled by measurement

One scenario has an ancestor zone signing a delegated child's data. The
signature is cryptographically perfect and made by the wrong authority.
Daddybound reports Bogus with `signer_not_zone`; libunbound 1.19.2 and BIND
delv 9.18.39 both accept the answer.

The explanation previously recorded here was that all three implementations
know where the zone cut is and read RFC 4035 §5.3.1 differently — that the
oracles take the containing zone from the RRSIG's signer name as a deliberate
choice. That explanation was wrong, and the queries say so.

The lab's authoritative server records every question a reference validator
asks. Against the foreign-zone-signature scenario, delv asks exactly four:

```
www.example.dnsdaddylab.  A
dnsdaddylab.              DNSKEY
dnsdaddylab.              DS
.                         DNSKEY
```

It never asks about `example.dnsdaddylab.` at all. Reading the containing zone
off the signer name is not a judgement it makes *about* a cut it has found; it
is what determines where it looks, so the cut is never discovered. RFC 4035
§5.3.1 says "the RRSIG RR's Signer's Name field MUST be the name of the zone
that contains the RRset", and delv cannot apply that sentence here because it
has not established which zone that is. A lying signer redirects the walk to
the zone where its signature verifies.

Daddybound, over the same scenario, fetches the DS and the DNSKEY for
`example.dnsdaddylab.` because it descends the delegations from the anchor
rather than following the signature. So the refusal rests on evidence the
other implementation did not gather. This is a difference in what was known,
not a difference of reading.

**It is still not a vulnerability in delv, and the earlier note was right
about that.** RFC 4035 §5.3.1 also requires the signer to be at or above the
owner name, which delv does check, so the only signatures this admits are from
ancestors of the name. An ancestor can already seize any name beneath it by
replacing the delegation and publishing its own DS, so accepting its signature
grants no authority it lacked. That is a plausible reason not to spend a query
on the check.

Daddybound keeps the strict behaviour: it errs towards refusal, it cannot
produce a false Secure, and it has the information anyway as a by-product of
walking the chain. Two tests in `internal/daddybound/differential/zonecut_test.go`
pin the measurement — one that Daddybound asks about every cut and asks the
same questions whether or not the signer lies, and one that delv accepts
without ever asking. If delv's query pattern changes, those tests fail and
this section is to be re-derived rather than re-asserted.

libunbound is not measured the same way here. It is pointed at the lab as a
forwarder rather than resolving iteratively, so its query pattern reflects the
harness as much as its own logic, and nothing can be concluded from it either
way.

## 6. IANA registries

Reproduced as read on 7 September 2026. Daddybound's tables are checked against
these by test; a registry that has moved since is a test failure and a
deliberate code change, never a runtime download. Runtime code does not fetch
either registry.

### 6.1 DNS Security Algorithm Numbers

| No. | Mnemonic | Description | Zone signing | Reference |
| --- | --- | --- | --- | --- |
| 0 | DELETE | Delete DS | N | RFC 4034, RFC 4398, RFC 8078 |
| 1 | RSAMD5 | RSA/MD5 (DEPRECATED) | N | RFC 3110, RFC 4034 |
| 2 | DH | Diffie-Hellman | N | RFC 2539 |
| 3 | DSA | DSA/SHA1 | Y | RFC 3755, RFC 2536 |
| 5 | RSASHA1 | RSA/SHA-1 | Y | RFC 3110, RFC 4034, RFC 9905 |
| 6 | DSA-NSEC3-SHA1 | DSA-NSEC3-SHA1 | Y | RFC 5155 |
| 7 | RSASHA1-NSEC3-SHA1 | RSASHA1-NSEC3-SHA1 | Y | RFC 5155, RFC 9905 |
| 8 | RSASHA256 | RSA/SHA-256 | Y | RFC 5702 |
| 10 | RSASHA512 | RSA/SHA-512 | Y | RFC 5702 |
| 12 | ECC-GOST | GOST R 34.10-2001 (DEPRECATED) | Y | RFC 5933, RFC 9906 |
| 13 | ECDSAP256SHA256 | ECDSA Curve P-256 with SHA-256 | Y | RFC 6605 |
| 14 | ECDSAP384SHA384 | ECDSA Curve P-384 with SHA-384 | Y | RFC 6605 |
| 15 | ED25519 | Ed25519 | Y | RFC 8080 |
| 16 | ED448 | Ed448 | Y | RFC 8080 |
| 17 | SM2SM3 | SM2 with SM3 hashing | Y | RFC 9563 |
| 18 | MLDSA44 | ML-DSA-44 | Y | draft-westerbaan-dnssec-mldsa-03 |
| 23 | ECC-GOST12 | GOST R 34.10-2012 | Y | RFC 9558 |
| 253 | PRIVATEDNS | private algorithm | Y | RFC 4034 |
| 254 | PRIVATEOID | private algorithm OID | Y | RFC 4034 |

Numbers 4, 9 and 11 are reserved; 19–22 and 24–122 are unassigned; 123–251 are
reserved. Daddybound treats every number it has no verifier for as unsupported
rather than assuming an unassigned number is unusable, because the registry
gains entries and the code should not have to be edited to fail correctly on
one it has not seen.

### 6.2 DS digest algorithms

| Value | Description | Use for delegation | Use for validation | Implement for validation | Reference |
| --- | --- | --- | --- | --- | --- |
| 0 | Reserved | MUST NOT | MUST NOT | MUST NOT | RFC 3658 |
| 1 | SHA-1 | MUST NOT | RECOMMENDED | MUST | RFC 3658, RFC 9905 |
| 2 | SHA-256 | RECOMMENDED | RECOMMENDED | MUST | RFC 4509 |
| 3 | GOST R 34.11-94 (DEPRECATED) | MUST NOT | MUST NOT | MUST NOT | RFC 5933, RFC 9906 |
| 4 | SHA-384 | MAY | RECOMMENDED | RECOMMENDED | RFC 6605 |
| 5 | GOST R 34.11-2012 | MAY | MAY | MAY | RFC 9558 |
| 6 | SM3 | MAY | MAY | MAY | RFC 9563 |

7–127 unassigned, 128–252 reserved, 253–254 private use, 255 unassigned
(RFC 9904). Registry last updated 13 January 2026.

Note the shape of row 1, which is the §5.4 distinction again in table form:
SHA-1 is `MUST NOT` for creating delegations and simultaneously `MUST` for
implementing validation.

## 7. Where Daddybound relies on `github.com/miekg/dns`

The brief's line is that first principles means implementing the protocol and
trust logic, not the cryptographic mathematics — and, by the same reasoning,
not re-deriving wire formats that are pure mechanical serialisation.

Daddybound uses `miekg/dns` for: RR type definitions, wire parsing and packing,
DNSSEC record structures, canonical packing of names and RDATA, and key tag
computation. It uses Go's standard `crypto/*` for SHA-2, RSA, ECDSA and
Ed25519.

Daddybound implements, itself: which key may sign what, whether a DS
authenticates a DNSKEY, whether an RRSIG is admissible, what the signed data
for an RRset is, how a chain of trust is walked, what each outcome means, and
what it is permitted to claim. That is the trust logic, and none of it is
delegated.

The line between the two is enforced by testing rather than asserted: the
canonicalisation tests assert the *bytes* against the RFC's rules (`R-CANON-*`)
rather than asserting that the library was called. If a library upgrade changed
canonical packing, those tests fail. A test that only checked the call happened
would not.

Nothing in the shipped resolver links against a validating resolver
implementation. libunbound appears in this repository only as a differential
test oracle behind a test-only build constraint, and never produces a
Daddybound verdict.

## 8. What Daddybound does not implement

Stated here because the credibility of everything above depends on this list
being complete and blunt.

- **No aggressive use of NSEC/NSEC3 (RFC 8198).** Denial proofs are validated
  when a response carries them; they are never used to synthesise an answer to
  a question that was not asked.
- **No recursive resolution.** Daddybound validates responses something else
  supplies. The live differential corpus points it at a recursive resolver
  with CD set; that is a harness reading records, not Daddybound discovering
  them.
- **No YXDOMAIN handling.** A DNAME substitution that would overflow the legal
  name length is refused (`R-DNAME-06`) rather than reported as the RCODE
  RFC 6672 §2.2 has a *server* return.
- **No RFC 5011 trust anchor rollover.** Trust anchors are configuration.
- **No encrypted transports** as part of the validation engine.
- **No production enforcement.** Daddybound cannot be configured to decide a
  real DNS answer for a real client. That is a deliberate structural property,
  not an unfinished feature.
- **No ENS, no CCIP Read, no blockchain naming of any kind.**

## 9. Standing rules that follow from all of the above

1. A disagreement with a reference validator is investigated against the rule
   IDs in §4 first. "libunbound says so" is not a finding.
2. Policy is never decided by matching an English error string. Reasons are
   typed values; text is for humans.
3. Trust anchors and algorithm policy are code and configuration, reviewed as
   changes. Runtime code downloads neither.
4. A verdict Daddybound cannot derive from a rule in §4 is Indeterminate with a
   reason, never a guess in either direction.
