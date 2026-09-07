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

**Read date for every source below: 7 September 2026.** Registries change; the
IANA tables reproduced here are snapshots, and §6 says what happens when they
move.

## 1. How each source was verified

Three levels are used, and the level is stated for every document. Nothing is
promoted a level because it was "obviously" fine.

| Level | Meaning |
| --- | --- |
| **Verified** | The RFC or registry was fetched from the authoritative publisher and the specific normative sentences that v0.1 implements were read in the original text. Quotations below are from that text. |
| **Consulted** | Fetched and read for scope and terminology, but v0.1 implements nothing that depends on its detail, so no rule below cites it as authority. |
| **Scoped only** | Named in the roadmap, not read for this milestone. Nothing in v0.1 may depend on it. |

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
| IANA "DNS Security Algorithm Numbers" | The algorithm registry Daddybound's tables must agree with |
| IANA "Digest Algorithms" (DS RR) | The DS digest registry Daddybound's tables must agree with |

### Consulted

| Document | Why it is not load-bearing in v0.1 |
| --- | --- |
| RFC 1034, RFC 1035 | Daddybound uses `github.com/miekg/dns` for wire parsing and packing. v0.1 implements no message parser of its own, so the base specification informs terminology only. |
| RFC 9904 | Restructures the DNSSEC registries into the "Use for" / "Implement for" columns reproduced in §6. Daddybound reads the registries; it does not implement this document. |

### Scoped only — nothing in v0.1 depends on these

RFC 6891 (EDNS(0)), RFC 7766 (DNS over TCP), RFC 8198 (aggressive NSEC use),
RFC 8914 (extended DNS errors), RFC 7858 (DNS over TLS), RFC 8484 (DNS over
HTTPS), RFC 9156 (QNAME minimisation), RFC 9250 (DNS over QUIC), RFC 9460
(SVCB/HTTPS records), RFC 9462 (discovery of designated resolvers), RFC 5155
(NSEC3), RFC 5011 (automated trust anchor updates).

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

Two consequences for v0.1, both of which constrain what Daddybound is allowed
to return:

- **Insecure requires signed proof.** RFC 4033's Insecure is not "we did not
  find a signature". It is "we proved, with a signature, that no DS exists".
  v0.1 implements no denial-of-existence proofs at all (no NSEC, no NSEC3), so
  **v0.1 can never legitimately return Insecure from a chain walk.** Where a
  real validator would prove Insecure, Daddybound returns Indeterminate and
  says why. This is a scope limitation stated honestly, not an approximation.
- **Bogus requires a secure delegation.** Returning Bogus for a name Daddybound
  never established a secure delegation to would be a fabricated verdict. The
  chain walk therefore tracks whether it is still under a secure delegation,
  and a failure above that point is Indeterminate.

## 4. Rules v0.1 implements

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

### 5.3 The v0.1 honesty constraint on §5.1 and §5.2

Both rules terminate in "treated as if it were unsigned", which is RFC 4033's
Insecure — and §3 above establishes that v0.1 cannot legitimately reach
Insecure, because reaching it requires signed proof that no DS exists, and v0.1
implements no denial proofs.

Daddybound v0.1 therefore does **not** claim to implement these rules. It
returns Indeterminate with a reason naming the unsupported algorithm or digest,
which is an accurate statement of "this validator could not determine the
status" and is not the same claim as "the zone is unsigned". Implementing §5.1
and §5.2 properly is blocked on denial-of-existence support and is recorded as
such in the roadmap.

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

Same shape, same v0.1 limitation as §5.3: Daddybound reports Indeterminate with
a specific reason where a complete validator would report Insecure.

## 5.5 Delegations v0.1 cannot prove, and the direction it errs in

A chain walk descends from the trust anchor towards the answer, asking at each
name whether a DS exists there. When none comes back, two situations are
indistinguishable without a signed proof of non-existence:

- the name is not a zone cut at all — true of nearly every name ever queried;
- the name *is* a zone cut with no DS, an insecure delegation, and everything
  below it is legitimately unsigned.

v0.1 implements no denial proofs, so it cannot obtain the evidence that
separates them. It assumes the first reading, continues in the same zone, and
records a step in the trace at every point where the assumption was made.

The choice of which way to be wrong is the whole decision, and it is one-sided:

- If the assumption is wrong, the data below is genuinely unsigned, the walk
  finds no signature from a zone it trusts, and the answer is reported **Bogus
  where a complete validator would report Insecure**. A false Bogus. It refuses
  data that was fine.
- The converse cannot happen. Concluding Secure requires a signature over the
  answer made by a key in an apex DNSKEY RRset the walk has already
  authenticated. An attacker operating below an insecure delegation does not
  have that key, so no assumption made here can manufacture a Secure verdict.

So the cost of the gap is paid in refusals and never in false Secures, which is
the only direction this engine is willing to be wrong in.

An earlier design carried the ambiguity to the end of the walk and downgraded
*any* final failure to Indeterminate. That was worse in the way that matters:
because almost no answer name is a zone cut, it turned every tampered answer
into "cannot tell", and an enforcing resolver reading Indeterminate as "allow"
would have accepted forged data. The scenario suite caught it — the tampered
and corrupt-signature cases both went Indeterminate — which is the argument for
having written the negative scenarios before trusting the positive one.

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

## 8. What v0.1 does not implement

Stated here because the credibility of everything above depends on this list
being complete and blunt.

- **No denial of existence.** No NSEC, no NSEC3, no authenticated NXDOMAIN or
  NODATA, no wildcard denial proofs. Consequence: Insecure is unreachable (§3,
  §5.3).
- **No recursive resolution.** v0.1 validates responses it is given; it does
  not discover them by walking the Internet.
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
