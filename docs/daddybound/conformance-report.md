# Daddybound laboratory conformance

Generated: `2026-11-16T11:23:44Z`  
Revision: `c1c786e`  
Status: **experimental**

## What this report claims

- The offline signed laboratory reaches the verdict each scenario requires.
- Known gaps and no-oracle cases are named rather than papered over.
- This package can be regenerated from the same binary and source revision.

## What this report does not claim

- Unrestricted agreement with every reading of the DNSSEC standards (known gaps remain named).
- Production reliability of Live mode.
- An independent professional security review.
- Zero unexplained differences against Unbound/BIND on every live Internet name.
- A measured false-positive rate for behavioural detection.
- Certification under ISO 27001, SOC 2, Cyber Essentials or HIPAA.

## Laboratory summary

| Metric | Value |
| --- | ---: |
| Scenarios | 78 |
| Agreed with scenario expectations | 78 |
| Disagreed | 0 |

### By family

| Family | Count |
| --- | ---: |
| `alias` | 14 |
| `chain-failure` | 19 |
| `configuration` | 1 |
| `nsec` | 18 |
| `nsec3` | 16 |
| `positive` | 10 |

### By expected verdict

| Expected | Count |
| --- | ---: |
| `bogus` | 38 |
| `indeterminate` | 7 |
| `insecure` | 5 |
| `secure` | 28 |

## Documented known gaps

### `foreign-zone-signature` (`chain-failure`)

Settled by measurement, and not the way the earlier note guessed. Two independent validators accept this answer and Daddybound refuses it: libunbound 1.19.2 and BIND delv 9.18.39. The explanation on file was that all three know where the zone cut is and read RFC 4035 section 5.3.1 differently. The lab's query log says otherwise: against this scenario delv asks for the answer, then dnsdaddylab DNSKEY, dnsdaddylab DS and the root DNSKEY, and never asks about example.dnsdaddylab at all. Taking the containing zone from the signer name is what determines where it looks, so the cut is never discovered and the rule cannot be applied. Daddybound fetches that zone's DS and DNSKEY because it descends the delegations rather than following the signature, so its refusal rests on evidence delv did not gather. Still not a vulnerability in delv: section 5.3.1 also requires the signer to be at or above the owner name, which delv does check, and an ancestor can seize any name beneath it by replacing the delegation anyway. Daddybound keeps the strict behaviour because it errs towards refusal and has the information as a by-product of the walk. See docs/daddybound/standards.md section 5.8 and the pinned measurement in internal/daddybound/differential/zonecut_test.go.

### `unsupported-algorithm` (`chain-failure`)

RFC 6840 §5.3 says such a zone is treated as unsigned. A complete validator reports Insecure; v0.1 has no denial proofs and so reports Indeterminate.

### `disallowed-algorithm` (`chain-failure`)

policy, not protocol, and the standards put the two implementations on opposite sides of it deliberately. RFC 9905 section 2 tells validator implementations they MUST continue to support validation using RSASHA1, and in the same paragraph tells validator operators they MUST treat it as unsupported. A reference validator built to the first sentence reports Secure; Daddybound's default policy is built to the second and reports Indeterminate with disallowed_algorithm. Neither is wrong about the data, and the disagreement would vanish if the oracle were configured with the same policy. What must not happen is Bogus, because the zone is not broken.

### `unsupported-ds-digest` (`chain-failure`)

RFC 6840 section 5.2 says that where no usable DS digest is left, the zone is treated as if it were unsigned, and a complete validator therefore reports Insecure. Daddybound reports Indeterminate with unsupported_digest. The difference is that Insecure is a claim — RFC 4033 section 5 defines it as signed proof that no DS exists — and here no such proof was offered: the DS records are present and this build simply cannot compute their digest type. Reporting Insecure would say the parent proved something it never asserted. The honest statement is that this validator could not evaluate the delegation, which is what Indeterminate means and what the reason says.

### `nxdomain-for-a-name-that-exists` (`nsec`)

libunbound 1.19.2 reports Secure here and hands its client NODATA, having rewritten the response code it did not believe. delv 9.18 refuses the response, as Daddybound does ("resolution failed: insecurity proof failed"). Daddybound returns a verdict rather than an answer, so it has no way to correct a response — refusing is the only outcome available to it that does not endorse the claim. RFC 8020 §2 is why endorsing would matter: a resolver MAY apply the NXDOMAIN cut, treating every name below as unreachable, and MAY choose to do so only for responses validated with DNSSEC. Calling this Secure would hand that licence to an attacker who changed one header field, and take out the name that does exist.

### `nsec3-opt-out-span-cannot-prove-a-name-error` (`nsec3`)

libunbound 1.19.2 agrees (insecure). delv 9.18.39 reports the same response fully validated, and does so on the live Internet too: darkegy.cam does not exist, .cam signs with opt-out, and delv returns a validated NXDOMAIN where libunbound returns insecure. This is a real divergence between two mature validators rather than a fault in either. Daddybound follows the weaker verdict because RFC 5155 section 12.2 is explicit that non-existence within an opt-out span is not provable, and this project treats an unjustified Secure as the failure that matters. The refusal is confined to the conclusion: the same span still establishes an insecure delegation under section 8.9, which is the one thing opt-out is permitted to prove.

### `nsec3-opt-out-proves-no-ds` (`nsec3`)

delv 9.18.39 agrees (fully validated); libunbound 1.19.2 reports the answer insecure instead. RFC 5155 §8.6 is titled "Validating No Data Responses, QTYPE is DS" and states what a validator MUST verify; those checks pass, so the response validates. The proof is also sound rather than merely permitted: §7.1 requires an NSEC3 at every secure delegation, so that name's hash is itself an owner in the chain and no record's open interval contains it. An attacker cannot fabricate a signed record, and omitting the real one leaves nothing covering the next closer name, so the proof fails rather than succeeding wrongly. Opt-out therefore cannot hide a secure delegation, and there is nothing left for the weaker verdict to protect against.

### `any-answer-with-a-tampered-rrset` (`chain-failure`)

delv disagrees, and the RFC decides it. Given a QTYPE=* answer holding a good NSEC RRset and a rewritten A RRset, delv 9.18.39 prints ";; RRSIG failed to verify resolving 'www.example.dnsdaddylab/ANY/IN'", drops the A RRset from its output, and then reports "; fully validated" over what is left — a partial answer marked authentic. RFC 6840 §4.2 is explicit that this is not the rule: "all received RRsets that match QNAME and QCLASS MUST be validated. If any of those RRsets fail validation, the answer is considered Bogus." libunbound 1.19.2 reads it the same way Daddybound does and returns bogus, so this is one implementation against the standard and a second implementation, not Daddybound against the field. Nothing here is excused in the dangerous direction: delv reports Secure and Daddybound reports Bogus, and Classify checks for a false Secure before it ever reaches this annotation.

## No-oracle scenarios

### `rollover-two-signatures-one-broken` (`positive`)

the two oracles genuinely differ here, and RFC 4035 §5.3.3 says why they are allowed to: "the local resolver security policy determines whether the resolver also has to test these RRSIG RRs and how to resolve conflicts if these RRSIG RRs lead to differing results." There is no fact about the data to disagree about — one signature is authentic and the other is not, and both validators can see that — only a policy about what to do next.

RFC 6840 §5.4 makes the SHOULD, and Daddybound follows it. Measured: libunbound 1.19.2 reaches Secure and agrees; BIND delv 9.18.39 reports "RRSIG failed to verify" and rejects, which is the more restrictive policy the same section warns about — "Such a resolver is also vulnerable to malicious insertion of gibberish signatures", which is exactly this scenario. Comparing anyway would file that as a false Secure, and a false Secure is the one class this suite refuses to let anything explain away. It must therefore not be manufactured out of a policy choice, or the class stops meaning what it says.

The rule is not left untested by that. rollover-every-signature-broken is the same shape with nothing valid in it, is fully comparable, and both oracles reject it — so a validator that accepted this one because a signature was merely present still fails there.

### `cname-chain-longer-than-the-hop-limit` (`alias`)

the limit under test is Daddybound's shipped hop budget. Every link is correctly signed, so a reference validator either resolves the chain or stops on a budget of its own; either way the disagreement would be about two numbers rather than about the data.

### `no-trust-anchor` (`configuration`)

this narrows Daddybound's own anchor set and asks about a name the hierarchy does not serve. An external validator is configured from the same hierarchy, so it still holds an anchor, and it has no records to reason about either way. The property under test belongs to Daddybound's configuration rather than to any data, so there is no question to put to a second validator.

## How to reproduce and extend

- Offline laboratory: `dnsdaddy daddybound validate  |  make daddybound-report`
- Differential vs Unbound/delv: `make test-daddybound  (needs libunbound-dev, bind9-dnsutils, cgo)`
- Real-world corpus: `make corpus  (network; several minutes; not a PR gate)`
- Fuzz targets: `make fuzz-daddybound`
- CD/AD independence tests: `internal/daddybound/native/client_test.go; forward_test.go (upstream AD never inherited)`
- Encrypted no-plaintext-fallback: `docs/encrypted-dns.md; resolver encrypted_* tests (no plaintext fallback)`

Documents:

- `docs/daddybound/validation-lab.md`
- `docs/daddybound/standards.md`
- `docs/daddybound/security-model.md`
- `docs/maturity/verified-trust.md`

## Milestone: DNS Daddy: Verified Trust

Statuses describe repository evidence today. partial means implemented evidence with named gaps; planned means not yet an evidence package.

| ID | Item | Status | Evidence |
| --- | --- | --- | --- |
| `VT-1.1` | DNSSEC interop suite vs Unbound and BIND delv | partial | make test-daddybound; differential/ |
| `VT-1.2` | Valid / unsigned / expired / forged / malformed / bad-delegation cases | partial | lab.Scenarios families positive + chain-failure |
| `VT-1.3` | NSEC / NSEC3 / CNAME / DNAME / wildcards / algorithm edges | partial | lab families nsec, nsec3, alias; algorithm positives |
| `VT-1.4` | RFC 5011 rollover, recovery, clock skew | partial | trustanchors/; differential timemodel_test.go |
| `VT-1.5` | Local validation never inherits upstream AD | available | native/forward_test.go; observe source CD=1 |
| `VT-1.6` | CD=1 handling documented and tested | partial | native/client_test.go; docs/daddybound/README.md CD=1 managed-client policy |
| `VT-1.7` | Reproducible malicious-DNS laboratory | partial | lab/ scenarios + Server; not a full packet-adversary harness |
| `VT-1.8` | Independent adversarial review of Daddybound | planned | external engagement required |
| `VT-1.9` | Published DNSSEC conformance report | partial | this package + docs/maturity/verified-trust.md |
| `VT-2.1` | Extended fuzz of DNS wire / DoH / feeds / backup | partial | make fuzz-daddybound; expand beyond daddybound |
| `VT-2.2` | AuthN/session/token/CSRF/SSRF review evidence | partial | docs/security-testing.md; CI security workflow |
| `VT-2.3` | Hardened container/host deployment guide | partial | docs/deploy.md; Dockerfile non-root where possible |
| `VT-2.4` | Signed releases, SPDX SBOM, checksum verification | partial | roadmap Phase 2; existing checksums/SBOM inputs |
| `VT-2.5` | Security release gate | planned | process + reviewer approval |
| `VT-2.6` | External audit published with remediations | planned | commission when evidence package is reviewable |

