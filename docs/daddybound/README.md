# Daddybound

Daddybound is an experimental DNS resolution and validation engine, written
from first principles in Go. It walks a DNSSEC chain of trust from a
configured trust anchor to an authenticated answer, an authenticated absence
or an authenticated redirection — and is honest about every case where it
cannot.

**Daddybound now supplies native client answers in experimental Live mode.**
It validates the exact returned data, returns Secure/proved Insecure answers,
and fails closed for Bogus, Indeterminate and operational failures without
falling back to an upstream. Live (`dns.local_dnssec_validation: enforce`) is
the default for a new installation; existing recorded Learn/off choices and
explicit configuration are preserved. Longer operational evaluation is still
required before claiming production readiness.

Learn (`observe`) continues to validate independently after the forwarded
answer is final, so its verdict cannot change that answer. Off constructs no
native runtime. Both enabled modes use plaintext authoritative UDP/TCP 53,
independently of any encrypted forwarder. See
[ADR 0003](../decisions/0003-daddybound-native-live.md) for mode controls,
CD/DO/AD behaviour, failure outcomes, split-DNS limits and evidence provenance.

## What "first principles" means here

Daddybound implements the DNS and DNSSEC **protocol and trust logic** itself.
It does not implement cryptographic mathematics itself, and it does not
implement wire serialisation itself.

| Daddybound writes | Daddybound uses |
| --- | --- |
| Which key may sign what | `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/sha*` |
| Whether a DS authenticates a DNSKEY | `github.com/miekg/dns` for RR types, parsing and packing |
| Whether an RRSIG is admissible | |
| What bytes a signature covers | |
| How a chain of trust is walked | |
| What each outcome means, and what it is entitled to claim | |

No validating resolver implementation produces a Daddybound verdict.
libunbound and BIND's `delv` appear in this repository only as differential
test oracles — the first behind a build tag no shipped build sets, the second
invoked as a subprocess from a test and never linked. See
[validation-lab.md](validation-lab.md).

Every rule Daddybound enforces is traced to a sentence in a standard.
[standards.md](standards.md) is the record: it quotes the source text, gives
each rule a stable identifier, and the code cites those identifiers. A rule
with no identifier is either a bug or an invention.

## What Daddybound does

- Walks a chain of trust from a configured trust anchor through DS and DNSKEY
  records to a signed RRset.
- Verifies RSASHA256, RSASHA512, ECDSA P-256, ECDSA P-384 and Ed25519
  signatures; can verify RSASHA1 and refuses to rely on it by default, which
  is what RFC 9905 asks of an implementation and an operator respectively.
- Matches DS records using SHA-1, SHA-256 and SHA-384 digests.
- Validates authenticated denial of existence with NSEC and NSEC3: NXDOMAIN,
  NODATA, empty non-terminals, wildcard expansion and insecure delegation,
  including NSEC3 closest-encloser proofs and opt-out.
- Reaches RFC 4033's **Insecure** only by proving something, never by failing
  to. Two routes qualify: an authenticated denial record at a delegation
  showing NS present and DS absent, and an authenticated NSEC3 Opt-Out span,
  which RFC 5155 §12.2 says cannot prove non-existence and §7.1 says may only
  omit unsigned names. Never for a missing signature, an unsupported
  algorithm, a timeout, or any other flavour of "could not prove Secure".
- Bounds the work an NSEC3 response can demand, by iteration count and by
  total hash computations, and refuses rather than downgrades when a response
  exceeds it.
- Follows **CNAME chains**, validating each hop from the trust anchor down and
  reporting the weakest link's verdict. A signed alias into an unsigned zone
  is Insecure however well signed its destination is; neither the first hop's
  classification nor the last is inherited.
- Follows **DNAME redirections** (RFC 6672), authenticating the DNAME RRset and
  recomputing the substitution from it. The server-synthesised CNAME is never
  read: RFC 6672 §5.3.1 requires it to be unsigned, so its target is whatever
  the sender wrote.
- Validates **QTYPE=ANY** per RFC 6840 §4.2 — every RRset received at the
  queried name must validate — and refuses to authenticate an empty ANY
  answer, because no NSEC or NSEC3 type bitmap can deny a query type.
- Bounds a chain by hops and by a visited set, so a loop or a long chain
  produces Indeterminate with a resource reason rather than an accusation
  against the zone.
- Produces a deterministic, structured trace of every step, with typed
  reasons rather than English strings.
- Binds every authenticated client RRset to a cryptographic receipt for its
  exact canonical data, including negative SOA data; an independent response's
  verdict cannot authenticate it. Unsigned aliases do not exempt signed
  targets from validation. Cached material is checked against current anchors
  and time, with accepted-signature lifetime constraining TTLs.
- Applies bounded native client admission and end-to-end deadlines; failures
  have explicit reasons and Extended DNS Errors for EDNS clients.
- Runs a deterministic signed laboratory offline, and compares its verdicts
  against two independent reference validators — libunbound and BIND's
  `delv` — over the same served records.
- Compares those verdicts against the **live Internet** in a separate,
  opt-in run: several hundred real names, most of them sampled from a public
  ranked list by rank arithmetic rather than chosen, each put to the same two
  oracles. See [validation-lab.md](validation-lab.md).

## What Daddybound does not do

Stated plainly, because the credibility of the list above depends on this one
being complete:

- **No aggressive use of NSEC or NSEC3** (RFC 8198). Denial proofs are checked
  when a response carries them; they are never used to answer a question that
  was not asked.
- **One remaining zone-cut assumption, and only where the resolver cannot
  see.** Reading through the native resolver, zone cuts are established from
  referrals actually followed. Reading through a forwarder, which cannot see
  the path, the walk still assumes a name with no proof either way is not a
  zone cut. That can cost a false Bogus and cannot produce a false Secure —
  argued in standards.md §5.5 and measured by a property test that strips every
  delegation proof and checks no verdict strengthens.
- **No encrypted transport to authoritative servers.** Native recursion speaks
  ordinary DNS over port 53. There is no DoT or DoH to the root or to a TLD,
  because authoritative servers do not offer it; QNAME minimisation limits what
  each server on the path learns, and does not remove the exposure.
- **No native conditional forwarding.** Native Live does not route private
  split-DNS names to configured forwarders. Deployments that require that path
  should select Learn or Off until conditional forwarding is implemented.
- **No production-readiness claim.** New deterministic client tests establish
  specific correctness properties. They do not replace target-device load
  testing, extended field use, independent review or real rollover evidence.
- **No ENS, no CCIP Read, no blockchain naming.**

What it does do that this list used to deny: it resolves for itself, from root
hints to the authoritative servers, and validates the records it fetched — see
`internal/daddybound/recursive` and `internal/daddybound/native`. And it
follows RFC 5011 trust-anchor rollover over a persisted trust point, so a key
the root announces and signs for can become an anchor after a thirty-day
hold-down, and a self-signed revocation withdraws one. The compiled-in digests
seed that and are never discarded: a lost state file costs hold-down progress,
not the ability to validate.

## Trying it

```
dnsdaddy daddybound lab          # the laboratory hierarchy and its trust anchor
dnsdaddy daddybound scenarios    # every scenario and why it exists
dnsdaddy daddybound validate     # run them and report each verdict
dnsdaddy daddybound validate -scenario tampered-answer -trace
```

These commands build a signed hierarchy in memory. They cannot be pointed at
a running deployment. Runtime mode is controlled separately by configuration
or the dashboard; the Assurance page and `GET /api/v1/dnssec/status` report
effective mode, native counters, anchor lifecycle and observation losses.
Learn rows use `resolution: native`; Live rows use `resolution: native_live`
and describe the exact native client result. Changing mode does not relabel
historical evidence. The import-graph test permits only the narrow native and
observation seams and keeps lab/oracle packages out of the query path.

The live differential corpus is a separate, opt-in test rather than a
subcommand, for the same reason it is not in CI — it needs the network, both
reference validators, and several minutes, and its result depends on the state
of other people's zones:

```
make corpus
```

## The documents

| | |
| --- | --- |
| [validation-model.md](validation-model.md) | What Daddybound proves and what it assumes, separated line by line |
| [standards.md](standards.md) | Which RFCs were read, what they say, and the identifier each rule is cited by |
| [architecture.md](architecture.md) | The packages, the dependency direction, and why the seams are where they are |
| [security-model.md](security-model.md) | What Daddybound is trusted with, what it is not, and how that is enforced |
| [ADR 0003](../decisions/0003-daddybound-native-live.md) | Native Live answer binding, mode controls, failure semantics and limits |
| [validation-lab.md](validation-lab.md) | The laboratory, the scenarios, and the differential comparison |
| [roadmap.md](roadmap.md) | What comes next, and what each step unblocks |
