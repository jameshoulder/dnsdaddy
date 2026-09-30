# Daddybound

Daddybound is an experimental DNS resolution and validation engine, written
from first principles in Go. It walks a DNSSEC chain of trust from a
configured trust anchor to an authenticated answer, an authenticated absence
or an authenticated redirection — and is honest about every case where it
cannot.

**Daddybound supplies locally validated client answers in experimental Live
mode.** Native authoritative recursion remains the default transport. An
optional encrypted profile obtains answer data through operator-approved DoQ,
HTTP/3 DoH or HTTP/2 DoH recursive endpoints and validates it locally. With
checking enabled, Live serves Secure/proved Insecure answers and fails closed
for Bogus, Indeterminate and operational failures. It never silently changes
transports to obtain a different answer. A new installation starts in
**Forward** (`dns.local_dnssec_validation: off`), using the configured upstreams
without local DNSSEC enforcement. Existing recorded choices, including Live,
and explicit configuration are preserved. Overview and Daddybound can select
Forward, Learn or Live unless configuration pins the mode.
No encrypted endpoint bundle is enabled automatically. Longer operational
evaluation is still required before claiming production readiness.

Learn (`observe`) validates independently after the forwarded answer is final,
so its verdict cannot authenticate or change that answer. Forward constructs no
Daddybound validation runtime and stops its anchor refresh. Forward/Learn client
answers still use forwarding: legacy upstream URLs under the native profile,
or approved encrypted endpoints under the encrypted profile. Native Live and
native Learn use plaintext authoritative UDP/TCP 53 for their own lookups. The
encrypted profile instead uses its approved endpoints for all DNS answer data,
supporting validation material and anchor refresh, without a native or system
DNS fallback.

A client's explicit CD bit skips cryptographic checking in Live while client
admission, policy and rebinding protection remain active; it does not request
a plaintext transport. Daemon background hostname lookups also use the selected
encrypted profile, but do not pass through independent Daddybound Live
validation. Client-to-server encryption and the provider's onward resolution
are separate connections. See [encrypted DNS](../encrypted-dns.md) for the
current transport controls and limits, and the historical
[native Live design](../decisions/0003-daddybound-native-live.md) for its
answer-binding and wire-semantics decisions.

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
- Applies the same local answer-binding and DNSSEC checks to the exact records
  obtained from approved encrypted recursive endpoints. Answer data, DS,
  DNSKEY and denial lookups share bounded query/byte budgets and authenticated
  transport. Upstream AD is not proof of a local Secure verdict.
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
- **No encrypted native authoritative iteration.** This implementation's native
  recursion speaks ordinary DNS over port 53; QNAME minimisation limits what
  each server on that path learns without encrypting it. The optional encrypted
  profile forwards to approved recursive resolvers. It does not claim that
  arbitrary authoritative servers accept encrypted DNS or that the selected
  provider encrypts its onward queries.
- **No native conditional forwarding.** Native Live does not route private
  split-DNS names to configured forwarders. Encrypted Live uses the approved
  endpoints for every name, not per-zone routing, and does not waive local
  trust requirements for a private answer. Split-DNS compatibility still
  depends on the chosen resolver, trust configuration and rebinding exceptions;
  Forward/Learn forwarding is a separate mode choice, not an automatic fallback.
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
effective mode, selected transport, local validation counters, anchor lifecycle
and observation losses. `GET /api/v1/dns/transport` reports the current approved
endpoint configuration and transport counters without sending a test query.
Recorded observation provenance remains immutable:

| Recorded operation | Observation `resolution` | Client query `dnssecSource` |
| --- | --- | --- |
| Native Live | `native_live` | `native` |
| Encrypted Live | `encrypted_live` | `encrypted_forwarded` |
| Native Learn | `native` | `upstream` for the separately forwarded client answer |
| Encrypted Learn | `encrypted_forwarded` | `upstream` for the separately forwarded client answer |

Forward has no new local validation observation; forwarded client answers retain
`upstream` provenance. Blank legacy query sources mean unknown. Changing mode
or transport never relabels historical evidence. The import-graph test permits
only the narrow native and
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
| [Encrypted DNS](../encrypted-dns.md) | Optional encrypted outbound profiles, local validation, recipient and transport boundaries |
| [validation-lab.md](validation-lab.md) | The laboratory, the scenarios, and the differential comparison |
| [roadmap.md](roadmap.md) | What comes next, and what each step unblocks |
