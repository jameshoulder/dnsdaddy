# Daddybound

Daddybound is an experimental DNS resolution and validation engine, written
from first principles in Go. Its first milestone is one thing done properly:
walking a DNSSEC chain of trust from a configured trust anchor to a signed
answer, and being honest about every case where it cannot.

**Daddybound is not a production DNSSEC validator and must not be relied upon
as one.** It answers no queries. It enforces no policy. The DNS Daddy resolver
does not import it, and a test asserts that the query path cannot reach it —
see [security-model.md](security-model.md).

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

## What v0.1 does

- Walks a chain of trust from a configured trust anchor through DS and DNSKEY
  records to a signed RRset.
- Verifies RSASHA256, RSASHA512, ECDSA P-256, ECDSA P-384 and Ed25519
  signatures; can verify RSASHA1 and refuses to rely on it by default, which
  is what RFC 9905 asks of an implementation and an operator respectively.
- Matches DS records using SHA-1, SHA-256 and SHA-384 digests.
- Produces a deterministic, structured trace of every step, with typed
  reasons rather than English strings.
- Runs a deterministic signed laboratory offline, and compares its verdicts
  against two independent reference validators — libunbound and BIND's
  `delv` — over the same served records.

## What v0.1 does not do

Stated plainly, because the credibility of the list above depends on this one
being complete:

- **No denial of existence.** No NSEC, no NSEC3, no authenticated NXDOMAIN or
  NODATA, no wildcard denial proofs. A consequence is that Daddybound can
  never legitimately return **Insecure**, and it does not: where a complete
  validator would, Daddybound returns Indeterminate and names what is missing.
- **No recursive resolution.** It validates records it is given. It does not
  discover them by querying the Internet.
- **No trust anchor rollover** (RFC 5011). Anchors are configuration.
- **No encrypted transports** as part of the engine.
- **No enforcement.** There is no configuration that makes Daddybound decide a
  real answer for a real client.
- **No ENS, no CCIP Read, no blockchain naming.**

## Trying it

```
dnsdaddy daddybound lab          # the laboratory hierarchy and its trust anchor
dnsdaddy daddybound scenarios    # every scenario and why it exists
dnsdaddy daddybound validate     # run them and report each verdict
dnsdaddy daddybound validate -scenario tampered-answer -trace
```

These commands build a signed hierarchy in memory. They cannot be pointed at
the Internet or at a running deployment, because v0.1 performs no recursive
resolution — there is nothing to point at a real name with.

## The documents

| | |
| --- | --- |
| [standards.md](standards.md) | Which RFCs were read, what they say, and the identifier each rule is cited by |
| [architecture.md](architecture.md) | The packages, the dependency direction, and why the seams are where they are |
| [security-model.md](security-model.md) | What Daddybound is trusted with, what it is not, and how that is enforced |
| [validation-lab.md](validation-lab.md) | The laboratory, the scenarios, and the differential comparison |
| [roadmap.md](roadmap.md) | What comes next, and what each step unblocks |
