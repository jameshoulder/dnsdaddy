# ADR 0002 — Daddybound observe mode

**Status:** accepted
**Date:** 2026-09-09
**Implements:** [issue #63](https://github.com/jameshoulder/dnsdaddy/issues/63)
**Builds on:** [ADR 0001](0001-local-dnssec-validation.md),
[docs/daddybound/](../daddybound/README.md)

---

## The decision in one paragraph

DNS Daddy gains a third runtime mode for local DNSSEC validation, `observe`,
alongside today's `off`. In `observe` the resolver answers exactly as it does
now, and **after** the answer is decided a bounded pool of background workers
asks Daddybound what it concludes about the same name. The verdict is recorded
against the query and exposed through the API, the query log, metrics and the
Assurance page. It changes nothing a client sees. Enforcement is not
implemented, and `enforce` is refused at startup rather than silently treated
as `observe`.

## Why an ADR before any wiring

Daddybound has been deliberately unreachable from the query path since it was
written, and an import-graph test enforced that. This milestone is the first
time that boundary moves. Moving it badly is how a component labelled
experimental acquires a vote on whether a user's DNS request succeeds.

Two questions have to be answered before code, because getting either wrong is
not something a later test catches:

1. **What data does Daddybound validate?** The obvious answer — "the response
   we just returned" — does not work, and §2 explains why.
2. **How does validation reach the network without becoming part of
   resolution?** §4.

## 1. What observe mode must never do

The client-visible response is decided entirely by the existing path. In
`observe` mode Daddybound's verdict must not be able to change:

RCODE · answer, authority or additional RRsets · TTLs · the AD, AA or TC bits ·
which DNSSEC records are present · the policy decision · the blocklist decision
· whether the query is logged · whether the query succeeds at all.

This is stated as an invariant rather than an intention because it is tested as
one: a stub validator is made to return each of Secure, Insecure, Bogus,
Indeterminate, a timeout, a resource-limit refusal and a panic, and the bytes
returned to the client must be **byte-identical** in every case. A verdict that
cannot change the answer is the whole safety argument for this milestone.

## 2. Observe mode validates the name, not the response bytes

This is the most important thing in this document and the easiest to get
quietly wrong.

The intuitive design is `Validate(question, theResponseWeReturned)`. It does
not work, for three independent reasons:

**The response usually carries no signatures.** A client that did not set DO
gets no RRSIG, NSEC or NSEC3 records, because DNS Daddy asks upstream without
DO. There is nothing in those bytes to validate.

**Even with DO, one response is not a chain.** Validation needs the DS and
DNSKEY RRsets of every zone from the root down, and denial proofs for the
delegations in between. Those are separate questions to separate names. A
validator that only ever saw one response could authenticate nothing.

**Without CD, the upstream has already filtered the interesting cases.** A
validating upstream answers a bogus zone with SERVFAIL and no records. If
Daddybound only saw what such an upstream chose to return, it could never
observe a Bogus of its own — it would be a rubber stamp on the upstream's
verdict, which is precisely the thing this milestone exists to avoid depending
on.

So observe mode asks its own questions, with DO and CD set, and walks the chain
from the configured trust anchor. The question it answers is:

> What does Daddybound conclude about (QNAME, QTYPE) at the moment it looks?

**That is not identical to "was the answer we returned authentic".** The two
can differ:

- on a **cache hit**, the client's answer may be minutes old while the
  observation is fresh;
- if the zone **re-signs or changes** between the answer and the observation;
- if the upstream that answered the client and the upstream the observer
  reaches **disagree**.

None of those is a defect, and pretending the distinction does not exist would
make the disagreement matrix meaningless. Every observation therefore records
whether the client's answer came from cache, so analysis can separate the two
populations. Narrowing the gap — recording enough of the client's answer to
tell "the name validates" from "this exact answer validates" — is deliberately
left to a follow-up rather than guessed at here.

## 3. Where the observation happens in the query lifecycle

`dnsserver.Handler.Handle` already has the right seam, and it already has a
tenant: `h.observe(...)` hands each query to the behavioural detection engine
as the last thing on every path, after the response is fully decided. The
comment there gives the reason, and it applies unchanged to a DNSSEC verdict:

> Behavioural detection must not be able to influence what a client is told:
> it exists to explain traffic after the fact, and giving a heuristic a vote
> on an answer is how a false positive becomes an outage.

Daddybound observation goes in the same place, for the same reason.

```
client query
  → ACL           (unchanged; a refused client is never observed)
  → ANY refusal   (unchanged; RFC 8482 answers are not observed)
  → policy        (unchanged)
  → blocked?      → block response ────────────── no observation (§7)
  → resolve       → error? → SERVFAIL ─────────── no observation (§7)
  → query log
  → detection observe
  → DADDYBOUND OBSERVE   ← non-blocking enqueue, returns immediately
  → return the response the resolver produced
```

The enqueue is a non-blocking send on a buffered channel. If the queue is
full it drops and counts the drop. That is what makes "observe mode adds no
latency to an answer" a structural property rather than a benchmark result:
the answer path does a channel send and a counter increment, and never waits
for a validation.

Dropping biases the sample towards quiet periods, so the drop count is exposed.
An operator reading "10,000 observed" must be able to see "and 4,000 dropped"
next to it, or the numbers invite a conclusion the sample cannot support.

## 4. How supporting DNSSEC queries reach the network

Daddybound consumes a narrow interface it already defines:

```go
type Source interface {
    Lookup(ctx context.Context, name string, rrtype uint16) (Response, error)
}
```

The runtime implementation lives in `internal/daddybound/observe` and sends
each question with **DO and CD set** through the operator's own configured
upstreams — the same servers, transports (UDP, TCP, DoT, DoH) and connection
pools the resolver uses, so an operator who chose an encrypted upstream does
not silently acquire plaintext DNSSEC traffic to somewhere else.

### Why the observer does not import the resolver

`internal/daddybound/**` must not import `internal/resolver`, `internal/store`,
`internal/config`, `internal/policy`, `internal/dnsserver`, `internal/api`,
`internal/blocklist`, `internal/querylog` or `internal/secrets`. That rule
exists so a verdict can never depend on deployment state, and it is enforced by
`TestDaddyboundDoesNotReachIntoTheResolver`. **It does not change in this
milestone.**

The observer therefore declares what it needs and lets the wiring supply it:

```go
// Exchanger sends one DNS message and returns the reply.
type Exchanger interface {
    Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}
```

`*resolver.Upstream` already satisfies this exactly. `cmd/dnsdaddy` passes the
resolver's upstreams in; the observer knows nothing about where they came from.
One interface, one method, no dependency.

### What the supporting queries deliberately bypass

They are internal resolver activity, not client activity, and are kept out of
everything that describes client behaviour:

- **the policy engine and blocklist** — a DS lookup for `com.` is not a client
  visiting `com.`, and running it through policy would let an operator's
  blocklist silently break validation;
- **the client ACL** — there is no client;
- **the query log and statistics** — logging them would flood an operator's
  log with names nobody asked for and corrupt every per-domain count;
- **the behavioural detector** — feeding validator traffic to a detector that
  measures client behaviour is a recursive instrumentation loop, and the
  detector would learn to describe the validator;
- **the resolver's answer cache** — §5.

Because supporting queries never re-enter `Handler.Handle`, an observation
cannot trigger further observations. The recursion is one level deep by
construction, not by a depth counter.

## 5. Cache semantics

Two caches, kept strictly apart.

**The resolver's answer cache is untouched.** The observer never reads it,
writes it, annotates it or evicts from it. This is not a policy applied
carefully in several places; it is the absence of any code path between them.
Every question in the brief about cache poisoning through observation —
a Bogus verdict poisoning an entry, a failed observation evicting good data,
validation state attaching to the wrong QNAME, DO/CD/AD leaking between cached
responses — is answered the same way: there is nothing to poison, because the
observation result is never stored in or beside a cached DNS response.

**The observer has its own record cache**, and it is necessary rather than an
optimisation: a chain walk asks for the root and TLD DNSKEY and DS records for
every name it validates, so without one, observing a busy resolver would send
tens of thousands of duplicate questions upstream. It is:

- keyed by `(name, type)` only — never by client, never by the resolver's cache
  key, so a client's DO/CD flags cannot influence what it holds;
- bounded by entry count, with the oldest evicted;
- TTL-respecting, with a ceiling so a hostile TTL cannot pin an entry;
- **never a cache of failures** — a timeout is not evidence about a zone, and
  caching one would turn a transient network fault into a persistent verdict.

**Observations are not reused across queries.** Each observation is recorded
against the query event that produced it and then forgotten. There is no
"validation state" that could go stale and be applied to a later, different
answer, because there is no store of validation state keyed by name.

**Observations run on cache hits as well as misses.** A popular signed domain
would otherwise be observed once and never again, and the failure modes this
milestone exists to find — a key rollover mid-flight, a zone re-signing —
only appear when the same name is re-observed over time. The queue bound, not
a cache-hit filter, is what keeps that affordable.

## 6. Timeouts, cancellation and concurrency

**The client's request context is not used.** It is cancelled as soon as the
response is written, which is before the observation starts; using it would
cancel every observation immediately. The observer holds a base context tied to
process shutdown and derives a per-observation deadline from it.

- **Deadline per observation**, default 2s, configurable. On expiry the walk is
  cancelled and the observation is recorded as `timeout`.
- **Fixed worker pool**, default 2, configurable. This is the concurrency
  bound: at most N validations run at once, whatever the query rate.
- **Bounded queue**, default 256, non-blocking send, drop and count when full.
- **Shutdown** cancels the base context and drains; workers exit.

Repeated timeouts cannot leak work, and that follows from the shape rather than
from care: the pool is fixed-size and the queue is fixed-size, so the number of
goroutines and the amount of queued work are both constant regardless of how
many observations time out. A test asserts the goroutine count is stable across
several thousand forced timeouts.

Daddybound's own internal bounds — chain depth, alias hops, RRsets per
response, NSEC3 iterations and total NSEC3 hashes per validation — continue to
apply underneath all of this. The orchestration bounds here are additional, not
a replacement.

## 7. Paths that are deliberately not observed

- **Policy-blocked queries.** There is no upstream answer to reason about, and
  observing would send queries upstream for names the operator has chosen to
  block — a behaviour change, and one that leaks the blocked lookup.
- **Failed resolution.** No answer exists; an observation would be answering a
  different question.
- **Refused clients.** No query was accepted.
- **RFC 8482 ANY refusals.** The answer was synthesised locally.
- **Malformed queries** rejected before resolution.

These record no observation at all rather than a status meaning "we tried and
could not", because conflating "not attempted" with "attempted and
inconclusive" is exactly the confusion §8 exists to prevent.

## 8. Security verdict and operational outcome are different things

Daddybound returns one of RFC 4033's four states plus a typed reason. Observe
mode keeps the verdict and the reason separate, and maps the operational cases
out of `indeterminate` using the reason rather than by parsing any text:

| Recorded status | When |
|---|---|
| `secure` | Daddybound authenticated the answer or the absence |
| `insecure` | Daddybound proved the data is in an unsigned part of the namespace |
| `bogus` | Daddybound established a secure delegation and the data failed |
| `indeterminate` | Daddybound could not decide, for a reason about the data |
| `timeout` | the observation deadline expired (`ReasonCancelled`) |
| `resource_limit` | an internal bound was reached (`ReasonResourceLimit`) |
| `unsupported` | the shape or algorithm is outside what this build evaluates |
| `internal_error` | the observer itself failed |
| *(no row)* | not attempted — see §7 |

`timeout`, `resource_limit`, `unsupported` and `internal_error` are **not**
RFC 4033 `Insecure`. Insecure is a claim that a proof was offered and showed
the data to be unsigned; an operational failure offered no proof at all.
Recording an inability to validate as a DNSSEC state would let an attacker
manufacture whichever state was cheapest to cause.

No free-form string drives anything. The status and reason code are closed
enumerations; the human-readable reason is stored for a person to read, bounded
in length and sanitised, and nothing branches on it.

The same distinction applies one layer down, to the supporting lookups. Only
NOERROR and NXDOMAIN carry DNSSEC evidence; every other rcode is the upstream
saying it could not answer. Handing a SERVFAIL to the chain walk as though it
were a reply would present a zone's DNSKEY as absent rather than unobtainable,
and Daddybound would correctly conclude Bogus from an incorrect premise — so an
upstream outage or a rate limit would arrive in the disagreement table as a
security finding. Those rcodes fail over to the next upstream, and with none
left the walk reports Indeterminate. These queries set CD, so a validating
upstream has no validation-related reason to SERVFAIL them either.

## 9. Upstream AD stays a separate fact

`dnssec_telemetry` and the `DNSSEC` field on a query event continue to mean
exactly what they meant before: *the upstream asserted it validated this
answer*. That field is not overwritten, not repurposed and not renamed.

The local observation is stored beside it as a new, additive field. The two may
disagree, and that disagreement is the evidence this milestone is for.

Three rules follow, and all three are tested:

- **Daddybound's verdict never depends on the upstream's AD bit.** The observer
  does not read it, and cannot: supporting queries set CD, so the upstream's
  own validation is disabled for them by design.
- **Upstream AD is never presented as local validation.** The API, the query
  log and the Assurance page label them separately and never merge them into a
  single "DNSSEC: secure".
- **A disagreement is recorded, not resolved.** Neither side wins; the counts
  are the output.

## 10. Configuration

```yaml
dns:
  # off | observe.  Default off.
  local_dnssec_validation: off

  # Tuning, only read in observe mode.
  local_dnssec_workers: 2
  local_dnssec_queue:   256
  local_dnssec_timeout: 2s

  # Unchanged, and not the same thing.
  dnssec_telemetry: true
```

`enforce` is recognised by the parser and **refused at startup** with a message
saying it is not implemented. Accepting it and quietly behaving as `observe`
would leave an operator believing their resolver rejects forged answers when it
does not, which is worse than not offering the word at all.

`off` is the default and must be indistinguishable from the previous release:
no observer is constructed, no worker starts, no supporting query is sent, and
the answer path does not gain a branch that touches Daddybound state.

Observations are not separately configurable, and deliberately so. A row names
the domain it validated and carries the id of the query-log row it explains, so
it is governed by the query log's two existing settings rather than by any of
its own: rows are written only when that query would have been logged, and they
expire on `log.retention_days`. A diagnostic feature must not be able to keep
domain names that the operator has told the product not to keep, and an
observation that outlived the query it explains would be a dangling reference
into an empty table.

## 11. What this ADR does not decide

Enforcement, and everything that depends on it: turning Bogus into SERVFAIL,
asserting AD locally, RFC 5011 trust-anchor rollover, and aggressive NSEC use
(RFC 8198). The evidence required before any of that is the subject of a
separate issue, and this milestone exists to produce the first of it.
