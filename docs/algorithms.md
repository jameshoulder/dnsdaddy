# First-party algorithms

DNS Daddy's own decision procedures: the ones where the input is something this
process observed, the decision is Go in this repository, and the output is
evidence plus a reason rather than a number from somewhere else.

This page exists to separate those from the things DNS Daddy merely relays. A
resolver that asks Quad9 whether a name is malicious has outsourced the
decision; a resolver that walks a DNSSEC chain of trust from a root key it
holds has made one. Both can be useful. Only one belongs here.

**What qualifies.** All five:

1. The inputs are names, packets, answers, or streams this process observed.
2. The decision procedure is Go in this repository, documented and unit-tested.
3. The output is structured evidence plus a plain-English reason.
4. The engine supports off / observe / enforce, and enforce is a separate door.
5. Other implementations may be oracles in tests. None may be required at
   runtime.

## The engines

| Engine | Input | Decision | Mode today | Enforce gated on |
|---|---|---|---|---|
| [Client ACL](#client-acl) | source address | serve / REFUSE | **enforce** | shipped; open-resolver combination refused at startup |
| [Per-client rate limiter](#per-client-rate-limiter) | source address, arrival time | serve / REFUSE | **enforce** | shipped; defaults set far above legitimate use |
| [Blocklist policy](#blocklist-policy) | qname | block / allow | **enforce** | shipped; feed health |
| [Daddybound](#daddybound) | chain of trust + answer | RFC 4033 state | **observe** (Learn) | disagreement rate against a trustworthy oracle, and a decided failure mode |
| [Behavioural detectors](#behavioural-detectors) | query stream | finding | **observe** (alert-only) | a published false-positive measurement, [issue #18](https://github.com/jameshoulder/dnsdaddy/issues/18) |

Engines named in the programme but **not yet implemented**, listed so this page
is not read as a complete inventory: a persistent first-seen index, a DNS
rebinding answer filter, a dictionary-based DGA complement, and descriptive
device baselines. None of them exists in the code today.

---

## Client ACL

`internal/clientacl`. Decides which source addresses may use the resolver at
all, from configuration unioned with the dashboard's per-network permissions.

Enforcing since the first release. An address the listener cannot read is
**refused**: an ACL that cannot tell who is asking has not established that the
asker is allowed, which is the only question it is being asked.

## Per-client rate limiter

`internal/ratelimit`. Decides how much of the resolver any one client may take.

**Input.** The client's source address, masked to a prefix, and the time the
query arrived. Nothing else — not the name, not the type, not a reputation.

**Procedure.** GCRA: the leaky bucket written as a deadline rather than a
counter. Per client, keep TAT — the theoretical arrival time, the instant at
which that client would next be exactly at its configured rate. With emission
interval `T = 1/rate` and burst tolerance `tau = (burst-1) * T`, a query
arriving at `t` is refused when `TAT - tau > t`, and otherwise accepted with
`TAT = max(TAT, t) + T`.

That is the whole algorithm. One `int64` of state per client, no background
refill, no goroutine, and any decision it made is reconstructible on paper from
three numbers.

**Output.** A `Decision` carrying the key it was made against, the rate and
burst that applied after overrides, and — on a refusal — how long until the
client would be admitted again, derived from the same deadline the refusal was
so the two cannot disagree.

**Why this one enforces when the detectors do not.** The objection to blocking
on a behavioural detector is that a threshold causes outages. That objection
applies here too, and the answer is not confidence but the kind of claim being
made. A detector deciding "this looks like a DGA" can be wrong about a name. A
limiter deciding "this source has sent 40,000 queries in the last minute"
cannot be wrong about the count. What it can be wrong about is whether that
count is legitimate — which is why the shipped default is 500 queries/second
sustained with a burst of 1,000, far above what any legitimate host does,
rather than a number tuned to catch things.

It is a backstop against saturation, not a quota.

**Four decisions worth knowing about.**

*A refusal does not extend the lockout.* TAT is left where it is when a query
is refused. A limiter that advanced the deadline on every arrival would turn a
client in a tight retry loop into a client locked out for as long as it keeps
trying — a momentary overshoot becomes permanent and the limiter manufactures
the outage it was meant to bound.

*REFUSED, not a drop.* A client that is told no can back off. Silence is
indistinguishable from the resolver being broken. The reply is the question
echoed with an rcode, so it is no larger than what provoked it and gains a
spoofer nothing.

*No query-log row.* Exactly as for the ACL. A client sending faster than it is
allowed to must not be able to convert that into unbounded disk writes, or the
control that bounds one resource becomes a way to consume another. The refusal
is counted in `/metrics` instead, unlabelled — a label per client would put the
same cardinality back in the monitoring system.

*IPv6 is grouped by /64 by default.* This is the trade-off most likely to
surprise. A host using privacy addressing (RFC 8981) holds several addresses at
once and rotates them, so limiting per /128 would see a stream of strangers and
never accumulate enough state about any of them to refuse one. Grouping by /64
gathers a host's own addresses together. The cost is that on a typical LAN,
where every host shares one /64, the IPv6 limit is effectively per-LAN — which
is part of why the default is generous. `ipv6_prefix_length: 128` gives
per-host limiting back, with the rotation caveat.

**Bound.** The tracking table holds at most `max_clients` entries (65,536 by
default — single-digit megabytes). When a shard is full, eviction samples eight
entries, deletes one whose deadline has already passed if it finds one, and
otherwise takes the entry closest to expiring. Both parts matter: the work per
query is constant regardless of table size, and the client furthest over its
limit is never the one evicted. A source-address flood therefore cannot flush
the state of the client being limited. `dnsdaddy_ratelimit_clients_evicted_total`
climbing means either more distinct clients than the table holds or somebody
rotating addresses; both are worth knowing and neither is visible any other way.

**Not solved.** A client behind a reverse proxy the resolver does not trust
appears as the proxy, and shares one allowance with everything else behind it.
DoH and DoT clients identified by a network token, with no usable peer address,
are not rate limited at all — there is no key to accumulate state against.

## Blocklist policy

`internal/policy`, `internal/blocklist`. Decides whether a name is blocked, from
public feeds plus per-policy allow and block lists. Allow-list wins, so an
operator can always override a bad feed entry.

Enforcing. The inputs are third-party feeds, which is why it sits at the edge of
what this page is about: the *decision procedure* is local and explainable, the
*indicators* are not.

## Daddybound

`internal/daddybound`. Walks a DNSSEC chain of trust from a trust anchor to a
signed answer, in pure Go, and reaches one of the four RFC 4033 states.

**Observe only.** In Learn mode it validates the same names clients ask for and
records what it concludes; the answer the client receives is decided entirely by
the resolver. A bogus verdict is a row in a table, not a refused query. `enforce`
is recognised and refused at startup rather than quietly treated as `observe`,
because accepting the word would leave an operator believing their resolver
rejects forged answers when it does not.

libunbound and BIND `delv` are test oracles. Neither is a runtime dependency.

## Behavioural detectors

`internal/detect`. Six detectors over the query stream — beaconing, NXDOMAIN
bursts, DGA-like names, tunnelling, TXT channels, resolution failures — each
emitting a finding with the signals behind it.

**Alert-only, and that is a position rather than a missing feature.** Promoting
any of them to blocking requires a published false-positive measurement against
real traffic, not confidence. The surface-statistics DGA detector in particular
misses dictionary-based generators, which is a known gap rather than a solved
problem.
