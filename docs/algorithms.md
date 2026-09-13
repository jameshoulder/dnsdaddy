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
| [Rebinding filter](#rebinding-filter) | answer records + policy exemption set | strip addresses / empty action | **enforce** | shipped; per-policy exemptions exist and are tested |
| [First-seen index](#first-seen-index) | qname on queries that passed the ACL | novelty signal | **observe** | n/a — there is no enforce door and there will not be one |
| [Blocklist policy](#blocklist-policy) | qname | block / allow | **enforce** | shipped; feed health |
| [Daddybound](#daddybound) | chain of trust + answer | RFC 4033 state | **observe** (Learn) | disagreement rate against a trustworthy oracle, and a decided failure mode |
| [Behavioural detectors](#behavioural-detectors) | query stream | finding | **observe** (alert-only) | a published false-positive measurement, [issue #18](https://github.com/jameshoulder/dnsdaddy/issues/18) |

Engines named in the programme but **not yet implemented**, listed so this page
is not read as a complete inventory: a dictionary-based DGA complement, and
descriptive device baselines. Neither exists in the code today.

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

## Rebinding filter

`internal/rebind`. Decides whether an address may leave this resolver.

**Input.** The A and AAAA records in an answer, the ipv4hint and ipv6hint
parameters of any SVCB or HTTPS record in it, and the exemption set of the
policy the client matched. Nothing else — not the name, not a reputation, not
where the answer came from.

**Procedure.** For each address: unwrap an IPv4-mapped IPv6 address to the IPv4
address it embeds, then test it against the filter ranges. A match that the
policy does not exempt is removed. If the answer had address records and now
has none, the answer section is cleared entirely and the configured empty
action applies.

**Output.** What was removed — owner name, address, matching range, class — and
a sentence for the query log naming the address, the range and the policy that
did not exempt it.

**The threat.** A page loaded from `https://evil.example` is a public origin.
If `evil.example` answers with `10.0.0.1`, the browser will let that page make
requests to a machine on the operator's LAN, because as far as the same-origin
policy is concerned it is still talking to `evil.example`. The router's admin
page, a database bound to loopback, a cloud metadata endpoint at
`169.254.169.254`. Nothing about the DNS is malformed, which is why neither
DNSSEC nor a trustworthy upstream prevents it.

**What it does not inspect.** Addresses embedded in record types that are not
address records: a TXT record containing `10.0.0.1`, or an SRV target that
later resolves to one. The first is not something a client connects to; the
second is a separate lookup, and that lookup is filtered when it happens.

**The cache rule, which is the part most likely to go wrong.** The answer cache
is keyed by question alone, so one entry is shared by every network on the
resolver. Filtering on the way *into* the cache would store one policy's view
and hand it to clients of another — an exempted network would populate the
cache with a private address for everybody, and a non-exempt one would hide a
legitimate answer from the network that is allowed it. So the cache holds the
raw answer and **the filter runs on every serve, cache hits included**. That
costs a pass over the answer section per query and is not an optimisation
opportunity. `TestTwoNetworksNeverReceiveEachOthersView` pins it in both
orders.

Mutating the answer in place is safe only because `resolver.Cache.Get` returns
a deep copy and `reattach` copies again, so the message is this query's
private one. `TestTheCachedAnswerIsNeverMutated` pins that too, because if it
stopped being true the filter would corrupt the cache for every client.

**Exemptions.** Per policy, stored in the database, applied through the same
atomic snapshot the blocking decision comes from — so an exemption added in the
dashboard applies on the next query, and a query is never evaluated against one
policy's rules and another's exemptions. A default route is refused at the
write path, ignored defensively at read time, and reported as a FAIL by
`dnsdaddy doctor`: exempting everything would disable the filter for that
policy while every status display still said it was on.

**Upgrade behaviour.** A fresh install filters. An upgrade does not until the
operator asks, recorded once in the database the way
`local_dnssec_validation` is. Withholding addresses an installation has been
serving for a year is a change to that network, and not one a release should
make on its operator's behalf.

## First-seen index

`internal/firstseen`. Records which registered domains this installation has
ever been asked about.

**Input.** The normalised qname of a query that has passed the client ACL and
the rate limiter. Nothing about the client, nothing about the answer.

**Procedure.** Reduce the name to its registered domain with
`domainutil.RegisteredDomain` (the public suffix list, plus an exclusion list
for private namespaces like `.local`). Hand it to a bounded channel. A worker
collapses repeats into one row update per domain per flush, upserts the batch,
and evicts the stalest rows if the table is over its ceiling.

**Output.** `first_seen`, `last_seen`, `query_count`, and whether the
`first_seen` is provably the true first sighting. Nothing else, and nothing
that reaches a client.

**Observe only, permanently.** There is no enforce door here and there is not
going to be one. A domain being new is not a domain being bad: every
legitimate site was new once, and the first query after a cache flush looks
identical to the first query ever. Novelty is a reason to look, which is a
thing a person does.

**Why a separate table rather than the query log.** "Never resolved here
before" derived from `query_log` is only as good as retention, and at the
seven-day default almost every domain looks new. This table is outside that
window and is not touched by the pruner — `TestThePrunerDoesNotTouchTheIndex`
fails if anybody wires it in, because a weekly reset would make every domain on
the network novel again every Monday.

**Keyed by eTLD+1, not by FQDN.** `attacker1.a.b.example.com` and
`attacker2.c.d.example.com` are one registration and one signal. Keying by full
name would also hand any single domain an unlimited supply of rows, which is
the table-filling attack the bounds exist to stop. Per-hostname novelty is
still answerable from the query log for as long as that lives.

**Installation-wide, not per network.** Two networks asking the same domain
share one row and one `first_seen`. "Has anything here ever asked for this" is
the question a hunt is actually asking; per-network rows would multiply the
table by the number of networks and make the common case harder to answer.

**Bounding, which is the actual design problem.** An authorised client can ask
for unique names forever, and eTLD+1 cardinality is unbounded in practice — new
gTLDs and generated second-level names see to that. Three limits, all shipped:

| Limit | Default | What it stops |
|---|---|---|
| `max_rows` | 100,000 | the table growing without end; ~12 MB, evicting stalest `last_seen` first |
| `max_new_per_minute` | 200 | a flood filling the ceiling in an afternoon |
| the queue | 4,096, drops | the index adding latency when the writer falls behind |

Repeats of known domains never consume the new-row budget. That split is the
point: an attacker minting fresh names is throttled while a network browsing
the same few thousand domains never is.

Eviction is by oldest `last_seen`, not by lowest `query_count`. A domain nobody
has asked for in months is the one whose absence is least likely to be noticed;
evicting by count would discard a domain seen once yesterday in favour of one
seen a thousand times last year, which inverts the signal.

**The honesty problem with eviction.** After a row is evicted and later
re-created, its `first_seen` is when counting restarted, not when the network
first saw the domain — and remembering every evicted name to say so would be
exactly the unbounded thing the ceiling exists to prevent. So the index makes
one claim it can support exactly: a row created **before this installation's
first eviction** cannot have been re-inserted, because nothing had been evicted
yet. That is a single stored timestamp. Records carry `certain: true` when they
predate it; `false` means "cannot prove", not "was evicted".
`dnsdaddy doctor` warns at 80% of the ceiling, before this starts to matter.

**Nothing it can be asked that it answers wrongly.** A lookup returns `new`,
`known` or `unknown`, and `unknown` — the index is off, or the name has no
registered domain — must never be rendered as `new`. An interface that showed
"never seen before" for every domain on an installation with the index disabled
would be the loudest false signal this project could produce.

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

---

## Evidence and why

`internal/decisions`, `internal/store` (`decisions`, `decision_evidence`),
`internal/api/handlers_why.go`.

**This is not an engine and it scores nothing.** No name is classified here, no
traffic is judged, and nothing on this page is decided by it. It is the memory
of what the engines above already decided, and it is documented here only so an
operator knows where reconstruction lives — because the question "why was this
blocked?" is answered from stored evidence, not by re-running anything.

**Reconstruction is reading, never re-deriving.** `GET
/api/v1/queries/{id}/why` reads the decision row and the evidence rows it
cited. It never calls the policy engine and never consults a feed. The reason is
straightforward: feeds change. A domain URLhaus dropped this morning was still
listed last night, and an explanation that re-evaluated the current world would
quietly claim last night's block never had a basis. Every field is stored at
decision time, including the feed's *name*, so renaming or deleting a feed
cannot blank an old explanation.

**Three roles, and only one of them is a cause.**

| Role | Meaning |
|---|---|
| `caused` | The evidence the outcome turned on. |
| `contributed` | Part of the reasoning without changing the outcome — the block-list entry an allow-list win overrode. |
| `observed` | An engine that looked and cannot change an outcome: Daddybound, the detectors, the first-seen index. |

The separation is load-bearing rather than cosmetic. Every observe-mode engine
on this page is observe-mode *by design*, and a record that listed a Daddybound
bogus verdict beside a block with no role attached would read, to anyone
skimming it, as if DNSSEC validation had refused the answer. It did not, it
cannot, and the record says so in a field rather than in prose a client may not
render. There is no code path that writes an observation with any role but
`observed`, and `TestAnObserveEngineIsNeverCaused` fails if one
appears.

**Three completeness states, because "no evidence" has three causes.** A
response says `complete`, `truncated` or `missing`, and a `missing` one says
which kind:

* nothing decided the query — it was allowed normally, and there was never
  anything to record;
* a decision was made but its record was dropped under load, or the query
  predates the feature;
* the query names a decision the decisions table does not hold, which is what a
  drop between two independent writers looks like from the outside.

The alternative — one empty evidence list for all three — would make an
explanation that was never written indistinguishable from one that was never
needed. `dnsdaddy_why_missing_total` counts the requests that could not be
answered.

**Bounded.** One decision cites at most `MaxEvidence` = 16 pieces, ordered
cause first, then contributors, then observations, so the cap drops the least
load-bearing items rather than an arbitrary slice. Exceeding it sets
`truncated`; it is never silently trimmed and reported as the whole story.

**Dropped rather than delayed.** The recorder is a bounded channel with a
non-blocking send. A full queue drops the record and counts it. The answer path
does not wait for SQLite, and it does not wait for the audit writer either —
losing the explanation of a block is a bad day; adding write latency to every
blocked answer is an outage.

**Indicator lifecycle fields: P5.** `blocklist.Entry` is
`{Category, FeedID, FeedName}` (`internal/blocklist/index.go:45`) and carries no
first-seen, last-seen or expiry. So a record can say *which feed* listed a
domain and *what it was called*, but not *how long it had been listed* or
whether the listing has since aged out. That is the honest limit of what is
stored today.
