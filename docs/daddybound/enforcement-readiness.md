# Enforcement readiness

**Status: Live mode is unavailable. `local_dnssec_validation: enforce` is
refused at startup and will stay refused until the gate in §5 is met.**

This page exists because "is it ready yet?" deserves an answer with numbers in
it rather than a feeling. It is written for an operator deciding whether to
trust this resolver with their DNS, not for the people who wrote it.

Nothing here proposes shipping enforcement. Read §5 first if you only read one
section.

---

## 1. What Observe measures today, and what Enforce would do to a packet

### Today

Learn mode (`dns.local_dnssec_validation: observe`) validates **alongside**
resolution. The client's answer is produced, sent, and never consulted again by
the validator.

The seam is one non-blocking call. `internal/dnsserver/handler.go:531
observeDNSSEC` runs after the answer is decided, hands the question to a queue
(`handler.go:565`), and returns. If the queue is full the observation is
dropped and the query log says so rather than claiming a verdict
(`handler.go:576-579`). The call is wrapped in a `recover` — not because a
panic is acceptable, but because this runs on the goroutine serving a client
and `miekg/dns` does not recover per request, so an unhandled panic there would
take down every client's DNS rather than one observation
(`handler.go:550-557`). The containment is counted and exposed, so it shows up
as a defect rather than being absorbed (`handler.go:634`).

Only resolved queries are observed. A blocked name has no upstream answer to
reason about, and a failed resolution has no answer at all; both record nothing
rather than a status meaning "we tried and could not"
(`handler.go:525-530`).

What that produces, per query: one of four verdicts — Secure, Insecure, Bogus,
Indeterminate (`internal/daddybound/observe/observation.go:40-50`) — plus a
reason, plus a disagreement class where the local verdict differs from what the
upstream's AD bit claimed. The classes are a closed set of five
(`internal/daddybound/observe/observer.go:486-490`), exported as
`dnsdaddy_dnssec_local_validation_total{status}` and
`dnsdaddy_dnssec_local_disagreement_total{class}`, alongside dropped, panic,
stored, unrecorded and write-error counters
(`internal/api/metrics.go:342-405`).

Defaults: 2 workers, a queue of 256, a 5-second per-observation timeout
(`internal/config/config.go:688-700`).

**So Observe measures agreement, and the rate of each verdict, on this
operator's own traffic. It does not measure what withholding an answer would
have cost.**

### What Enforce would do

Enforce would make a Bogus verdict change the packet the client receives:
SERVFAIL instead of the records, per RFC 4035 §5.5. That is a different kind of
action in every respect that matters.

| | Observe | Enforce |
|---|---|---|
| When it runs | after the answer is sent | before |
| Blocking | never — bounded queue, drop on full | must block, or it is not enforcement |
| Cost of a wrong Bogus | one row in a table | the client cannot reach the name |
| Cost of the validator being slow | a dropped observation | added latency on every query |
| Cost of a panic | contained, counted | contained, but the answer is already late |
| Recovery | read the report | the operator's users are offline until someone notices |

The asymmetry is the whole problem. Every counter in §1 is a measurement of
Daddybound under conditions where being wrong is free. Enforcement's failure
modes appear where being wrong is not free, and no amount of Observe data
reaches them.

---

## 2. Known false-Bogus and assumption paths that remain

A false Bogus is a correctly signed answer this resolver refuses. In Observe it
is a row. In Enforce it is an outage for that name. Three remain, and all three
are deliberate rather than unknown.

### 2.1 The unknown-cut assumption

`internal/daddybound/dnssec/denialwalk.go:123-125`. When a DS is absent, no
authenticated NSEC/NSEC3 settles whether the name is a zone cut, *and* the
record source cannot establish the boundary, the walk assumes "not a zone cut"
and continues in the parent zone.

The bias is one-sided by construction: if the assumption is wrong the data
below is unsigned, nothing a trusted key covers verifies, and the answer is
reported **Bogus where a complete proof would have given Insecure**. It cannot
produce a false Secure — that needs a signature from an apex DNSKEY the walk
already authenticated, and nobody below an insecure delegation holds one. The
property is asserted over every question the reference hierarchy can be asked,
with the delegation answer inverted in both directions
(`TestDiscoveringDelegationsNeverProducesSecure`).

**In Enforce this is the single largest availability risk in the validator.**

### 2.2 netsource has no delegation opinion

`internal/daddybound/netsource/` implements `Lookup` and not `ZoneCutsFor`, so
it is not a `dnssec.DelegationSource`
(`internal/daddybound/dnssec/chain.go:79-82`). Every name it is asked about
therefore lands on §2.1's assumption
(`denialwalk.go:151-154` returns `known=false` on the failed type assertion).

This matters less than it reads: production Learn always constructs the native
recursive resolver (`cmd/dnsdaddy/dnssecobserve.go:90`), which *is* a
`DelegationSource`. netsource is the corpus and diagnostic path. **But it means
the live corpus results in §3 were produced by the code path with the weakest
delegation knowledge**, which is worth knowing when reading them.

### 2.3 The warm-cache floor

`internal/daddybound/recursive/source.go:115-118`. Negative statements — "this
name is not a zone cut" — are only inferred for names at or below the zone the
resolution started in. With a warm cache that is a deep zone, so inference says
nothing above it.

Commit `43ed51f` narrowed this: where inference has nothing to say about the
name it was asked about, `Resolver.DelegationAt`
(`internal/daddybound/recursive/delegation.go:71`) establishes the boundary by
walking down from the deepest already-proven ancestor. The measured gap it
closed was the **failed resolution** — a lame delegation or unreachable child
made the source silent about a cut whose referral was perfectly readable from
the parent, and the walk then reported a real delegation Bogus.

Honest correction to an earlier claim in this repository's own review notes:
the warm-cache floor was reported as leaving the queried name unanswerable, and
measurement against the reference hierarchy showed it does not — inference
already covers the queried name, warm or cold. The floor remains as a
conservative rule; it is not currently known to cost a verdict.

---

## 3. What the corpus proves, and what it does not

`make corpus` puts real names to Daddybound and to two independent reference
validators (libunbound, BIND delv) through two independent resolving views —
Cloudflare `1.1.1.1` and Quad9's unsecured `9.9.9.10`. See
[validation-lab.md](validation-lab.md) for the method.

### The measured slice

An 80-name slice, run 2026-09-15, 84 seconds, both views:

| | |
|---|---|
| Questions | 80 per view |
| Views | 2, each sending its own 116 queries |
| False Secures | **0** |
| Cross-view disagreements | **0 of 80** |
| vs delv | 80/80 MATCH in both views |
| vs libunbound | 77/80 MATCH in both views; 3 STATUS_DISAGREEMENT |

The three are `amazon.com./DS`, `github.com./DS`, `example.invalid./DS`, all in
the `ds-absent` category. They reproduce **identically in both views** and in
**neither view against delv**. They also reproduce on commit `43ed51f`, so they
pre-date the two-view work and are not caused by it.

### What this proves

- Daddybound agrees with two independently written reference validators on
  real names, and **the agreement is not an artefact of one resolver's cache or
  filtering policy** — that is precisely what the second view buys. Before two
  views, a disagreement could not be told apart from a resolver artefact.
- The three `ds-absent` disagreements are a **validator-level difference
  between Daddybound and libunbound**, not noise. Two unrelated resolvers
  produced them identically, and delv sides with Daddybound. That is a real,
  narrow, characterised finding.
- No false Secure appeared in any view. This is the one assertion the run makes
  rather than merely reports, because it does not depend on anyone else's zone
  being healthy.

### What this does not prove

- **80 names is a slice, not the corpus** (612 questions) and the corpus is a
  sample of the DNS, not a survey of it. Nothing here characterises the tail.
- **Zero cross-view disagreements is a null result on a small sample.** It is
  consistent with "Daddybound is insensitive to the resolving path" and equally
  consistent with "80 names was not enough to find one". It is not evidence of
  robustness; it is the absence of evidence of fragility.
- **Two views are two.** A resolver minimising qnames differently again, or
  behind a different transport, could hand over responses neither view
  produced.
- **Every corpus run is an Observe run.** Records are fetched, judged and
  counted; no client ever sees a different answer because of a verdict. The
  corpus measures agreement under working conditions. Enforcement fails under
  *partial* conditions, and there is no measurement of that here at all.
- The corpus reads through `netsource` — the path described in §2.2, with no
  delegation opinion.

---

## 4. Failure modes if Enforce shipped tomorrow

Each of these is a way a correct implementation still takes a network down.

### 4.1 Expired signatures — someone else's operational error becomes your outage

A zone whose operator lets an RRSIG lapse is Bogus to every validating
resolver. In Observe that is a counter. In Enforce every client behind this
resolver loses that name until the zone's operator fixes it — which may be
hours, and is entirely outside the operator's control. This is the commonest
real-world DNSSEC incident and it is not a Daddybound defect; it is the cost of
enforcing.

**Unmeasured:** how often this operator's actual traffic touches a zone in this
state. That is exactly what §5 asks for.

### 4.2 Lame delegations and unreachable children — §2.1's assumption, now load-bearing

A cut whose child servers are broken is still a cut. Before `43ed51f` the
source went silent and the walk assumed "not a cut", descended into the child's
records holding the parent's keys, and reported Bogus. That path is narrowed,
not closed: where the probe also cannot establish the boundary — the source is
not a `DelegationSource` (§2.2), the lookup budget is spent, or the context is
cancelled — the assumption still fires and still costs a false Bogus.

In Enforce that false Bogus is an outage for a name that was fine.

### 4.3 Probe traffic — new packets on a path that used to send none

`DelegationAt` sends real queries. It is bounded three ways: `maxProbeSteps`
(24 label steps, `delegation.go:63`), the probe resolution's own `MaxQueries`
(64, `recursive/resolve.go:53`), and the validator's `MaxLookups`, which the
delegation question is now spent from (`denialwalk.go`, `delegationKnown`).
Established boundaries are memoised for the referral TTL (600s,
`recursive/cache.go`).

**Unmeasured:** the query-rate increase on a real resolver. Bounded is not the
same as small, and on a 1 vCPU / 1 GB machine the difference between "bounded"
and "measured" is the difference between a working resolver and a slow one. In
Observe an overrun costs a dropped observation. In Enforce it costs latency on
every query, on the path where latency is the product.

### 4.4 The two machine sizes disagree about whether this is even on

`cmd/dnsdaddy/main.go:1211 freshInstallLearn`: a fresh 1 GB install starts with
Learn **off**; 2 GB and above start with Learn **observe**. An upgrade never
changes a recorded setting, and an operator's YAML always wins.

The consequence for readiness is uncomfortable and should be said plainly: **the
smallest machines, which are the ones most likely to be hurt by §4.3, are also
the ones producing no Observe evidence at all.** Any gate met by aggregating
across the fleet would be met almost entirely by 2 GB-and-larger boxes, and
then applied to Nanodes that contributed nothing to it. §5 accounts for this.

---

## 5. The gate

Enforce stays refused until **all** of the following have been measured on real
production traffic. These are the conditions, not a prediction of when they
will be met.

**X — what must be measured:**

1. **30 consecutive days** of Learn mode on at least **5 independent
   deployments**, at least **2 of which are 1 GB machines** (§4.4 — the
   fleet cannot be represented by the boxes that find it cheap).
2. **Zero** `local_bogus_upstream_validated` disagreements that are traced to a
   Daddybound defect rather than to the zone. Every instance in that class
   investigated individually and classified; the count of unexplained ones must
   be zero, not small.
3. **A measured false-Bogus rate below 1 in 10⁵ resolved queries**, where a
   false Bogus is any Bogus verdict on a name that libunbound *and* delv both
   accept. Below that rate, enforcing costs roughly one name per deployment per
   day at typical household query volumes; above it, the resolver gets switched
   off, and a resolver that is switched off protects nobody.
4. **The §4.3 query-rate increase measured**, not bounded: Learn on versus Learn
   off, same deployment, same traffic, reported as a percentage of outbound
   queries, with the 1 GB case reported separately.
5. **The three `ds-absent` disagreements of §3 resolved** — either Daddybound is
   corrected, or the difference is documented as a deliberate and justified
   departure from libunbound with the RFC citation that makes it right.
6. **A failure drill**: a deliberate expired-signature zone, enforced, in a test
   deployment, with the operator-facing failure documented — what doctor says,
   what the dashboard says, and how an operator turns it off **without** needing
   working DNS to read the instructions.

**Y — how long:** 30 days minimum for (1), and the measurement window for (3)
must contain at least 10⁶ resolved queries, or the rate is not measured, it is
estimated.

**What is explicitly not on this list:** any form of "the tests pass", "the
corpus is green", or "we feel ready". The tests and the corpus are entry
conditions for *starting* to collect this evidence, and this project already
has them. They are not the evidence itself, and treating them as such is how
enforcement ships early.

**Who decides:** the gate is met or it is not, by the numbers above. If it turns
out one of these is the wrong thing to measure, the honest move is to change
this page and say why — not to meet it in spirit.

---

## What this page is not

It is not a schedule. Nothing here commits to enforcement ever shipping; if the
false-Bogus rate in (3) proves unreachable, the right outcome is that Daddybound
stays an observation tool and this page records why.

It is not a claim that the validator is wrong. Every measurement so far says it
agrees with two independent reference implementations. The argument of this page
is narrower and harder to escape: **agreeing under working conditions is not
evidence about behaviour under failure**, and enforcement is entirely a
question about failure.

## Related

| | |
| --- | --- |
| [validation-model.md](validation-model.md) | What is proved and what is assumed, line by line |
| [validation-lab.md](validation-lab.md) | The laboratory, the oracles and the two-view corpus |
| [standards.md](standards.md) | §5.5 for the zone-cut rules behind §2 |
| [security-model.md](security-model.md) | Where Daddybound sits relative to the answer path |
