# Decision records — "why was this blocked?"

**Status:** new in v0.3. Off by default.

The question this answers: *DNS Daddy blocked something. Which source said so,
when, how confident was it, and what policy turned that into a block?*

Before this, the query log said `Blocked by your custom block-list` and that
was the whole of it. The sentence was written at block time and then the
reasoning was gone — you could not ask which feed listed the domain, when it
first appeared, or whether anything else agreed.

---

## What a record contains

```
Decision  dec_7b1e04c9a2f3            2026-09-03 10:44:12
Subject   evil.example (domain)       A record
Client    workstation-14 (192.0.2.10)
Action    BLOCKED                     Completeness: complete
Path      network:Office → policy:Standard → category:malware → BLOCK

  "Blocked because URLhaus listed as malware."

Evidence cited
  URLhaus            feed        high confidence    caused
  Daddybound         validation  observe mode       observed
```

Five things are stored, and each answers a different question:

| Field | Question |
|---|---|
| `rule` | Which step of policy evaluation reached the verdict — allow-list, block-list, category, reputation |
| `policyPath` | How the decision was reached, readably |
| `explanation` | The sentence, **as written at the time** |
| cited evidence | Which claims existed, each with the role it played |
| `completeness` | Whether that evidence list is the whole list |

### Roles: only one of them is a cause

Every cited piece carries a role, because a list of claims with no roles reads
as a list of reasons:

| Role | Meaning |
|---|---|
| `caused` | The evidence the outcome turned on. |
| `contributed` | Part of the reasoning without changing the outcome — the feed listing that an allow-list win overrode. |
| `observed` | An engine that looked and **cannot** change an outcome: Daddybound in Learn mode, the behavioural detectors, the first-seen index. |

The distinction is the whole point of storing observations at all. Daddybound
concluding *bogus* on a query that was also blocked did not block it and could
not have; a record that listed the two side by side with nothing to separate
them would read, to anybody skimming, as if DNSSEC validation had refused the
answer. There is no code path that writes an observation with any role but
`observed`, and `TestAnObserveEngineIsNeverCaused` fails if one
appears.

### Completeness: three states, because "no evidence" has three causes

A record says `complete` or `truncated`. A query with no record at all reports
`missing`, and the response says which kind of missing:

* nothing decided it — it was resolved normally, and there was never anything
  to record;
* something decided it, but the record was dropped under load, or the query
  predates the feature being switched on;
* the query log names a decision the decisions table does not hold, which is
  what a drop between two independent writers looks like from outside.

One empty evidence list for all three would make an explanation that was never
written indistinguishable from one that was never needed.
`dnsdaddy_why_missing_total` counts the requests nothing could answer.

At most 16 pieces of evidence are cited per decision, ordered cause first, then
contributors, then observations — so the cap drops the least load-bearing items
rather than an arbitrary slice. Exceeding it sets `truncated`.

---

## The rule that governs all of it

**Everything is written down when the decision is made. Nothing is
re-derived at display time.**

A feed that drops a domain tomorrow must not change why it was blocked today.
That sounds obvious and is easy to get wrong: the natural implementation reads
the current evidence for a domain when somebody opens the explanation, which
produces an explanation that quietly rewrites itself as feeds refresh.

So:

* the explanation is a stored string, not a template rendered on read;
* cited evidence is fetched **by the IDs the decision recorded**, never by
  re-reading the subject;
* `sourceName` is denormalised onto the evidence row, so renaming a feed does
  not blank the explanation of an old block;
* `explanationVersion` moves if the wording rules change, so two explanations
  can be told apart.

`GET /api/v1/evidence/domain/{domain}` is the deliberate counterpart: it says
what is true *now*. The two are kept separate because they answer different
questions and merging them would let one drift into the other.

## No explanation without evidence

`Explain` returns an empty string when nothing was cited, and the dashboard
renders that as "No explanation was recorded for this decision."

There is no branch anywhere that produces a sentence from nothing. A record
that asserts a decision and cannot say why is worse than no record — it looks
like an answer.

---

## Cost, and why it is off by default

One extra write per **decided** query, not per query. That means a block, or an
allow-list hit — the cases where a rule fired and there is something to
explain. Ordinary resolution, which is almost all of it, records nothing, and
the miss path does not even allocate.

An observe-mode engine having looked at a query is deliberately **not** enough
to create a record. Daddybound in Learn mode observes every query that resolves
successfully, so if observations created records then enabling local DNSSEC
validation — a setting about DNSSEC — would quietly convert this table from one
row per block into one row per query. Observations attach to a record that
exists for another reason; they never bring one into being, and
`TestAnObserveEngineAloneDoesNotCreateADecisionRecord` fails if that changes.

The honest caveat on the other side: an allow-listed domain can be asked for
thousands of times a day, and each of those is a decision and a row. If you
allow-list something very busy, that is where the volume goes.

Nothing happens on the resolution path:

1. The policy engine returns a `Basis` alongside its decision, as a pointer
   that is nil unless a rule fired. **The miss path — almost every query —
   allocates nothing and is unchanged**, asserted by
   `TestEvaluateAllocatesNothingForAnOrdinaryQuery`.

   The pointer is not an accident. Carrying the basis inline made `Decision`
   112 bytes larger to zero and copy on every query, measured at roughly
   80ns → 90ns on the miss path. A blocked query now allocates the basis once
   — pinned at exactly one by test — on a path that already allocates a
   response message.
2. The handler offers the decision to a buffered channel and returns. The send
   is non-blocking: a full queue **drops and counts** rather than waiting,
   which is the same discipline the query log already uses. Recording must
   never put SQLite's write latency into a DNS answer.
3. A worker writes the evidence and the decision.

`dnsdaddy_intel_*`-style counters are exposed on the recorder: queued, written,
dropped, failed. A rising `dropped` means records are incomplete — worth an
alert if you rely on them.

---

## Turning it on

```yaml
log:
  decision_records: true
  decision_retention_days: 30
```

Restart. Records appear under **Threats → Why was this blocked?** and at
`GET /api/v1/decisions`.

## Privacy

A decision record stores the domain, the client IP and name, and the policy
context — the same categories of data the query log already holds, for a
smaller number of events. It is covered by `decision_retention_days` and
pruned on the same hourly schedule as everything else.

If query logging is off for privacy but decision records are on, decisions are
still recorded: they answer a different question and are far fewer. If that is
not what you want, leave both off.

---

## What is not here

* **Indicator lifecycle.** A record names the feed that listed a domain and
  what that feed was called, but not how long it had been listed or whether the
  listing has since aged out. `blocklist.Entry` is `{Category, FeedID,
  FeedName}` and carries no first-seen, last-seen or expiry, so those fields do
  not exist to record. Adding them means changing the index a decision reads
  from.
* **No "why" for anything answered before this was on.** The explanation is
  read back from a record written at the time, and none can be manufactured
  afterwards — the feeds have moved on. Those queries report `missing` with the
  reason stated.
* **Observations say an engine looked, not what it concluded.** A Daddybound
  observation carries the correlation id of the row its verdict will land in,
  seconds later, in its own table. The verdict is not copied onto the decision
  because at the moment the decision is recorded it does not exist yet, and
  guessing it would be inventing evidence.
* **No detector findings yet.** Behavioural findings are evidence in the model
  and `KindDetector` exists, but `detect.Engine.Observe` is a channel send that
  returns nothing, so there is no finding to attach at decision time. When one
  attaches it will attach as `observed`, like everything else that cannot
  enforce.

## The audit log

A sibling table with the opposite subject. Decision records say why the
resolver did something to a *query*; the audit log says what an *operator*
changed, and when.

One row per configuration change — policies, networks, API tokens, provider
credentials, mode switches, password changes, session revocations — with the
actor, the source (`dashboard`, `api`, `config-reload`, `seed`), the target, and
the value before and after.

**Always on**, unlike decision records, and it needs no switch because it cannot
be filled by traffic: it grows per operator edit. That is not an incidental
property. An audit log an attacker can flood by sending queries is an audit log
they can erase by sending more of them, so the two tables are kept strictly
apart.

**Secrets are redacted before the write, not on the way out.** A password change
stores `set`; a cleared provider key stores `cleared`. Bcrypt hashes, raw
tokens, provider keys and session material never reach the table at all, because
an audit export is exactly the thing an operator hands to an auditor or a
support engineer. `TestASecretNeverReachesTheDatabase` fails if one gets
through.

**It never delays the change it describes.** The mutation commits, the entry is
queued, and a worker writes batched entries a fraction of a second later. A full
queue drops and counts: failing an operator's already-committed policy update
because its audit row could not be queued would leave them retrying something
that already took effect. `GET /api/v1/audit` returns those drop counts
alongside the entries, so an incomplete log is visible to the person reading it
rather than only in `/metrics`.

```yaml
log:
  audit_retention_days: 90   # 0 keeps everything
```

---

## API

| Route | Purpose |
|---|---|
| `GET /api/v1/queries/{id}/why` | Explains one query-log row from the record written at the time: the stored sentence, the policy path, the cited evidence with roles, and a `completeness` of `complete`, `truncated` or `missing`. |
| `GET /api/v1/decisions` | Recent decisions, newest first. `recording` says whether the feature is on at all — an empty list means different things either way. |
| `GET /api/v1/decisions/{id}` | One decision with the evidence it cited, and which of it decided. |
| `GET /api/v1/evidence/domain/{domain}` | What is known about a domain **now**, with the assessment it supports. |
| `GET /api/v1/audit` | Recent configuration changes, with `written` and `dropped` counts alongside so an incomplete log is visible to the person reading it. |

All five are read-only. There is no route that creates, edits or deletes a
decision or an audit entry, and a test asserts that: a management API that could rewrite a
decision would make the record worthless as evidence.
