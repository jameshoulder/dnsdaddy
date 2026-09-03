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
Action    BLOCKED
Path      network:Office → policy:Standard → category:malware → BLOCK

  "Blocked because URLhaus listed as malware."

Evidence cited
  URLhaus            feed      high confidence     decided this
  listed as malware                                observed 3 days ago
```

Four things are stored, and each answers a different question:

| Field | Question |
|---|---|
| `rule` | Which step of policy evaluation reached the verdict — allow-list, block-list, category, reputation |
| `policyPath` | How the decision was reached, readably |
| `explanation` | The sentence, **as written at the time** |
| cited evidence | Which claims existed, and which one changed the outcome |

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

One extra write per **blocked** query, not per query. Blocks are a small
fraction of traffic, so the cost scales with how much you block rather than
with how much you resolve.

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

* **Allow-list hits are not recorded.** An allow-listed domain can be queried
  thousands of times a day and each is a decision; recording them would swamp
  the table for little benefit. The evidence path for operator decisions
  exists and is tested, so this is a wiring change if it turns out to matter.
* **One piece of evidence per decision.** The rule that fired is cited, and
  it is marked as having contributed. Corroborating evidence that was on file
  but did not change the outcome is not yet attached — the schema supports it
  (`contributed` exists precisely for that) and the assessment layer already
  computes it, but populating it needs the feed pipeline of P2.
* **No detector evidence yet.** Behavioural findings are evidence in the
  model, and `KindDetector` exists, but detectors do not enforce, so they do
  not produce decisions. They will attach as corroborating evidence once P2
  lands.

## API

| Route | Purpose |
|---|---|
| `GET /api/v1/decisions` | Recent decisions, newest first. `recording` says whether the feature is on at all — an empty list means different things either way. |
| `GET /api/v1/decisions/{id}` | One decision with the evidence it cited, and which of it decided. |
| `GET /api/v1/evidence/domain/{domain}` | What is known about a domain **now**, with the assessment it supports. |

All three are read-only. There is no route that creates, edits or deletes a
decision, and a test asserts that: a management API that could rewrite a
decision would make the record worthless as evidence.
