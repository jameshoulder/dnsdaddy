# Decision records — why a query was allowed, blocked or failed

**Status:** enabled by default for new installations, subject to query-log
privacy settings. Existing records retain their recorded provenance.

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
| `rule` | Which policy or local resolution check reached the verdict — allow-list, block-list, category, reputation, native validation or rebinding protection |
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
* every new decision captures an immutable JSON copy of each cited evidence
  row in the same transaction as its original explanation;
* the capture is independent of the mutable intelligence store. Refreshing,
  renaming, deleting or expiring a feed cannot change that historical copy;
* captured evidence follows the decision's retention period, including its
  source name, original details, confidence, expiry and contribution flag;
* `explanationVersion` moves if the wording rules change, so two explanations
  can be told apart.

**Existing records are not retroactively certified.** Decisions written before
snapshot capture was added return `evidenceSource: legacy_current_reference`
and an explanation of that limitation. Surviving references may have changed
or been removed; an upgrade cannot reconstruct them. New decisions return
`evidenceSource: recorded_snapshot`, including a decision with no citations.

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

## Recording cost and defaults

New installations enable decision records by default. An explicit
`log.decision_records: false` opts out. Recording also requires query logging
to be permitted by both the instance and the applicable policy; enabling
native resolution does not override those privacy settings.

The recorder writes decisions with an actual basis: policy matches, explicit
allow-list decisions, native failures and rebinding refusals. Ordinary
successful queries without such a basis do not create a decision record.

Nothing happens on the resolution path:

1. The policy engine returns a `Basis` alongside its decision, as a pointer
   that is nil unless a rule fired. **The miss path — almost every query —
   allocates nothing and is unchanged**, asserted by
   `TestEvaluateAllocatesNothingForAnOrdinaryQuery`.

   The pointer is not an accident. Carrying the basis inline made `Decision`
   112 bytes larger to zero and copy on every query, measured at roughly
   80ns → 90ns on the miss path. A blocked query now allocates the basis once
   inside the policy engine — pinned at exactly one by test — on a path
   that already allocates a response message. The recorder makes its own
   bounded copy before queueing so that later caller mutation is harmless.
2. The handler offers the decision to a buffered channel and returns. The send
   is non-blocking: a full queue **drops and counts** rather than waiting,
   which is the same discipline the query log already uses. Recording must
   never put SQLite's write latency into a DNS answer.
3. A worker writes the evidence and the decision.

The recorder exposes queued, written, dropped, failed and shutdown-drop
counters through the API. A rising `dropped` means records are incomplete.

---

## Configuration

```yaml
log:
  decision_records: true
  decision_retention_days: 30
```

Explicit configuration takes effect on restart. New decisions appear in the
Investigate view and at `GET /api/v1/decisions`; query explanations link to
what was actually recorded. Enabling the recorder does not backfill earlier
queries or recover evidence that was never captured.

## Privacy

A decision record stores the domain, the client IP and name, and the policy
context — the same categories of data the query log already holds, for a
smaller number of events. It is covered by `decision_retention_days` and
pruned on the same hourly schedule as everything else.

The handler records a decision only when both `log.query_log` and the matched
policy's `logQueries` permit a per-query record. Turning either off also
withholds new decision evidence for those requests. `log.log_client_ip: false`
omits the client address and name. The separate
`log.decision_records: false` switch disables decision recording even when
query logging remains enabled. These switches affect new records; retained
records continue to follow their retention policy.

---

## What is not here

* **A decision for every query.** Ordinary successful queries with no explicit
  policy basis do not create a decision. Explicit allow-list hits, blocks,
  native failures and rebinding refusals do, subject to the privacy switches.
* **More than one piece of evidence per decision.** The rule that fired is cited, and
  it is marked as having contributed. Corroborating evidence that was on file
  but did not change the outcome is not yet attached — the schema supports it
  (`contributed` exists precisely for that) and the assessment layer already
  computes it, but the recorder currently captures only the deciding claim.
* **No detector evidence yet.** Behavioural findings are evidence in the
  model, and `KindDetector` exists, but detectors do not enforce, so they do
  not produce decisions. Investigation presents findings alongside decisions
  without asserting that those findings caused a historical block.

## API

| Route | Purpose |
|---|---|
| `GET /api/v1/decisions` | Decisions newest first, paged by `(time, id)`. `nextCursor` is empty only on the final page. Filter by domain, client, action and `since`/`until` or `hours`. `recording` distinguishes no recorded events from a disabled recorder. |
| `GET /api/v1/decisions/export` | Bounded NDJSON pages including captured evidence and its provenance. Follow `Link` until `X-Truncated: false`; see [exports.md](exports.md). |
| `GET /api/v1/decisions/{id}` | One decision with the evidence it cited, contribution flags, and explicit snapshot/legacy provenance. |
| `GET /api/v1/evidence/domain/{domain}` | What is known about a domain **now**, with the assessment it supports. |

All four are read-only. There is no route that creates, edits or deletes a
decision, and a test asserts that: a management API that could rewrite a
decision would make the record worthless as evidence.

## Local resolution and rebinding decisions

The `native_validation` and `dns_rebinding` rules cite `local` evidence, with
`native` and `protection` as their sources. The claim is the reason captured
by the serving path at the time, not a new reputation lookup or a claim that
the domain is malicious. Evidence confidence describes the recorded local
outcome; it is not a probability of maliciousness.

A native failure with `action: error` has an `ERROR` policy path and a
“Resolution failed” explanation. It is never rendered as `ALLOW` simply
because it was not a category block. Recording remains subject to the
query's privacy configuration. The recorder copies the policy basis before
queueing, so a caller cannot change the explanation by reusing its decision
value after the query has finished.

### Shutdown accounting

On shutdown, the recorder stops accepting events before draining the queue.
An in-flight transaction retains its existing ten-second bound; accepted
queued records then have a separate five-second drain budget. Events left
when that budget expires are counted in both `dropped` and
`shutdownDropped` and reported in the shutdown log. A late offer is rejected
without blocking the DNS caller. Successful drained records include their
captured evidence in the same transaction as during normal operation.
