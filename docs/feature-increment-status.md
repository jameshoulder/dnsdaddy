# Feature increment: acceptance and evidence map

Baseline reviewed: `59cc816d9c2aa12cd367f35c3a18c12a673dd3bb`.
The investigation, policy-preview, review and Daddybound status work was
already present at that baseline. This increment extends those surfaces and
implements the remaining operational controls; it does not relabel the
experimental algorithms as independently validated protection.

## Requested priorities

| Priority | Baseline | Increment and evidence | Remaining limit |
|---|---|---|---|
| **1. Domain and client investigation** | Implemented for recorded activity, decisions, current evidence, findings and Learn observations. | Decision windows now honour both bounds and have continuation cursors. Domain+client findings are filtered before the page limit. Current reviews appear beside findings. Observations use exact retained query correlation for client attribution and distinguish current runtime mode from historical `native_live`/Learn rows. Client views include the current local learning baseline. See [handlers](../internal/api/handlers_investigate.go), [store reads](../internal/store/investigate.go), [API regression tests](../internal/api/investigate_test.go) and [store regression tests](../internal/store/investigate_test.go). | Per-section pages are bounded and truncation is explicit. Missing, private, dropped or pruned query data cannot be reconstructed. A current learning baseline is separate from historical query evidence. |
| **2. Read-only policy preview** | Implemented using the policy engine's compiled rules and cached external verdicts; cache misses were explicitly not evaluated. | Retained and regression-tested as read-only: no provider request, DNS resolution, configuration write or model training. The note now distinguishes policy allowance from DNSSEC/rebinding checks that require an answer. See [preview implementation](../internal/api/handlers_investigate.go), [engine preview tests](../internal/policy/preview_test.go), and `TestPreviewSaysNotEvaluatedRatherThanGuessingAllowed`. | An allowed policy preview does not guarantee successful DNS resolution; answer-dependent validation and rebinding checks are not evaluated. Enrichment is an explicit consented POST. |
| **3. Finding review workflow** | Implemented new/acknowledged/resolved/false-positive states, notes, optimistic versions, authenticated actor and append-only history beside original finding JSON. | Preserved and surfaced in investigations. Original decision evidence now also has immutable snapshots; legacy mutable references are explicitly labelled. See [review store](../internal/store/findingreview.go), [workflow tests](../internal/api/findings_review_test.go), [snapshot tests](../internal/store/decisions_pagination_test.go) and [decision-record documentation](decision-records.md). | A false-positive review is not a domain allow-list entry, detector disable switch or automatic benign training label. |
| **4. Daddybound operational visibility** | Implemented Learn/native transport, anchors, refresh/persistence failures, stored versus observed populations and sample limitations; Live was unavailable. | Runtime status now reports the effective native serving mode, its control/lock state, native query counters, writer loss and the separate Learn path. Recorded query `dnssecSource` distinguishes native from upstream; old rows remain unknown. Local failures record their actual reason as local evidence and `error` is never rendered as allow. See [status](../internal/api/handlers_dnssec_status.go), [mode control](../internal/api/handlers_dnssec_mode.go), [native serving tests](../internal/dnsserver/protection_runtime_test.go) and [native evidence tests](../internal/decisions/recorder_test.go). | Native resolution remains experimental. Historical observations are interpreted from recorded provenance, not today's mode. Native transport uses authoritative DNS over UDP/TCP port 53. |
| **5. Per-client rate limiting** | Not implemented. | Bounded client state, refill accounting, stable attribution and shared overflow capacity; refusal precedes resolution and allocates no per-query record. Operational metrics and versioned controls expose the configuration. See [controller](../internal/protection/protection.go), [controller tests](../internal/protection/protection_test.go) and `TestRateLimitPrecedesResolutionAndAllocatesNoQueryRecord`. | This controls one instance's application work. It is not an upstream volumetric DDoS service, clustering or anycast. |
| **6. DNS rebinding protection** | Not implemented. | IPv4/IPv6, transition addresses, aliases, additional records, SVCB/HTTPS address hints, explicit domain/CIDR exceptions and serving-path tests for native and forwarded cached responses. See [controller](../internal/protection/protection.go), `TestRebindingAddressFamiliesAndTransitions`, `TestAliasesAndAdditionalRecordsCannotObtainDomainException`, `TestSVCBAndHTTPSHintsAreChecked`, and [runtime tests](../internal/dnsserver/protection_runtime_test.go). | Internal and split-DNS deployments need deliberately scoped exceptions. Policy preview cannot inspect an answer that it has not resolved. |
| **7. Change history and backup/restore** | Manual backup guidance; no integrated recovery workflow. | Redacted before/after configuration history with durable pending intent and explicit failure states. Encrypted backups capture consistent SQLite/WAL data, effective/source configuration, verified credential key, trust-anchor state, learner checkpoint and referenced recovery files. Restore targets a fresh offline directory and revokes restored sessions. See [recovery guide](recovery.md), [audit tests](../internal/store/audit_test.go), [backup tests](../internal/backup/backup_test.go) and [API tests](../internal/api/handlers_recovery_test.go). | Restore is an offline operation, not an in-place overwrite of a running resolver. Operators retain the passphrase and must rehearse recovery in their deployment. |
| **8. Complete exports and optional webhooks** | Findings had keyset NDJSON pagination; query/decision exports were missing and decisions had a capped list. | All three datasets now have bounded NDJSON exports with frozen windows, insertion boundaries, next links, valid-line and skipped-record counts. Decision list pagination resolves timestamp ties. Optional signed HTTPS webhooks use a bounded persistent outbox, durable retry/attempt accounting and receiver-side ID deduplication. See [export contract](exports.md), [API export tests](../internal/api/exports_test.go), [webhook implementation](../internal/webhook/service.go) and [webhook tests](../internal/webhook/service_test.go). | Exports are not transactional backups; retention can remove rows between pages, and current review filters can change. Retries are not exactly-once delivery. External delivery is opt-in and requires the operator's own receiver/secret. |
| **9. Measured detector evaluation** | Individual benign/adversarial unit fixtures, with no measured production false-positive rate. | Checked-in training/held-out split, frozen evaluation, an explicit reference rule, confusion counts, abstentions, scenario outcomes and a separate drift experiment. See [evaluation results](../labs/evaluation/RESULTS.md), [learning guide](learning.md), and `TestFrozenEvaluationDoesNotTrainOnHeldOutData` in [persistence tests](../internal/learning/persistence_test.go). | These are labelled synthetic scenarios, not independent real-world efficacy estimates. The results include false alerts, missed low-and-slow traffic and abstentions; no production detection-rate claim is justified. |

## What “learning” means in this build

The native DNS/DNSSEC engine and the statistical learner perform different
jobs. The native engine checks protocol and trust requirements for the actual
answer. The learner observes local traffic, maintains a bounded per-subject
baseline and produces explainable anomaly evidence. Its score alone does not
block a domain.

The learner uses Welford statistics during warm-up, then a clipped
exponentially weighted update. It scores a completed window before deciding
whether to train on it. Blocked/failed queries, anomalous quarantined windows
and windows affected by observation loss do not become the normal baseline.
Readiness requires both elapsed time and adequate samples. State is versioned,
validated on load and checkpointed; it is not a cosmetic counter that resets
whenever the process restarts. See [learning.md](learning.md) for the exact
parameters and privacy aggregation rules.

The checked-in evaluation uses 96 training windows containing 5,760 queries,
then 64 held-out windows containing 3,840 queries: 38 benign-intent and 26
malicious-intent windows. The fitted model scored 50 of those windows:
8 true positives, 4 false positives, 30 true negatives and 8 false negatives.
It abstained on 4 benign and 10 malicious windows. These denominators must
travel with the counts; neither all 64 windows nor all queries were scored.
A separate online drift experiment demonstrates parameter adaptation without
training on the frozen evaluation set. Full scenario limitations are in the
[results](../labs/evaluation/RESULTS.md).

## Evidence corrections included in this increment

The audit found several correctness gaps beneath otherwise completed UI
features:

- A domain+client investigation applied its client filter after taking 50
  findings, allowing another busy client to hide the relevant findings.
- Investigation decision lists ignored their displayed time window, and
  decisions had no continuation after the fixed limit.
- Activity summaries and per-client/domain aggregates did not apply the
  window's upper bound. Client renames could produce duplicate subjects, and
  a domain's last category used lexical order instead of the latest query.
  All sections now use the same time bounds and latest retained attribution.
- Relative-time exports recomputed their lower bound on each page. A long
  collection could lose older records as the window advanced.
- SQLite could reuse the highest deleted row ID, admitting a later backdated
  insertion into an earlier export boundary or reusing an exported query ID.
  Persistent monotonic counters now survive pruning and restart; the
  [migration regression](../internal/store/export_sequence_test.go) also
  preserves legacy IDs, citations and original explanations.
- A malformed stored finding was skipped while still counted as exported;
  pretty-printed JSON could also violate the one-record-per-line format.
- Historical decisions referenced mutable evidence rows. Refresh or deletion
  could change/remove the supposed historical evidence despite an unchanged
  explanation string. New snapshots preserve the original captured evidence;
  older rows are honestly labelled as legacy references.
- The recorder queued a pointer to its caller's basis and returned immediately
  on cancellation. It now copies that basis, drains accepted records for a
  bounded period, and counts/logs shutdown losses.
- Query records did not identify whether an authenticated answer came from
  the upstream or the new native serving path. `dnssecSource` now records that
  provenance when the query is written; migrations do not invent it for old
  rows.
- A saved learner state that cannot load is reported as unavailable, with
  unknown baseline presence, rather than as a disabled learner or an absent
  client baseline. The API omits private paths from the startup error.

The tests above exercise these failure cases, including ties, exact final
pages, late/backdated inserts, client/time filtering, corrupt documents,
concurrent reviews, snapshot deletion/refresh, legacy data and shutdown.
Repository-wide build, race and UI verification is recorded in the pull
request; the unit fixtures do not establish production security efficacy.
