# Stage 5B: index capacity and refresh consistency

Approved scope: P4-I01 (CWE-770/CWE-754, conditional availability and misleading
commit outcome), based on preserved Phase 4 source/tests and execution evidence.
Parent: Stage 5A commit 0eac9b8. No dependency updates, REA/Ghidra, daemon/service
execution, production access, merge, push or deployment.

## Root cause and implementation

Previously startup charged 32 MiB plus candidate and parsing contribution. Refresh
also charged the old live index, so identical data could fit at startup and fail
replacement. Worse, snapshot() had already validated, renamed and published a full
candidate before RefreshFeed()/Refresh() performed a redundant rebuild. That second
build could fail capacity, returning failure despite an already committed first
import and successful history entry.

The remedy reserves a fixed old-index working share at startup too. Publication is
capped at floor((memory_bytes - 32 MiB)/3); candidate/staging peak accounting still
charges before allocating claims, and an oversized external old index is charged
at its actual size. This conservatively reduces cold-start capacity rather than
removing limits or assuming the old index vanishes. All other Stage1–3 network,
HTTPS, redaction, rooted file, record, claim, byte, temporary-space and cancellation
controls remain. A supported unchanged corpus receives the same capacity decision
when initially cached, first imported, or refreshed repeatedly.

Snapshots publish once. Failed downloads never rebuild over a live index. A never
initialized manager can recover its existing valid cache after a provider failure,
while still reporting the provider error. HTTP 304 requires a complete usable
cached candidate before reporting success. Existing published enabled claims are
retained when a different cache becomes unusable. A cold cache load retains its
existing whole-feed skip/report semantics for independent ordinary corrupt feeds;
capacity/cancellation failure publishes no candidate.

Full refresh uses explicit per-feed results and reports partial batch outcomes.
There is no new global multi-feed transaction. Counts/history are recorded after
publication with a bounded cancellation-detached context, so caller cancellation
cannot turn a committed index into a false rollback. Genuine post-commit durability
or metadata failures are explicitly reported as committed warnings. SQLite history
records successful publication and warning together when writable. Runtime
LastFeedOutcome and authenticated API lastFeedOutcome retain the truth when history
cannot be written; no raw filesystem/SQL/feed body/URL secret enters this field.

A separate ingestion mutex serializes cache loads with the entire refresh operation,
including validation. The existing refresh slot still rejects concurrent refreshes.
The lock order is lifecycle read protection -> ingestion -> candidate mutex. DNS
readers use the atomic Holder and do not acquire these locks. Shutdown cancels and
joins operations before closing pinned roots. A review-found inverse ordering was
corrected before final verification, with a concurrent Close/load/refresh regression.

## Changes and security evidence

| Files | Purpose |
|---|---|
| internal/blocklist/ingest.go | Uniform reservation/publication cap; reject loss of published enabled claims; explicit committed results/counts |
| internal/blocklist/manager.go | Single-publication refresh, serialized ingestion, safe lifecycle lock order, 304/cold fallback rules, outcome/history handling |
| internal/store/feeds.go | Preserve successful commit evidence alongside post-commit warnings |
| internal/api/handlers_config.go | Expose latest completed feed outcome to authenticated feed polling |
| internal/blocklist/p4_capacity_validation_test.go | Desired capacity/first-import regressions; exact original Phase4 corpus replay |
| internal/blocklist/stage5b_security_test.go | Parse/record/rename/cancel failures, prior-index retention, corrupt other feed, history failure and concurrent shutdown |
| internal/blocklist/manager_test.go | Failed full refresh now must report an error while preserving cached protection |
| internal/store/stage5b_feed_test.go | Committed warning and subsequent pre-commit failure history |
| internal/api/stage5b_feed_test.go | Authenticated runtime outcome remains accurate when history writes fail |
| docs/threat-intel.md, this report | Capacity preflight, batch/commit semantics, compatibility and limitations |

Original Phase4 reproductions are preserved in Git parent and the external Stage5B
before-copy. At 64/256 MiB, original 24,139/168,979-claim fixtures were accepted at
startup and rejected on refresh; first import could commit and return ErrLimit.
The exact original fixtures are now consistently rejected without commit. Boundary
fixtures at 20,116/140,815 claims (556 accounting bytes per claim) are accepted at
startup/first import and three repeated refreshes; one extra claim is rejected.
These are synthetic fixture capacities, not universal domain-count promises.

Tests additionally assert original pointer/generation/cache retention on failure,
correct last-success/error/counts, no staging leak, no partial malformed Observatory
publication, record-limit rejection, cancellation during candidate generation,
rename failure, successful retry after committed-history warning, corruption of a
previously published other feed, and shutdown with queued cache loads/refresh.
A 304 publication with a count-write warning also retains its actual domain count.
Existing slot contention, policy-change, descriptor, symlink/hardlink, TLS/SSRF,
redaction, password/session/backup regressions remain in the affected suites.
Exact final counts, command exits, commit, hashes and preservation checks are in
stage1/stage5b/SECURITY_REMEDIATION_REPORT.md and its evidence directory.

## API race timeout investigation

The old 300-second run exhausted the package timeout while a newly started existing
network-access test was in newHarness -> store.Open -> schema application. Its
SQLite goroutine was runnable; DB opener/transaction waiters were normal background
workers, not evidence of a deadlock. The old test was only 0 seconds into its own
execution, so the stack represented cumulative suite time, not a 300-second wait
inside that test.

A complete uncached Stage5A API race run with a 20-minute ceiling passed in 409.741s.
An intermediate Stage5B API run also passed in 640.294s while other validation ran.
The formerly interrupted test passed three times in isolation with and without
race detection. A local CPU profile of that test shows race instrumentation and
bcrypt/Blowfish, with SQLite work too. This supports slow cumulative fixture/security
work under instrumentation and validation load, rather than a persistent deadlock.
The profile is a sample of one test, not proof of the whole suite's CPU distribution.
No password cost, security check or concurrency assertion was disabled to pass tests.
Use an explicit adequate CI timeout and retain successful package completion evidence;
never call a timed-out full suite passing. Final-source results are recorded separately.

## Compatibility and residual risks

- Publication capacity is stricter than old cold-start admission. Upgrade preflight
  is mandatory; otherwise a previously accepted oversized cache may prevent a new
  process from starting. Existing main startup returns on resource/cancellation
  failure before opening listeners; that fail-closed policy was not changed. No silent budget increase,
  data deletion, feed splitting or production configuration change is performed.
- This is a conservative accounting envelope, not an OS RSS ceiling. GC lag,
  retained old generations, unrelated daemon work and stalled kernel I/O remain.
  Validate actual representative load and filesystem behavior on Linux before release.
- Full batches commit feed-by-feed. A warning after publication is not rollback.
  Cache/index/history/directory durability cannot form one cross-resource transaction;
  crash/power-loss atomicity is not established by these tests.
- Metadata recording is bounded to five seconds after commit; DB contention or errors
  can leave stale persisted history/counts, explicitly identified by the runtime
  outcome/log. Runtime outcome disappears on restart and is only the latest feed.
- Serialized reloads can wait behind an active import; cancellation is cooperative
  and lock waiting/kernel I/O may delay shutdown. Normal DNS snapshot reads continue.
- No Linux executable was run. ARM64 compilation is build evidence, not Linux
  filesystem/race/runtime evidence or independent binary security verification.
- D01 dependency findings and V01–V05/R03 remain unchanged. Stage5A R01 and previous
  F01–F05 fixes/commits are preserved. Dependency remediation requires separate approval.

Release remains not ready pending dependency and remaining platform/integration
acceptance. Stop after presenting Stage5B; no automatic next stage is authorized.
