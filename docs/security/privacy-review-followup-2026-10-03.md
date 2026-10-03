# Privacy review follow-up, 3 October 2026

Baseline: `91ae60740e9ace5b9761920beefed9d30f2285f9`. This integrates the four
Claude patches supplied by the maintainer and addresses the subsequent review.
AI-assisted development and automated tests are not an independent audit or human
sign-off. The larger privacy lifecycle in issue #81 is not closed by this change.

| Concern | Change and regression evidence |
|---|---|
| A failed/no-op chmod could be accepted | Both Docker install and upgrade call the verified permission helper before Compose changes. Failure-injection tests check nonzero exit and no restart/up/down/build. New files are private at creation. |
| Native helper broadened stricter modes or accepted arbitrary owners | Only bits are removed; root/service ownership, service access and group changes are checked. Stricter service-owned modes survive. Root-owned inaccessible modes fail for explicit operator review. Links are refused. |
| Disabled collectors hid historic indefinite retention | Warnings are independent of collection switches. Seeded historical findings/decisions tests check both zero (preserved, warned) and positive (expired) policies. |
| Headerless local proxy remained privileged | Only real API/session authentication grants health detail. A real loopback HTTP reverse-proxy test sends no forwarding headers. Minimal public liveness remains accessible. |
| Doctor could interpret missing health fields as false/zero | Pointer fields preserve unknown state; an optional owner-only token file enables local authenticated checks. Redirects/proxies stay disabled. Token use has normal authentication metadata effects, disclosed in deployment docs. |
| One exhausted cleanup deadline starved other steps | Each sequential table/atomic lifecycle step gets a fresh cooperative timeout. Deadline and shutdown tests check isolation and cancellation. Shared DB outages and oversized deletes can still fail; failure is not hidden. |
| Monitoring omitted no-first-success/missing-instance cases | Sample Prometheus rules and eight scenarios cover those cases, startup, failures, stalls, recovery, restart and scrape failure. Operators must install/reroute rules themselves. |
| Hostname-only disclosure test missed a counting error | A bounded documentation table is compared exactly to feed membership, names, initial URLs, categories and counts. Six enabled feeds/four hosts are confirmed from the baseline catalogue. Malware & C2 is one feed. |

## Validation scope

Nine permission helper tests were executed against the supplied Claude versions:
six fail, with zero test errors. All nine pass against the follow-up helpers.
These run only on synthetic temporary files and never install a service. The
complete local Python suite passes (26 tests, including existing assurance tests).
The standalone cleanup-runner tests pass with the race detector, and the exact
catalogue/disclosure tests pass locally using Go 1.23.2 in standalone-file mode.
That is **not** the project's full Go 1.27.1 build or complete regression suite.

The `Privacy regression evidence` workflow builds/tests the affected packages
with the repository's toolchain and runs the Prometheus rule tests. Its artifacts
record the actual tested commit, outcomes and tool/image identity. Consult the
PR's exact-commit Actions results; a workflow definition or earlier successful
commit is not proof that a later revision passed. Full CI/security/deployment
workflows remain separate and are not weakened by these changes.

## Operator migration and limits

Unauthenticated health is now liveness-only on every topology. Doctor can use
`--api-token-file`; without private detail, doctor/healthcheck report incomplete
readiness rather than asserting that a live ACL is healthy. The container's
built-in liveness check needs no credentials. Existing authenticated dashboard
health reads retain the same fields.

Permission errors stop installation/upgrade rather than stopping an existing
resolver. Rerun the relevant installer after upgrading to apply host-file
permissions. Rebuilding a binary/image alone does not fix an old host `.env` or
native configuration. Review any earlier exposed bootstrap credential and rotate
it where appropriate. Parent-directory trust, ACLs, snapshots and external copies
need separate review; POSIX mode checks are not a universal storage audit.

Expiry-disabled data stays retained. Every step has a 20-second cooperative
budget; a very large dataset may need additional bounded-batch maintenance work.
No new subject-erasure endpoint, retrospective remote deletion, database-wide
encryption, enterprise RBAC, independent certification or guarantee of physical
erasure is introduced. DNS enforcement and anomaly thresholds are unchanged.

References: [Go context](https://pkg.go.dev/context),
[Prometheus rule tests](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/),
[OWASP authorisation guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

## Initial integrated validation correction

The first privacy workflow, run `37135175973` on branch head `8965fdfb`,
reported success but its logs contained failures. Its piped `tee` commands lacked
`pipefail`; that green outcome is **not valid passing-test evidence**. Existing
health and deployment tests still expected unauthenticated private fields, a test
fixture attempted to overwrite a symlinked host command, and promtool could not
write its temporary test store under the read-only container root. No host command
was changed by the denied fixture write.

The follow-up explicitly enables pipefail, tests failure propagation, unlinks only
the temporary fixture command before replacement, migrates the old health tests,
runs the independent cleanup tests without an excluding regex, and supplies an
isolated writable tmpfs to promtool. The production deployment helper also no
longer attempts to obtain private detail by moving a request into the container.
Only the corrected exact-commit reruns establish their respective outcomes.

The first Security run also flagged the new doctor token file's unconstrained
open call. That call now opens the explicitly selected directory as an `os.Root`
and accesses only its leaf, preserving the before/after identity and private-mode
checks, rather than suppressing the scanner rule.
