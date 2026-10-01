# Engineering assurance

DNS Daddy is AI-assisted and experimental. No independent professional security
audit is claimed. This page describes controls and how to inspect their evidence;
configuration of a check is not evidence that the current commit passed it.
Start with the [trust index](../TRUST.md), [capabilities](capabilities.md),
[privacy](privacy.md) and [threat model](threat-model.md).

## Existing engineering checks

The [CI workflow](../.github/workflows/ci.yml) defines build, formatting, vetting,
unit/integration and race tests, dashboard tests, documentation checks and smoke
checks. The [security workflow](../.github/workflows/security.yml) defines
`govulncheck`, Staticcheck, gosec, Semgrep, CodeQL, Trivy source/container scans,
CycloneDX SBOM generation and domain-normalisation fuzz smoke tests. Dependabot
and commit-pinned GitHub Actions are already part of the project.

Inspect the workflow run for the exact commit and its individual job outcomes.
A skipped, failed or unexecuted job is not a passed assessment. Tool versions,
rules, database freshness, suppressions and tested configuration affect coverage.
Several tool installations still use `latest`; reproducible tooling and release
provenance are tracked work, not completed guarantees.

The supplemental [assurance workflow](../.github/workflows/assurance.yml) adds a
machine-readable source dependency candidate inventory, exact CISA KEV correlation,
register validation and offline tests. It retains all severities/unfixed candidates
and marks missing or stale evidence unavailable. See the
[vulnerability process](trust/vulnerability-management.md) for scope and limits.
It does not replace the existing blocking checks or constitute a runtime host scan.

## Security properties to review

Review the invariants, not just a test count: admission before upstream work;
refused clients do not fill query logs; bounded parser and resolver work; cache
and policy attribution isolation; no trust in arbitrary forwarding headers;
authenticated management; meaningful local DNSSEC provenance; privacy settings
across decisions, observations and learning; and alert-only behavioural analysis.
Tests and documentation support these properties but cannot establish every
possible execution or deployment. Expand adversarial and protocol-conformance
coverage as the project matures.

**Local DNSSEC validation is implemented in experimental Daddybound Live.**
Forward/Learn client answers use the selected upstream path; separate Learn
observations do not validate an already-returned answer. Native Live and encrypted
Live have different transport/privacy properties. Fresh installations start in
Forward; saved choices and explicit pins are preserved. See
[encrypted DNS](encrypted-dns.md) and [capabilities](capabilities.md).

**Behavioural findings remain hypotheses.** ATT&CK mapping rationales now distinguish
measurement from adversarial interpretation, including tunnelling and DGA-like
traffic. Previous stored findings are not retroactively rewritten. See the
[mapping policy](detection/mitre.md).

## Evidence that is still needed

Independent adversarial review, broader/longer fuzzing, measured real-world detector
performance, release-specific provenance verification, reproducible-build assessment,
clean-machine deployment and restore exercises, and complete privacy lifecycle tests
remain separate tasks. Existing encrypted backup/restore functionality is not itself
evidence of successful recovery on every supported deployment.

The SQLite database is not wholly encrypted by the application. There is no
all-copies subject-erasure API, and configuration history has no automatic pruning.
Those are explicit [tracked risks](trust/risks.json), not solved by documentation.

Automated scanning finds classes of problems, not a security verdict. Multiple AI
models reviewing the same design are not independent professional review. A named
practitioner review must document actual scope, methods and findings using the
[review record](trust/review-template.md); no such sign-off is created here.
Historical internal documents titled "audit" are point-in-time project records,
not independent certifications. Reporting: [SECURITY.md](../SECURITY.md).
