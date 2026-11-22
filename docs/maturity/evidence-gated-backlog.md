# Evidence-gated follow-on backlog

These are **follow-on requirements**, not features to implement automatically in
the operator-validation pass. Advance an optional feature when **two independent
deployments** report the same problem, or when **one reproducible consequential
security/reliability defect** justifies it. Do **not** require adoption evidence
before fixing a real security bug.

| ID | Requirement | Evidence gate | Coordination |
| --- | --- | --- | --- |
| EG-1 | DHCP/PTR identity enrichment with source, time, confidence and stale/unknown | Two deployments need lease/PTR naming, or one security defect in identity confusion | Keep manual operator naming |
| EG-2 | Feed-health/provenance improvements | Coordinate with [PR #104](https://github.com/jameshoulder/dnsdaddy/pull/104); do not duplicate while open | Merge or rebase after #104 |
| EG-3 | Temporary policy-scoped exceptions with expiry, history and correct cache behaviour | Recurring false-positive / temporary allow friction in cohort diary | — |
| EG-4 | Webhook receiver/deduplication usability | Operators fail to consume webhooks before asking for new adapters | — |
| EG-5 | Saved investigations | Recurring workflow friction observed across testers | After Investigate usage evidence |
| EG-6 | Read-only export scopes / TOTP | Concrete multi-reader access requirement | Preserve bcrypt + rate limits |
| EG-7 | Map evidence pivots and validated AdGuard coexistence | Map pivot requests from ≥2 deployments; AdGuard only after a measured trial | Pi-hole recipe exists; AdGuard unverified |

## Explicitly deferred

Additional detectors, heuristic blocking, speculative resolver expansion,
endpoint agents, clustering/tenancy, Safe Search enforcement, new intelligence
adapters and decorative map work stay deferred until evidence gates above fire
or a security defect requires action.
