# Milestone: DNS Daddy — Verified Trust

**Priority:** P0  
**Status:** Active foundation (experimental Daddybound)  
**Identity claim to earn:** *don't just trust this resolver — verify what it actually does*

This milestone turns Daddybound's existing laboratory, differential oracles and
standards mapping into an independently reviewable assurance package. It is
not a feature checklist race against Technitium, Unbound, Pi-hole or AdGuard
Home.

## Flagship capabilities this milestone supports

| Capability | What "done" means for Verified Trust |
| --- | --- |
| **Daddybound Verified DNS** | A locally verifiable DNSSEC decision with trust-chain evidence, failure explanation, implementation revision and reproducible test cases. |
| **Explainable Threat Investigations** | Out of scope for the first Verified Trust slice; tracked under Findings/Investigate maturity after DNSSEC evidence is reviewable. |
| **Privacy with verifiable boundaries** | Local-by-default intelligence; external services optional and disclosed. Data-flow inventory is a later gate in this milestone family. |

## Measurable release gates (not a self-awarded score)

| Category | Gate |
| --- | --- |
| DNSSEC | No unexplained differences from reference validators on the supported laboratory corpus |
| Security | Independent review completed; critical findings addressed (later gate) |
| Reliability | Documented long-running reference deployment with failure and recovery notes |
| Performance | Published p50/p95/p99 latency and memory on 1 vCPU / 1 GB |
| Encryption | Tested authenticated TLS paths; demonstrated no plaintext fallback |
| Detection | Real-data false-positive and miss rates with denominators (not claimed yet) |
| Privacy | Published data-flow inventory, retention tests and outbound disclosure |
| Releases | Signed / provenance-verifiable artefacts with SBOM |
| Usability | New user can deploy and verify a real DNS query from the guide |

## Interactive checklist map (P0 shopping list)

Statuses are honest: **available** means repository evidence exists and can be
reproduced; **partial** means substantial evidence with named gaps; **planned**
means not yet an evidence package.

### 1. DNSSEC and resolver correctness

| # | Item | Status | Where the evidence lives |
| --- | --- | --- | --- |
| 1.1 | Comprehensive DNSSEC interop suite vs Unbound and BIND | partial | `make test-daddybound`; `internal/daddybound/differential/` |
| 1.2 | Valid, unsigned, expired, forged, malformed, bad-delegation | partial | `lab.Scenarios` families `positive`, `chain-failure` |
| 1.3 | NSEC/NSEC3 denial, CNAME/DNAME, wildcards, algorithm edges | partial | families `nsec`, `nsec3`, `alias`; algorithm positives. DNAME coverage still thinner than CNAME |
| 1.4 | RFC 5011 rollover, recovery, key changes, clock skew | partial | `trustanchors/`; differential time-model tests |
| 1.5 | Locally validated answers never inherit upstream AD | available | `native/forward_test.go`; observe path uses CD=1 |
| 1.6 | CD=1 handling + documented strict policy for managed clients | partial | `native/client_test.go`; Daddybound README CD semantics |
| 1.7 | Reproducible malicious-DNS laboratory | partial | Offline signed lab + scenario builders; not yet a full packet-adversary / cache-poison harness |
| 1.8 | Independent adversarial code review | planned | External engagement once this package is reviewable |
| 1.9 | Published DNSSEC conformance report | partial | `dnsdaddy daddybound report` / `make daddybound-report` |

### 2. Secure software and deployment

| # | Item | Status | Notes |
| --- | --- | --- | --- |
| 2.1 | Extended Go fuzz (wire, HTTP, TLS/QUIC, feeds, backup) | partial | `make fuzz-daddybound` today; broaden outside Daddybound |
| 2.2 | AuthN, session, tokens, CSRF, SSRF, dashboard controls | partial | Existing security testing docs and CI; deepen for Verified Trust |
| 2.3 | Hardened container/host deployment | partial | Deploy docs + non-root container work; tighten capabilities/read-only FS |
| 2.4 | Verifiable provenance, signed artefacts, SPDX SBOM | partial | Roadmap Phase 2; ship as a release gate |
| 2.5 | Security release gate | planned | No unresolved criticals + protocol tests + recorded approval |
| 2.6 | Independent external audit published | planned | After evidence package is ready |

Sections 3–8 (reliability, encryption/privacy, detection, adoption,
integrations, research/identity) remain on the shopping list. Days 1–30 of
the plan deliberately concentrate on **proving the resolver**.

## How to regenerate the conformance package

```bash
# Offline laboratory agreement with standards (no network, no CGO)
make daddybound-report

# Writes docs/daddybound/conformance-report.md and .json
# Equivalent:
go run ./cmd/dnsdaddy daddybound report -format markdown -o docs/daddybound/conformance-report.md
go run ./cmd/dnsdaddy daddybound report -format json -o docs/daddybound/conformance-report.json

# Differential vs Unbound + delv (optional local deps)
make test-daddybound

# Real-world corpus (network; not a PR gate)
make corpus
```

The report refuses to emit a “green” package if any laboratory scenario
disagrees with the standards.

## What the report claims — and does not

**Claims**

- The offline signed laboratory reaches the verdict each scenario requires.
- Known gaps and no-oracle cases are named.
- The package is regenerable from the same binary and source revision.

**Does not claim**

- Production reliability of Live mode.
- An independent professional security review.
- Zero unexplained differences against Unbound/BIND on every live Internet name.
- Measured false-positive rates for behavioural detection.
- Certification under ISO 27001, SOC 2, Cyber Essentials or HIPAA.

## Suggested 90-day focus (stretch for a single maintainer)

| Window | Focus |
| --- | --- |
| Days 1–30 | Prove the resolver: differential tests, adversarial regression, transport verification, public assurance report |
| Days 31–60 | Prove reliability: long-running workloads, constrained-hardware benchmarks, upstream failure tests, release signing, two-resolver deployment notes |
| Days 61–90 | Make adoption easier: first-run, encrypted-DNS client guides, dashboard verification evidence, honest alpha reliability report |

Prefer one fully tested improvement over ten experimental ones.

## Deliberate non-goals

- Do not rewrite the project in Rust for security theatre; correctness evidence matters more.
- Do not let AI become the authority for DNS safety; the local learner stays an investigation aid without uncalibrated autonomous blocking.
- Do not attempt to out-feature Technitium, Unbound, Pi-hole and AdGuard Home simultaneously.

## Related documents

- [Daddybound overview](../daddybound/README.md)
- [Validation laboratory](../daddybound/validation-lab.md)
- [Standards map](../daddybound/standards.md)
- [Security model](../daddybound/security-model.md)
- [Encrypted DNS](../encrypted-dns.md)
- [Maturity programme](README.md)
- Regenerated report: [conformance-report.md](../daddybound/conformance-report.md)
