# Engineering assurance

**The question this document answers:** why should you trust DNS Daddy enough
to *test* it?

Not enough to run it on a network that matters — not yet, and this document is
specific about why not. Enough to spend an hour on it and form your own view.

DNS Daddy is an AI-assisted open-source project. That is disclosed rather than
hidden, because the useful response to "was this written with an LLM?" is
evidence, not reassurance. What follows is the evidence, and — equally
important — what it does not prove.

---

## 1. What is actually checked, and by what

| Control | Where | What it runs on |
|---|---|---|
| Build | `.github/workflows/ci.yml` | every push and PR |
| `gofmt`, `go vet` | CI | every push and PR |
| Unit and integration tests | CI | every push and PR |
| Race detector (`go test -race`) | CI | every push and PR |
| `staticcheck` | `.github/workflows/security.yml` | every push and PR |
| `gosec -severity medium -confidence low` | security workflow | every push and PR |
| `govulncheck` | security workflow | every push and PR |
| Semgrep | security workflow | every push and PR |
| CodeQL | security workflow | every push and PR |
| Trivy (container) | security workflow | every push and PR |
| Fuzzing (`FuzzNormalize`, `FuzzSuffixes`) | security workflow | 60-second smoke run per push; crashers uploaded as artefacts |
| End-to-end smoke test | `.github/workflows/ci.yml` | starts a real resolver, asserts blocking, resolution, tunnel detection, and that an open-resolver config refuses to start |
| Dashboard tests (`node --test`) | CI | every push and PR |
| Documentation link check | CI | every push and PR |
| `go.mod` / `go.sum` tidiness | CI | every push and PR |
| SBOM | security workflow | every push and PR |
| Dependabot | `.github/dependabot.yml` | weekly |
| Pinned GitHub Actions | all workflows | actions pinned by commit SHA |

Run the same checks yourself:

```bash
make test          # go test ./...
go test -race ./...
go vet ./...
gofmt -l .
staticcheck ./...
gosec -severity medium -confidence low ./...
govulncheck ./...
go test -run=Fuzz -fuzz=FuzzSuffixes -fuzztime=60s ./internal/domainutil
```

## 2. Design decisions that are written down

Trusting a security control means being able to read *why* it works that way
and disagree.

| Decision | Where |
|---|---|
| How a query flows through the system | [architecture.md](architecture.md) |
| Assets, boundaries, actors, threats, residual risk | [threat-model.md](threat-model.md) |
| What is implemented vs experimental vs planned | [capabilities.md](capabilities.md) |
| What is stored, for how long | [privacy.md](privacy.md) |
| Every default feed and where it comes from | [threat-intel.md](threat-intel.md) |
| Why each detector fires, and its false-positive shape | [detection/README.md](detection/README.md) |
| The most recent full audit and its findings | [audit-2026-08.md](audit-2026-08.md) |

Security-relevant choices carry their reasoning in the code rather than in a
commit message that nobody will find again. Examples worth reading, because
they are the ones most likely to be wrong:

- `config.validateNotAnOpenResolver` — why the process refuses to start rather
  than trusting the operator to firewall it.
- `dnsserver.Handler.Handle` — why the client ACL is checked before anything
  else, and why the refusal path deliberately writes no query-log row.
- `dnsserver.Handler.observe` — why behavioural detection is alert-only and
  runs after the answer is already decided.
- `httpx.TrustedProxies` — why no forwarding header is believed by default.
- `diag.coverage` — where the client-access analysis is deliberately
  conservative, and which way it errs.

## 3. Invariants the tests are there to protect

Test count is not evidence. These are the properties the suite exists to hold:

- **Behavioural detection can never change an answer.** `detect.TestObserveNeverBlocks`,
  and `detect/invariants_test.go` asserting no detector declares itself
  enforcing. Structurally guaranteed by `Handler.observe` running after the
  response is decided.
- **A blocked domain blocks its subdomains; an allow-list entry always wins.**
  `policy/engine_test.go`.
- **The client ACL is checked before any upstream work, and refusals write no
  log row.** `dnsserver/hardening_test.go`.
- **A forwarding header from an untrusted peer is never believed.**
  `httpx/clientaddr_test.go`, `api/security_test.go`.
- **A failed, truncated or structurally invalid feed keeps the last known good
  index rather than emptying it.** Four cases in `blocklist/manager_test.go`.
- **The index swaps atomically; a query never sees a half-built one.**
  `blocklist/index_test.go`, plus race coverage.
- **Deployment artefacts cannot drift from the binary's defaults.**
  `config/deployment_test.go` — added after a shipped `.env.example` silently
  refused every LAN client.
- **Malformed and pathological DNS names do not panic or blow up CPU.**
  `domainutil/fuzz_test.go`, `dnsserver/handler_test.go`.

## 4. What none of this proves

Read this section twice; it is the honest half.

- **No independent professional security audit has been carried out.** Nobody
  outside the project has adversarially reviewed the DNS parser, the resolver,
  the policy attribution path or the authentication code. This is the single
  largest gap and no amount of CI substitutes for it.
- **Static analysis finds the bugs it has rules for.** A clean `gosec` run
  means no rule matched. It is not a statement about design flaws, logic errors,
  or misuse of a correct API.
- **CodeQL, Semgrep and Trivy are the same.** They are a floor, not a verdict.
- **The race detector only reports races that actually occurred** during the
  tests that ran. Clean does not mean race-free.
- **Fuzzing coverage is narrow, and the CI run is a smoke test.** Sixty seconds
  per target finds shallow bugs and nothing deeper. `domainutil` is fuzzed; the
  DoH request path and the feed parsers are not, and both take hostile input.
- **DNSSEC is not validated locally.** DNS Daddy forwards and records the
  upstream's AD bit. That is a weaker claim than validation and is labelled as
  such throughout.
- **Behavioural detectors are experimental** and their thresholds are
  calibrated against synthetic lab traffic, not against a corpus of real
  networks. They are alert-only for this reason.
- **Performance figures are measured on one machine.** Treat them as an order
  of magnitude, not a specification.
- **There is no reproducible-build guarantee** and releases are not signed
  beyond GitHub's own attestations.

## 5. Reporting something

Security issues: [SECURITY.md](../SECURITY.md). Please do not open a public
issue for a vulnerability.

False positives in threat intelligence have their own issue template, because
they are the failure mode most likely to affect a real user and the one most
useful to hear about.

## 6. Independent review status

**None to date.** If you review any part of this and find something, that
finding is welcome whether or not it comes with a fix — a well-described bug is
worth more than a patch to code the author does not yet understand.

[audit-2026-08.md](audit-2026-08.md#g-where-a-reviewer-should-start) ranks the
areas by risk and says where two to four hours would be best spent.
