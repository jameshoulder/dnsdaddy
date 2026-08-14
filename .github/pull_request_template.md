<!--
Thank you for contributing.

Security-sensitive changes should not be discussed in a public PR before the
issue is fixed. See SECURITY.md.
-->

## What this changes

<!-- What and why. If it fixes an issue, "Fixes #123". -->

## Why

<!--
The reasoning, not just the mechanism. This codebase comments the *why*
extensively — a reviewer should not have to reconstruct your thinking from the
diff, and neither should whoever reads it in two years.
-->

## How it was tested

<!--
What you actually ran. "make test passes" is the floor, not the answer.
-->

- [ ] `make test` passes
- [ ] `make test-race` passes
- [ ] `make lint` passes
- [ ] Tested against a running instance

---

## If this touches detection

Skip this section if it does not.

- [ ] **A benign corpus exists**, not only a malicious one. For every pattern
      worth detecting there is legitimate traffic sharing its most obvious
      property — a CDN against a tunnel, a mail server against a TXT channel, a
      stale search suffix against an NXDOMAIN burst. If you cannot construct
      that corpus, the false positives are not yet understood.
- [ ] **No single signal can raise a finding**, or the detector gates on the
      one signal that defines it.
- [ ] **The bands are published** in the finding, so the score can be
      reproduced by hand.
- [ ] **State is bounded.** No unbounded map fed by network input.
- [ ] **ATT&CK mappings carry a rationale**, and anything that describes what
      the behaviour *would* be if malicious is marked `hypothesis: true`.
      No mapping at all is better than a decorative one.
- [ ] **`Enforces` is false.** Behavioural detection alerts; it does not block.
      Changing that is a separate discussion requiring a measured
      false-positive rate.
- [ ] **Maturity is `experimental`** unless there is a measurement to justify
      otherwise.

## If this touches the resolution path

- [ ] No new allocation on a blocklist miss (the overwhelmingly common case)
- [ ] Nothing added that can block, delay or fail a DNS answer
- [ ] `make bench` shows no regression

## If this changes behaviour visible to a user

- [ ] `CHANGELOG.md` updated
- [ ] `dnsdaddy.example.yaml` updated, if configuration changed
- [ ] `internal/api/openapi.yaml` updated, if the API changed — the spec is
      served to clients, so letting it drift defeats the point
- [ ] `docs/capabilities.md` updated, if this adds or changes a capability

## Claims

- [ ] Everything this PR states in documentation is implemented by the code in
      it. Nothing planned is described in the present tense.

<!--
This is the project's central rule. A security tool that describes intentions
as capabilities is worse than one that describes less, because someone will
rely on the missing part.
-->
