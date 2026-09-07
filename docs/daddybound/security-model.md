# Daddybound security model

## What Daddybound is trusted with

Nothing, currently. That is the design, not a stage of it.

Daddybound reaches verdicts about signed data. It does not act on them, and
nothing in DNS Daddy reads them. It cannot be configured to decide a real
answer for a real client, and no flag, setting or environment variable changes
that.

## How that is enforced

Three mechanisms, in decreasing order of how hard they are to defeat.

### The import graph

`internal/daddybound/isolation_test.go` builds the module's import graph from
source and asserts two properties:

1. **No package on the query path can reach Daddybound.** `internal/resolver`,
   `internal/dnsserver`, `internal/policy`, `internal/blocklist`,
   `internal/api`, `internal/querylog` and `internal/store` are checked
   transitively.
2. **Daddybound cannot reach deployment state.** No package under
   `internal/daddybound` may reach the store, the config, the resolver, the
   policy engine, the query log, the API or the secrets keyring.

The first stops a verdict from an engine labelled experimental reaching a real
answer. The second stops a verdict from depending on deployment state, which
would make it unreproducible from a recorded trace.

The test reads imports **ignoring build constraints**, deliberately. A
property that holds only because of a build tag is one flag away from not
holding.

Both directions were checked by breaking them: adding a blank import of
`daddybound/dnssec` to `internal/resolver`, and of `internal/store` to the
chain walk, each fails the corresponding test.

### The build

Neither oracle can reach a shipped build. libunbound is compiled only when
**both** `CGO_ENABLED=1` **and** `-tags daddybound_unbound` are set; BIND's
`delv` is invoked as a subprocess from a test and is not linked at all. Every
build this project ships sets neither flag:

| | |
| --- | --- |
| `make build` | `CGO_ENABLED=0`, no tags |
| `make release` | `CGO_ENABLED=0` across five platforms |
| `Dockerfile` | `CGO_ENABLED=0` |
| CI build job | `CGO_ENABLED=0` |

So the resolver binary cannot link a reference validator even by accident, and
Daddybound stays pure Go. The `refunbound` package still builds without the
tag; it simply reports that no oracle is available, because a package that
failed to compile without the tag would break `go build ./...` for everyone.

### The command surface

`dnsdaddy daddybound` runs the in-memory laboratory and prints what the engine
concluded. There is no flag that points it at the Internet or at a running
deployment — not because one was withheld, but because v0.1 performs no
recursive resolution and there is nothing to point at a real name with. Adding
a switch that appeared to do so would be the most misleading thing the command
could offer.

## What Daddybound is trusted to say

Within its own scope, one thing matters more than the rest.

### Secure is a claim; Indeterminate is an admission

`StatusIndeterminate` is the zero value. A result that was never filled in
reads as "this validator could not tell", which is both true and safe. Every
budget, every cancellation, every unsupported algorithm and every
unimplemented capability terminates here, with a reason naming what was
missing.

Two rules keep that honest:

- **A limit is never a verdict.** Reaching a bound on lookups, keys,
  signatures or chain depth says something about this validator's
  configuration and nothing about the data. It produces Indeterminate, never
  Bogus and obviously never Secure. Pinned by tests that run correctly signed
  data under four separate exhausted budgets and assert no Bogus appears.
- **Bogus requires the standing to accuse.** RFC 4033 §5 licenses Bogus only
  where there is "a trust anchor and a secure delegation indicating that
  subsidiary data is signed". A failure before that point is Indeterminate.

### Insecure is unreachable, and says so

RFC 4033's Insecure means *signed proof* that no DS exists. Producing that
proof needs NSEC or NSEC3, and v0.1 implements neither. So no code path
returns Insecure. Where a complete validator would — an unsupported algorithm,
an unusable digest, a delegation with no DS — Daddybound returns Indeterminate
with a specific reason. A weaker claim, and a true one.

Returning Insecure because an RFC's sentence ends in that word, without the
proof the same RFC requires to reach it, would be a fabricated verdict.

## The P0 failure class

**Reference validator says BOGUS, Daddybound says SECURE.**

Everything else in this document is a question about correctness. This one is
a validator telling an operator that forged data is authentic.

The differential comparator tests for it **first and unconditionally**, before
the reference-error check, before the equality check, and before the
known-gap exemption. A scenario may annotate a disagreement with a written
justification and thereby rebut a false-Bogus classification; it can never
rebut a false Secure, because `Classify` has already returned by then. No case
added below that line can quiet it.

Current count across the laboratory scenarios, against **both** reference
validators: **0 false secures**. Sabotaging the verifier to accept a signature
because one was present — the classic form of this bug — makes four scenarios
report it, which is how we know the check does something.

That number is evidence about eighteen hand-built scenarios and nothing more.
See [validation-lab.md](validation-lab.md) for what it does not cover.

## Trust anchors

Anchors are supplied as values, from configuration or from a test. There is no
code path that observes a DNSKEY in a response and decides to trust it.

That single rule is what the rest rests on: a validator able to promote an
observed key into an anchor validates only that an attacker is self-consistent.

Runtime code downloads neither trust anchors nor algorithm policy. Both are
code and configuration, reviewed as changes.

## Policy is never decided by reading text

`Reason` is a typed constant. Human wording is generated from a reason and
never parsed back into one. The reference validator's `why_bogus` string is
carried into reports verbatim, for a person reading a failure, and nothing in
the comparator branches on it — a validator that decided anything by matching
another implementation's error text would be deriving its behaviour from that
implementation, which is the thing this project exists not to do.

## No model decides anything

No language model produces, reviews, overrides or influences a DNSSEC verdict.
The engine is deterministic code. There is no path by which a probabilistic
judgement about "probably safe" can reach a status.
