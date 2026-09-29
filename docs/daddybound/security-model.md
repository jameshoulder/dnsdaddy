# Daddybound security model

## What Daddybound is trusted with

Live (`enforce`) supplies native DNS answers and rejects checked Bogus or
Indeterminate results. This puts recursion, validation, exact-message binding
and their resource controls in the client answer path. Live is experimental;
new installs enable it, existing explicit and recorded choices are preserved.
The full contract is [ADR 0003](../decisions/0003-daddybound-native-live.md).

Learn (`observe`) retains its independent observation contract: the forwarded
client answer is already final, and no Learn result can change it. Off creates
no native runtime and sends no native traffic. Selecting one mode must never
silently run another. Native failures in Live return SERVFAIL, not a forwarded
replacement or an invented Insecure verdict.

## How that is enforced

Three mechanisms, in decreasing order of how hard they are to defeat.

### The import graph

`internal/daddybound/isolation_test.go` builds the module's import graph from
source and asserts two properties:

1. **Only the explicit native and observation seams reach Daddybound from the
   query handler.** The forwarding resolver, policy, blocklist, query log and
   store remain isolated. Lab signers, network corpus sources and reference
   oracle packages cannot be reached from the live query path.
2. **Daddybound cannot reach deployment state.** No package under
   `internal/daddybound` may reach the store, the config, the resolver, the
   policy engine, the query log, the API or the secrets keyring.

The first keeps test authorities and reference implementations out of live
resolution. The second makes verdicts depend on explicit records, trust,
policy and clock values rather than hidden deployment state.

The test reads imports **ignoring build constraints**, deliberately. A
property that holds only because of a build tag is one flag away from not
holding.

The test also asserts that both authorized runtime seams exist, so an
accidentally disconnected Live implementation does not satisfy isolation by
doing nothing.

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
concluded. There is no flag that points this lab command at a running
deployment. Runtime mode controls are separate, authenticated, and explicit
about native transport. A YAML/environment mode locks dashboard changes.

Real Internet names are reachable — the live differential corpus points the
engine at a recursive resolver — but through a test rather than a subcommand.
That is the honest place for it: the corpus needs the network, both reference
validators and several minutes, and what it produces is a comparison report,
not an answer anyone should act on.

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

### Insecure is only ever reached by proving something

RFC 4033's Insecure is a claim, not a shrug: it tells a consumer that unsigned
data here is expected and legitimate. So Daddybound reaches it only from
authenticated evidence, by one of exactly two routes.

**A signed proof that no DS exists** — an authenticated denial record at a
delegation showing NS present and DS absent. This is the ordinary insecure
delegation, and it is the majority of the Insecure verdicts anything will see.

**An authenticated NSEC3 Opt-Out span** covering the name whose absence a
proof depends on. RFC 5155 §12.2 states that opt-out costs "the ability to
prove the existence or nonexistence of an insecure delegation within the span
of an Opt-Out NSEC3 RR", and §7.1 permits a signer to omit only unsigned
delegations from the chain — so a name inside such a span either does not
exist or is unsigned, and §12.2 settles the verdict: "All unsigned names are,
by definition, insecure." This route exists because the alternative is worse:
reporting Secure for a non-existence the standard says is not provable. It is
`R-N3-13`, and the reference validators disagree with each other about it —
libunbound reports insecure, delv reports a validated name error.

Stated in the negative, because every wrong implementation of Insecure is a
downgrade. It is **not**: a missing signature, an unsupported algorithm, a
digest policy refuses, a failed validation, an unexpectedly absent DNSKEY, a
timeout, malformed DNSSEC records, an NSEC3 iteration count above the budget,
or "could not prove Secure". Each of those is Bogus or Indeterminate.

Returning Insecure because an RFC's sentence ends in that word, without the
proof the same RFC requires to reach it, would be a fabricated verdict — and a
fabricated verdict in the one direction an enforcing resolver would read as
permission.

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

The previously recorded comparison against **both** reference validators found
**0 false secures**,
across 78 laboratory scenarios and 612 questions put to the live Internet.
Sabotaging the verifier to accept a signature because one was present — the
classic form of this bug — makes four scenarios report it, which is how we
know the check does something.

The live corpus is the more interesting half of that number, because it is the
half nobody designed. It found two defects on its first runs, both false
Bogus and both in shapes no laboratory scenario reached: a name error whose
closest encloser is the root, and a delegation response carrying the parent's
DS as context. Neither could have produced a false Secure. Both are now
scenarios as well.

See [validation-lab.md](validation-lab.md) for what the evidence does not
cover — and it is a sample of the DNS, not a survey of it.

## Trust anchors

Bootstrap anchors come from local configuration or compiled IANA digests.
The RFC 5011 manager can learn a successor only from DNSKEY material signed
by existing trust and only after the hold-down period. Self-signed revocation
withdraws an eligible key; total trust loss remains Indeterminate and requires
operator attention. State and hold-down progress are persisted separately.

The current anchor snapshot is read for each checked native answer, including
answers whose DNS material was cached. A cached Secure status is never used
to bypass a later revocation. Refresh failures and persistence health are
reported; failed refreshes do not create trust. Algorithm policy remains local
code/configuration, and external intelligence providers cannot change it.

## Policy is never decided by reading text

`Reason` is a typed constant. Human wording is generated from a reason and
never parsed back into one. The reference validator's `why_bogus` string is
carried into reports verbatim, for a person reading a failure, and nothing in
the comparator branches on it — a validator that decided anything by matching
another implementation's error text would be deriving its behaviour from that
implementation, which is the thing this project exists not to do.

## Models do not decide DNSSEC trust

No language model or statistical learner produces, overrides or influences a
DNSSEC verdict. The validator is deterministic code. The separate local
behavioural learner can fit baselines and generate findings, but a probability
of benign behaviour cannot authenticate data, create anchors or overrule a
Bogus/Indeterminate result.
