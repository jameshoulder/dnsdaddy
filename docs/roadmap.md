# Roadmap

What might come next, why, and what would have to be true first.

**No dates and no promises.** This is a solo side project. Items are ordered
within each section by how much they would improve the project against how
likely they are to actually happen. Anything here is **not implemented** — see
[capabilities.md](capabilities.md) for what is.

A recurring theme: most of these are blocked on *evidence* rather than on code.
The interesting problems in this project are "how would we know this works",
not "how would we build it".

---

## Near — clear value, understood scope

### Measure the detectors against real traffic

The single most valuable thing that could happen to this project, and it is not
a code change.

Every detector is marked **experimental** because its thresholds are calibrated
against synthetic corpora written from the same understanding of the problem
that produced the detectors. That tests internal consistency; it says nothing
about the false-positive rate on a real network with a mail server, an
endpoint agent and four hundred laptops.

**What it would take:** several deployments willing to run the detectors and
report what fired and whether it was real. Even a handful of "this fires
constantly on X" reports would be worth more than any amount of further tuning
in the dark. That is the most useful contribution anyone could make right now —
see [CONTRIBUTING.md](../CONTRIBUTING.md).

**What it unlocks:** promoting a detector from experimental to available, which
in turn is the precondition for everything in the enforcement section below.

### Per-client query rate limiting

The clearest gap in the [threat model](threat-model.md#t18--denial-of-service-and-resource-exhaustion).
A single authorised client can saturate the resolver, and on a 1 GB box that is
not a high bar.

**Why it is not done:** the interesting part is the failure mode. Refusing
queries from an over-limit client breaks that client's network access, which is
an outage caused by a threshold — the same objection that keeps behavioural
detections from blocking. Needs a considered answer on defaults, per-network
overrides, and what happens to a busy-but-legitimate host.

### A persistent first-seen index

"This domain has never been resolved on this network before" is one of the more
useful signals in DNS security, and
[hunt 5](threat-hunting/README.md#hunt-5--newly-observed-domains) currently
approximates it from the query log — which means it is only as good as your
retention, and at the 7-day default it is close to useless on a general network.

A small separate table of (registered domain, first seen) kept independently of
query-log retention would fix it properly, and would cost very little: it is one
row per domain ever seen, not one per query.

### Webhook sink

The one integration genuinely missing from [siem.md](siem.md). A POST per
finding to a configured URL covers Slack, Teams, PagerDuty and anything with an
inbound webhook, without a client per vendor.

**Needs:** retry policy, a bounded queue, and a considered answer to a slow
endpoint — the same "never block, drop and count" discipline the rest of the
detection path has.

### `safeSearch` enforcement

Accepted by the API and stored on the policy since the first release; the
resolver does not act on it. A known gap, documented in the README and in
[capabilities.md](capabilities.md).

Enforcement means CNAME-rewriting search engine hostnames to their safe-search
variants, which is straightforward but touches the answer path — the one place
where a bug is a visible outage. It has stayed on the list because the risk is
not zero and the benefit is modest.

---

## Medium — worth doing, needs design

### Local DNSSEC validation

The most significant capability gap in the project.
[dnssec.md](dns-security/dnssec.md) is explicit that DNS Daddy records the
*upstream's* verdict and cannot verify anything itself, which leaves
[T11 — compromised upstream](threat-model.md#t11--compromised-upstream-infrastructure)
essentially unmitigated. The AD bit is self-reported, and a lying upstream will
set it happily.

**What it needs:** trust-anchor management including [RFC 5011] rollover,
authenticated denial-of-existence handling (NSEC/NSEC3), a considered failure
mode, and negative-answer caching that does not become a memory problem on a
1 GB box.

**Why it is genuinely hard:** the failure mode is the difficult part, not the
cryptography. Fail-closed on validation failure means a broken signature at a
supplier takes them offline for your whole network — and expired signatures are
the most common DNSSEC event by a wide margin, someone else's mistake becoming
your outage. Fail-open means the validation was decorative. Neither is right as
a blanket default, and getting this wrong is worse than not claiming it.

Realistically this is either a substantial piece of work or a decision to
integrate a library that already does it correctly.

### DNS rebinding protection

Filtering private addresses out of upstream answers.
[T8](threat-model.md#t8--dns-rebinding) currently says, honestly, that this is
not mitigated.

**Needs:** configurable ranges, per-policy exemptions (plenty of legitimate
internal services resolve to RFC 1918 space through a public zone), and care
not to break split-horizon deployments.

### Response-content telemetry

Only the question is logged today, not the answer. That closes off
fast-flux detection, answer-based tunnelling analysis, and any
"resolved-to-what" hunting.

**Needs:** a considered answer to storage — answers are much larger than
questions — and to privacy, since answer records reveal more, not less.

### Behavioural baselining

Everything today uses fixed thresholds. "Unusual *for this network*" is a
better question than "above 200".

**Needs, and this is the blocker:** an answer to poisoning during the learning
window. An attacker present while the baseline is learned teaches the system
that their behaviour is normal — and a baseline that learns continuously
un-learns an ongoing attack. This is a real research problem, not a
configuration option.

### Sigma rules / detection-as-code

The finding schema was designed with this in mind. Exporting the detection
logic as [Sigma](https://sigmahq.io/) rules would let the same detections run
in a SIEM against DNS logs from any source.

**Question worth answering first:** whether the scoring model translates
usefully. Sigma expresses matching conditions; DNS Daddy's detectors express
weighted signals with bands. A Sigma rule for "unique_subdomains > 200" loses
the multi-signal gate, which is the thing that makes the detector usable.

---

## Far — research, or a different project

### Enforcement from behavioural findings

Blocking on a detection, opt-in and per-detector.

**Hard precondition: a published false-positive rate.** Not an intention to
measure one — a measurement. Until the first item on this page has happened,
this cannot responsibly follow.

Even then it should be opt-in, per-detector, severity-gated, and loud about
what it did. The [design principle](detection/README.md#observe-score-explain-alert--never-block)
is not a stepping stone to automatic blocking; it is the position, and moving
off it requires evidence rather than confidence.

### Word-list DGA detection

The current heuristic measures surface statistics and **misses dictionary-word
generators completely** — `silverhorse.com` scores near zero on all four
properties. This is stated wherever the detector is described rather than
quietly omitted.

Detecting these well probably does need a model — n-gram likelihood against a
domain corpus, or a small classifier. Which leads directly to:

### Machine learning, and the conditions for it

**ML stays on this list until three things exist**, and they are not
negotiable:

1. **A defensible dataset.** Labelled DNS traffic, from real networks, with
   known ground truth. Not synthetic, because a model trained on traffic
   generated from your own assumptions learns your assumptions.
2. **A baseline to beat.** The current heuristics, measured on that dataset. A
   model that does not beat four arithmetic measurements is not worth its
   opacity.
3. **An evaluation methodology.** Held-out data, precision and recall reported
   honestly, and a stated position on drift.

Without those, adding ML would make the output *less* trustworthy, not more —
because nobody, including the author, could check it. Four measurements
combined with equal weights can be verified on paper. A model cannot.

**It will not be called AI for marketing reasons under any circumstances.**
Entropy is entropy. If a model is ever added it will be described as what it
is, with its evaluation published, and the heuristics will stay available for
anyone who prefers something they can audit.

### Encrypted-DNS visibility

Identifying clients bypassing DNS Daddy via external DoH. Today the only signal
is *absence* — a host that is clearly online and resolving nothing.

Doing this properly needs flow data or endpoint telemetry, which is a different
class of product. What is realistic here is a *correlation input*: making DNS
Daddy's "hosts seen resolving" list easy to diff against an inventory from
somewhere else.

### Clustering and high availability

One server is one server. Run two and give clients both addresses.

Real HA — shared state, coordinated feed refresh, consistent policy — is a
substantial change to an architecture deliberately built around one process and
one SQLite file. Distributed detection state alone would be a project.

### SSO, RBAC, multi-tenancy

A single admin password and API tokens. Real multi-tenancy would change the
data model throughout.

Worth being honest about scope: DNS Daddy is a self-hosted tool for one
network. An MSP managing forty customers wants something else, and building
towards that would compromise what this is good at.

---

## Things that will not happen

Not "unlikely" — decided.

**A hosted service, a paid tier, or a commercial edition.** Free,
self-hosted, Apache-2.0, permanently. There is no supporter-only build and no
private feature branch.

**Telemetry or phone-home.** No usage statistics, no licence check, no account.

**Blocking on unvalidated heuristics.** See above.

**Threat feeds you cannot inspect.** Every default feed is a public URL listed
in [`internal/catalog`](../internal/catalog/catalog.go). No proprietary
intelligence, no black-box scoring service.

**Statistics labelled as AI.**

---

## Influencing this

The most useful contributions, in order:

1. **Tell me a detector is wrong on your network.** Which one, what fired, and
   why it was benign. This is worth more than any feature request.
2. **Find a flaw in the design.** [SECURITY.md](../SECURITY.md) for anything
   sensitive; an issue otherwise.
3. **Say which of these you would actually use.** The ordering above is one
   person's guess.

[CONTRIBUTING.md](../CONTRIBUTING.md) has the practicalities.

[RFC 5011]: https://www.rfc-editor.org/rfc/rfc5011
