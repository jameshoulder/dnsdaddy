# Contributing

Thanks for looking. Bug reports from people actually running this in anger are
the most useful thing you can send.

## Getting set up

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy

make test     # run the suite
make run      # local resolver on 127.0.0.1:5353, data in ./tmp, no root needed
```

Go 1.25.13+. That is the whole toolchain — no cgo, no npm, no code generation.

With `make run` going, query it:

```bash
dig @127.0.0.1 -p 5353 example.com
```

and open <http://127.0.0.1:8080>. The generated admin password is printed on
startup and written to `./tmp/initial-password.txt`.

To test blocking without downloading real feeds, point a feed at a local file:

```bash
printf '0.0.0.0 blocked.example\n' > /tmp/feed.txt
# then add a custom feed with url: file:///tmp/feed.txt in the dashboard
```

## Before you open a PR

```bash
make lint         # vet + gofmt
make test-race    # the concurrency here is load-bearing
```

CI runs both, plus cross-compilation and an end-to-end smoke test that starts
the binary and checks real DNS answers.

## House style

Match the surrounding code. Beyond that:

**Comments explain why, not what.** `// increment the counter` above `c++` is
noise. A note about why a false positive matters more than 25 MB of memory is
worth its line. If a decision has a real trade-off behind it, write the
trade-off down — the next person cannot see the alternatives you rejected.

**Nothing blocks the DNS hot path.** No disk I/O, no database queries, no locks
held across work. If you need data at query time, put it in a snapshot that is
swapped atomically. If you need to record something, hand it to a buffered
channel.

**Third-party input is hostile.** Feed files, DNS messages, and DoH bodies all
come from outside. Parse defensively: skip a bad line, cap a body, never let one
malformed record abort a whole load.

**Errors say what to do.** `policy is assigned to 3 network(s); reassign them
first` beats `constraint violation`. The reader is usually mid-incident.

**Test names state the claim.** `TestLookupDoesNotMatchSiblingSuffix` beats
`TestLookup2`. When a test guards against a specific failure mode, say so in a
comment — future readers should not have to guess whether a strange-looking
assertion is deliberate.

## Testing expectations

New behaviour needs a test. Bug fixes need a test that fails before the fix.

Tests must not depend on the internet or on a third-party feed being up. Use a
local `file://` feed, or the in-process test upstream in
`internal/dnsserver/handler_test.go`.

Areas where a regression would be worst, and where tests are non-negotiable:

- Suffix matching — blocking `evil.com` must block `login.evil.com` and must
  **not** touch `notevil.com`
- Allow-list precedence over every blocklist
- Client → network → policy attribution, including DoH tokens
- Cache correctness: NXDOMAIN staying NXDOMAIN, generation invalidation
- Anything touching authentication

## Adding a threat feed

Feeds go in `internal/catalog/catalog.go`. To be considered as a default it
should be public, free, no-registration, actively maintained, and
security-focused.

New feeds start `Enabled: false` unless they are clearly a security category
with a low false-positive rate. Ads, adult, and gambling stay off by default —
those are preferences, not security controls.

Update [docs/threat-intel.md](docs/threat-intel.md) in the same PR, including
the licence.

## Changing the API

`internal/api/openapi.yaml` is served to clients from every running resolver. If
you change a route or a payload, change the spec in the same commit. A spec that
has drifted is worse than no spec.

## Reporting bugs

Include the version (`dnsdaddy -version`), how it was installed, what you
expected, what happened, and the relevant log lines.

For anything security-sensitive, use [SECURITY.md](SECURITY.md) instead — do not
open a public issue.

## The most useful thing you could contribute

Not code.

Every behavioural detector in this project is marked **experimental** because
its thresholds are calibrated against synthetic traffic written from the same
understanding of the problem that produced the detectors. That tests internal
consistency. It says nothing about what they do on a real network with a mail
gateway, an endpoint agent and four hundred laptops.

**If a detector fires on something harmless on your network, that report is
worth more than any feature.** There is
[an issue template](https://github.com/jameshoulder/dnsdaddy/issues/new?template=false-positive.yml)
for it. Naming the vendor or product is especially useful, because it may
belong on the shipped exclusion list where everyone benefits.

Second most useful: finding a design flaw. This sits in the resolution path of
every lookup on a network and has had no independent security review. See
[SECURITY.md](SECURITY.md) for anything sensitive.

## Working on detection

`internal/detect` has house rules that matter more than the code, and a PR that
ignores them will get the same comments every time:

**Write the benign corpus first.** For every pattern worth detecting there is
legitimate traffic sharing its most obvious property — a CDN against a tunnel,
a mail server against a TXT channel, a stale search suffix against an NXDOMAIN
burst. If you cannot construct that corpus, you do not yet understand the false
positives, and you are about to ship an alert somebody will mute.

**No single signal may raise a finding**, or the detector must gate on the one
signal that defines it. The tunnel detector requires three of seven; the
beaconing detector gates on regularity itself.

**Publish the bands.** A score that cannot be reproduced on paper from the
numbers in the finding is not explainable, and an unexplainable finding is not
actionable.

**Bound the state.** This code is fed directly by untrusted network traffic.
Use `newTracker`; never a plain map that grows with input.

**Attach ATT&CK only with a rationale**, and mark hypotheses as hypotheses. No
mapping is better than a decorative one — see
[docs/detection/mitre.md](docs/detection/mitre.md).

**Nothing blocks.** `Enforces` is false everywhere and a test asserts it.
Changing that is a separate discussion that requires a measured false-positive
rate first, not confidence.

Full detail: [docs/detection/README.md](docs/detection/README.md#extending-it).

## Claims discipline

The rule the whole project runs on:

> **Do not describe planned functionality in the present tense.**

A security tool that overstates is worse than one that does less, because
somebody will rely on the missing part.
[docs/capabilities.md](docs/capabilities.md) is the source of truth, and a PR
adding a capability updates it. A PR adding a *sentence* claiming a capability
that does not exist will be asked to remove the sentence.

## The lab

```bash
make build-lab
bin/dnsdaddy-lab -sink 127.0.0.1:5300      # synthetic upstream
bin/dnsdaddy-lab -scenario all -speed 10   # traffic
```

Or `make lab` for the Docker version. It is entirely offline and uses reserved
domains, so demonstrating a detection never requires touching anyone else's
infrastructure — and it is the fastest way to check that a change to a detector
did what you meant. Two scenarios are supposed to produce nothing; if they
start producing findings, you have introduced a false positive.

## Scope

This project is meant to stay focused on a single organisation running a
single self-hosted resolver. Things that fit: resolver correctness, filtering,
visibility, reporting, deployment ergonomics, documentation.

Things that generally do not fit: multi-tenancy, billing, white-labelling.
Not because they are unwelcome ideas, but because they pull in a different
direction and would make this one worse for the person self-hosting it. There
is no commercial edition this project is being kept separate from — it is
just scope discipline for a single-purpose tool.

## Licence

Contributions are accepted under [Apache-2.0](LICENSE), the licence this project
ships under.
