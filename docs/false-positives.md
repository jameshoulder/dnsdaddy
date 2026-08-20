# False positives

The hardest problem in DNS detection is not noticing bad traffic. It is not
crying wolf about the ordinary traffic that looks identical.

A detector that fires on a synthetic DGA and also on `d1vg5xiq7qffdj.cloudfront.net`
has not detected anything. It has moved the analyst's work from "investigate"
to "dismiss", and after enough dismissals nobody reads the alerts at all. Every
heuristic in DNS Daddy is therefore judged against benign traffic first.

This document records what triggers each heuristic, what legitimately looks the
same, how confident it is entitled to be, and how to suppress it.

## The rule

**No detector in DNS Daddy blocks anything.** Blocking is done by policy and by
curated threat intelligence. Heuristics observe, score, explain and alert.

That is not a temporary state pending better accuracy. A false positive that
raises an alert costs somebody five minutes. A false positive that blocks
silently breaks a working network and is discovered by a user who cannot reach
their supplier. The asymmetry is the whole argument.

## Name analysis

`AssessName` looks at a single name and nothing else. It is the weakest
evidence in the product and is capped at **25 of 100** so that appearance alone
can never approach a blocking threshold whatever it trips.

### What it measures

| Signal | Weight | Triggers on |
|---|---|---|
| `dga_like_characteristics` | 0.40 | Vowel distribution, consonant runs, digit fraction and entropy combined |
| `label_entropy` | 0.20 | Even character spread, measured only on labels ≥ 12 characters |
| `digit_ratio` | 0.15 | A high proportion of digits |
| `name_length` | 0.10 | Names past ~60 characters |
| `encoded_label` | 0.10 | base32/base64/hex character sets with an encoded-looking mix |
| `hyphen_density` | 0.05 | Heavy hyphenation |

The weights are deliberately spread so no single property carries a name.
Entropy in particular is held at 0.20 — at most **5 points of 100** on its own,
which is by design: entropy is the signal most often over-trusted and on its
own it measures very little. `TestEntropyAloneCannotProduceAHighScore` pins
that.

### What legitimately looks the same

This is the important half of the table.

| Benign traffic | Why it scores |
|---|---|
| CDN edge hostnames (`d1vg5xiq7qffdj.cloudfront.net`) | Machine-generated random identifiers — the same thing a DGA produces |
| Cloud resource names (`prod-elastic-cache-01.eu-west-2…`) | Long, hyphenated, digit-bearing |
| API shard and build identifiers (`api-5f8c2a1b.stripe.com`) | Hex identifiers read as encoded |
| Telemetry endpoints (`v10.events.data.microsoft.com`) | Version digits |
| Long descriptive hostnames | Length and hyphens |
| Punycode (`xn--…`) | Machine-generated *by definition* — excluded from randomness scoring entirely, and reported as unavailable rather than scored |

### Measured separation

Against a corpus of real benign traffic — Microsoft, GitHub, Cloudflare,
Google, Debian, Ubuntu, npm, PyPI, Mozilla telemetry, Akamai, CloudFront, S3,
Stripe and Facebook CDN hostnames — versus synthetic DGA-like and
base32-encoded names:

| | Score |
|---|---|
| Worst benign name | **5.0** |
| Benign ceiling asserted by tests | 8.0 |
| Weakest synthetic DGA-like name | **10.1** |
| Cap | 25.0 |

Roughly a twofold margin between the worst ordinary name and the weakest
generated one. `TestBenignTrafficStaysBelowTheFalsePositiveCeiling` and
`TestDGALikeNamesScoreAboveOrdinaryOnes` fail the build if that closes.

**This is a separation margin on a fixed corpus, not an accuracy rate.** No
precision or recall figure is quoted anywhere in DNS Daddy, because measuring
one honestly needs a labelled sample of a real network's traffic, and this
project does not have one. A margin on 27 benign and 6 synthetic names is
evidence that the weighting is not absurd. It is not evidence that it is right.

### What it cannot do

- It has not resolved the name. Registration date, owner, hosting and
  reputation are all unknown to it.
- **Brand impersonation scores poorly.** `paypal-account-verify-secure-login-update.xyz`
  scores 4.6 — below the benign ceiling — because it is not random, it is
  English words. Lexical randomness is the wrong tool for that, and pretending
  otherwise would be worse than not claiming it.
- A name chosen to look ordinary scores zero. **A low score is not evidence of
  safety**, and the summary says so on every quiet result.

### Suppression

Score 0 results are already silent. The assessment never blocks, so there is
nothing to suppress operationally; if a name is being surfaced you disagree
with, the per-signal `contribution` values show exactly which property caused
it.

## Behavioural detectors

The windowed detectors in `internal/detect` each declare their own known false
positives in `DetectorInfo.FalsePositives`, which is served from
`GET /api/v1/detectors` and rendered in the dashboard rather than kept in a
document that can drift.

Known benign lookalikes covered by tests in `internal/detect`:

| Detector | Legitimately looks the same |
|---|---|
| Tunnelling | CDN hostnames with very high subdomain cardinality; mail servers doing DNSBL lookups; IPv6 reverse DNS |
| Beaconing | NTP, monitoring agents, telemetry, update checks, SaaS health checks — anything on a timer |
| NXDOMAIN burst | A laptop with a stale DNS search domain; captive portal probing; typo storms |
| DGA clustering | The same, plus antivirus and reputation lookups that append hashes to a parent |
| TXT anomaly | SPF, DKIM, DMARC and domain-verification lookups — excluded explicitly |

`internal/detect/exclusions.go` ships a suppression list, and the beaconing
detector separately accounts for TTL-driven re-queries so a client re-resolving
because its cache expired is not read as a client polling on a timer.

Exclusion lists are kept small on purpose. Shipping an enormous vendor
allowlist would hide the detector's real false-positive rate behind a list
nobody audits, and would silently stop detecting a compromise of any excluded
vendor.

## Reporting one

False positives are the most useful bug report this project can receive, and
there is an issue template for them: `.github/ISSUE_TEMPLATE/false-positive.yml`.

The `GET /api/v1/intelligence?domain=` endpoint gives you everything needed for
a report — which feeds listed a name, which one decided the block, whether the
listing is actually on a parent, and the per-signal arithmetic behind any name
analysis.
