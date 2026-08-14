# Lab: normal DNS

**Client:** 172.30.0.31 (`127.0.0.2` when run natively) ·
**Expected finding: none.**

```bash
bin/dnsdaddy-lab -server 127.0.0.1:5353 -scenario normal-dns -speed 10
```

## Objective

Establish the baseline. Everything else in the lab is only interesting relative
to what ordinary traffic looks like, and a detection stack that cannot stay
quiet on ordinary traffic is worthless regardless of what it catches.

## What is simulated

A workstation browsing: a small set of real-shaped destinations, address
lookups, bursty timing.

```
www.news.example        A
static.news.example     A
api.shop.example        AAAA
login.bank.example      HTTPS
cdn.docs.example        A
```

About 120 lookups over six simulated minutes, across eight parent domains and
seven hostnames. Timing is deliberately irregular: mostly a burst of lookups a
few hundred milliseconds apart as a page loads, then a pause of several seconds
to half a minute.

That irregularity is the signature of a human. Every behavioural detector here
is, in one way or another, looking for the absence of it.

## What you will see

In the **Query log**, unremarkable rows. In **Detections**, nothing.

`dnsdaddy_detection_observations_total` on `/metrics` will have risen by ~120,
which is how you tell "no findings" apart from "no traffic reached the engine".
That distinction matters more than it sounds: a silent detection stack and a
broken one look identical from the dashboard.

## Why nothing fires

Every detector's gates, in turn:

| Detector | Gate | This traffic |
|---|---|---|
| `dns_tunnel` | ≥30 queries **and** ≥15 unique subdomains under one parent | ~15 queries per parent, ~7 distinct hostnames |
| `nxdomain_anomaly` | ≥40 failures **and** ≥60 queries | all resolve |
| `dga_like` | ≥8 distinct random-looking registered domains | zero — the names are words |
| `txt_anomaly` | ≥25 non-infrastructure TXT lookups | zero TXT |
| `dns_beaconing` | ≥8 arrivals for one name **and** regularity ≥0.75 | irregular by construction |
| `resolution_failure` | ≥5 SERVFAIL for one domain, >50% failing | none |

Worth noticing that most of these are stopped by a *volume* gate rather than by
scoring. That is intentional. Behavioural inference on a handful of events is
guessing, and the honest way to express "not enough evidence" is to refuse to
produce a finding rather than to produce one with a low confidence number
attached.

## Interesting variation

Run this scenario **without** the lab's synthetic upstream — point the resolver
at a public one — and `.example` names fail, because `.example` is not
delegated. You will then see that even 120 straight NXDOMAINs do not raise
`nxdomain_burst`, because the `distinct_failed_domains` signal stays at zero:
eight parent domains is far below the floor of ten.

That is the difference between "a host that cannot resolve anything" (a
configuration problem, and DNS Daddy stays quiet) and "a host working through a
generated list of hundreds of unrelated domains" (worth a look). The count of
failures alone does not separate them; the spread across domains does.

## Related

- [dga-simulation](dga-simulation.md) — the same failures, spread across
  hundreds of domains
- [nxdomain-anomaly](nxdomain-anomaly.md) — failures at volume
