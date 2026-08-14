# Lab: DNS beaconing

**Client:** 172.30.0.37 (`127.0.0.8` when run natively) ·
**Expected finding:** `dns_beaconing_suspected`, medium severity ·
**ATT&CK:** [T1071.004] *(as a hypothesis)*

```bash
bin/dnsdaddy-lab -server 127.0.0.1:5353 -scenario beaconing -speed 10
```

This scenario runs for 31 simulated minutes — about three minutes at `-speed
10`. It is the slowest in the lab, because periodicity cannot be established
quickly by definition.

## Objective

Show detection of queries arriving on a machine's schedule rather than a
person's, and be honest about how far that gets you.

## What is simulated

One name, queried every 45 seconds with ±6% jitter, sustained for half an hour:

```
checkin.beacon.example   A    t+0s
checkin.beacon.example   A    t+46.2s
checkin.beacon.example   A    t+90.8s
checkin.beacon.example   A    t+136.1s
...
```

Forty-one lookups. The jitter is deliberate: a perfectly constant interval is
easier to detect and most implants add some, so the scenario models the harder
case.

## Why regularity is the signal

Human-driven DNS is bursty and irregular. You open a page, a dozen lookups
happen, then nothing for four minutes. Software checking in on a timer produces
the opposite.

The measurement is the **coefficient of variation** of inter-arrival times —
the standard deviation divided by the mean. That normalisation is what makes a
30-second beacon and a 10-minute beacon comparable. Poisson-like human traffic
sits near 1.0; a fixed timer sits near 0.

`regularity = 1 - CV`. This scenario scores about 0.96.

## Expected signals

| Signal | Measured | Band | Contributed |
|---|---|---|---|
| `timing_regularity` | ~0.96 | 0.75 – 0.97 | ~0.43 |
| `observation_count` | ~32 | 8 – 40 | ~0.15 |
| `observed_duration` | ~1400s | 300 – 1800 | ~0.11 |
| `ttl_independence` | 5.7 | 0.15 – 0.6 | 0.20 |

**Regularity is a gate, not just a weighted signal.** If it falls below 0.75 no
finding is produced at all, regardless of what the other three say. Without
that gate, a client that merely queried the same name often enough for long
enough could accumulate a low-severity finding from volume and duration alone
while being visibly irregular — which is exactly the "suspicious DNS traffic"
alert this project exists not to produce.

## The TTL discriminator

The most important false positive here has a complete, boring explanation, and
it can be removed mechanically.

A client re-resolving a name because its own cache entry expired queries at
**exactly the record's TTL**. That produces perfect periodicity and means
nothing at all.

So the detector records the smallest TTL seen in the answers, and if the
observed period matches it within 15%, the finding is **suppressed entirely** —
not downgraded, suppressed. The periodicity is explained; reporting it would be
noise.

In this scenario the lab's zone serves `beacon.example` with a 300-second TTL
against a 45-second check-in. The relative difference is 5.7, far outside the
tolerance, so the cadence is the client's own clock and the finding stands.
`TestBeaconDetectorSuppressesTTLDrivenRefresh` pins the other direction: a
60-second period against a 60-second TTL produces nothing.

This only works when an answer with a TTL was actually observed. Where none
was, `ttl_independence` scores at maximum and the finding says so in its
evidence (`answer_min_ttl_s: null`).

## Why severity is capped at medium

Because timing alone cannot distinguish an implant from an updater.

Windows Update, telemetry agents, monitoring probes, NTP, certificate status
checks, push and presence services are all periodic **by design**. They will
produce this finding, and they are not wrong to. This detector says "this host
is talking to that name on a fixed cadence"; deciding whether that is a
software vendor or an adversary is analyst work that needs context the resolver
does not have.

Framing it as a hunting lead rather than an alert is the honest presentation.
The ATT&CK mapping is marked as a hypothesis for the same reason: it states
what the behaviour would be if malicious, not what the evidence establishes.

## Practical consequence: memory

This is the most expensive detector to run, because its state is keyed on
(client, exact name) rather than (client, parent domain). On a busy network
that is a lot of keys.

The tracker is capped at 16,384 and evicts under pressure, so it cannot
exhaust memory — but eviction means **missed detections**, not just reduced
accuracy. That is a real coverage gap on a large network, it is reported
through the metrics rather than hidden, and it is the main reason this detector
is the weakest of the six.

## Investigation steps

1. **Establish what the name is and who operates it**, before looking at the
   host. Most of these findings end here.
2. **Check whether every device of this type shows the same cadence.** Fleet-
   wide regularity is a product. One host alone is worth explaining.
3. **On the endpoint, identify the process** making the lookups.
4. **Correlate the start of the cadence** with software installs or user
   activity. A beacon that started the day after a phishing email is a
   different conversation from one that has run for two years.
5. **Look at the interval itself.** Round numbers (60s, 300s) suggest
   configuration; odd ones (47s, 173s) suggest something trying not to be
   round.

## Mitigation

Nothing automatic, and nothing recommended without identification. Blocking a
beacon's domain on cadence alone has a meaningful chance of blocking your own
monitoring.

[T1071.004]: https://attack.mitre.org/techniques/T1071/004/
