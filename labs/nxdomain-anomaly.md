# Lab: NXDOMAIN anomaly

**Client:** 172.30.0.34 (`127.0.0.5` when run natively) ·
**Expected finding:** `nxdomain_burst`, medium severity ·
**ATT&CK:** [T1568.002] *(as a hypothesis — see below)*

```bash
bin/dnsdaddy-lab -server 127.0.0.1:5353 -scenario nxdomain-anomaly -speed 10
```

## Objective

Show the difference between a failed lookup, which is the most common
non-success response on any network, and a *rate* of failed lookups that no
browser produces.

## What is simulated

A client resolving several hundred names that do not exist, across several
hundred unrelated registered domains, in a few minutes:

```
xzmskab.ehlojvzq.example       NXDOMAIN
kdufhqp.mzvbxtrn.example       NXDOMAIN
qwnvkla.pdtsjxmc.example       NXDOMAIN
```

About 720 lookups over six simulated minutes.

## Why this framing, rather than alerting on NXDOMAIN

An individual NXDOMAIN means nothing. Typos, dead links, search-suffix
expansion and connectivity checks produce them constantly, and a detector that
treats one as suspicious produces an alert per user per minute.

What is worth reporting is the shape: one host, hundreds of failures, spread
across domains with no relationship to each other, in a window where a person
could not have typed them.

## Expected signals

| Signal | Measured | Band | Contributed |
|---|---|---|---|
| `failed_lookups` | ~704 | 50 – 500 | 0.40 |
| `failure_ratio` | ~0.98 | 0.30 – 0.90 | 0.30 |
| `distinct_failed_domains` | ~704 | 10 – 100 | 0.30 |

Score ~1.0 — but severity is capped at **medium**, because failing lookups
alone do not establish intent. This detector tells you where to look; it does
not tell you what you found.

## Two exclusions doing most of the work

**Blocked queries are not counted.** DNS Daddy answers a blocked name with
NXDOMAIN by default. If those counted here, the better your filtering worked,
the more your network would look like it was under attack — and the operators
with the best blocklists would get the most false alarms. Every rcode-derived
signal in the detection engine ignores blocked queries for this reason, and
`TestNXDomainDetectorIgnoresPolicyBlocks` pins it.

**Names with no registered domain are not scored.** A stale DHCP search suffix
means every short name on the network gets tried against a domain that no
longer exists — `printer.corp.local`, `wpad.corp.internal`, `nas.lan` — and it
is by a distance the loudest false positive this detector has. Those names are
counted separately and reported in the evidence as
`failures_without_registered_domain`, so you can see them, but they never
contribute to the score.

The same applies to the three random single-label names Chrome resolves at
startup to detect NXDOMAIN hijacking, which would otherwise appear on every
network with a browser on it.

## ATT&CK mapping, and why it is marked as a hypothesis

[T1568.002] (Dynamic Resolution: Domain Generation Algorithms) is attached with
`hypothesis: true`.

A burst of failed lookups is the expected resolver-side artefact of a DGA
walking its candidate list. It is *also* what a misconfigured search suffix, a
decommissioned internal service, a captive-portal check and a vulnerability
scanner produce. This finding measures the burst; it does not establish that a
generation algorithm caused it.

The `dga_like_domains` detector is what tests that hypothesis, by looking at
whether the names themselves are algorithmic. When both fire for the same
client in the same window, that is meaningfully stronger evidence than either
alone — and in this scenario both do, because the generated labels are random
enough to trip the randomness heuristic too.

## False-positive considerations

- **A stale search suffix.** Handled structurally, as above, when the suffix
  has no public suffix. A stale suffix under a real registered domain — an
  acquired company's domain that has lapsed, say — is *not* excluded and will
  fire. That is arguably correct: it is a real misconfiguration worth fixing.
- **Connectivity and captive-portal checks** deliberately resolve names that
  should fail.
- **A decommissioned internal service** that clients still reference. High
  count, but `distinct_failed_domains` stays at one, which is why that signal
  carries the same weight as the raw count.
- **Security scanners and asset discovery** enumerate names by design. If you
  run one, allow-list it in `detection.excluded_domains` or expect a finding
  every time it runs.

## Investigation steps

1. **Read the failing names.** This resolves most of these findings in seconds.
   Generated names look nothing like typos, and typos look nothing like a
   search suffix.
2. **Check whether `dga_like_domains` also fired** for this client in the same
   window.
3. **Check whether other hosts on the same subnet show the same failures.**
   Shared failures point at configuration; one host alone points at that host.
4. **Check the timing.** A DGA is usually driven by a date-seeded algorithm and
   restarts on a schedule.
5. If the names look generated, treat the endpoint as suspect and **preserve
   the query log before it is pruned** — the default retention is seven days.

## Mitigation

There is nothing to block: the domains do not exist. The value of this finding
is that it identifies a *host* worth examining, not a domain worth filtering.

If a small number of the attempted domains *did* resolve, those are the
rendezvous points and are worth blocking and investigating — that is the one
that was registered.

[T1568.002]: https://attack.mitre.org/techniques/T1568/002/
