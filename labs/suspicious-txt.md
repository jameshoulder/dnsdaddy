# Lab: suspicious TXT activity

**Client:** 172.30.0.35 (`127.0.0.6` when run natively) ·
**Expected finding:** `txt_activity_anomaly`, medium severity ·
**ATT&CK:** [T1071.004] *(as a hypothesis)*

```bash
bin/dnsdaddy-lab -server 127.0.0.1:5353 -scenario suspicious-txt -speed 10
```

## Objective

Show TXT records being used as a data channel, and show the exclusion step that
makes such a detector usable on a network that has a mail server.

## What is simulated

A mix, deliberately. Three in four queries are the channel:

```
mfzwizltoqycu4ylbmnqxgzjan52g.c2.example    TXT
n5zgs3tfnvsw45djnzsxg43fmnzgs.c2.example    TXT
```

One in four is routine mail infrastructure:

```
_dmarc.supplier.example                      TXT
```

About 220 lookups over six simulated minutes.

## Why TXT

TXT is the only widely permitted record type that carries arbitrary text, which
makes it the highest-capacity channel available to anything moving data through
DNS: command-and-control tasking, staged payloads, and exfiltration all use it.

It is also how SPF, DKIM, DMARC, MTA-STS, ACME and roughly every SaaS
domain-verification scheme in existence publish their configuration.

That second list is the entire difficulty. On a network with a mail server, TXT
lookups are among the most common queries there are. A detector that counts
them naively reports the mail server every five minutes, forever.

## The exclusion step

Before anything is measured, queries are classified by label structure. A name
containing `_dmarc`, `_domainkey`, `_spf`, `_acme-challenge`, `_mta-sts`,
`_tlsa` or a DKIM selector is infrastructure and is excluded.

The count of what was excluded is reported in the finding as
`txt_infrastructure_excluded`, so the reader can see what was filtered rather
than wondering. In this scenario that number will be around 55, and the score
is computed on the remaining ~165.

`TestTXTDetectorQuietOnMailInfrastructure` feeds 600 pure SPF/DKIM/DMARC
queries through the detector and asserts silence.

## Expected signals

| Signal | Measured | Band | Contributed |
|---|---|---|---|
| `txt_query_count` | ~165 | 30 – 300 | ~0.17 |
| `txt_query_ratio` | ~0.74 | 0.10 – 0.60 | 0.25 |
| `distinct_txt_names` | ~165 | 15 – 150 | 0.25 |
| `mean_txt_subdomain_entropy` | ~4.4 | 3.2 – 4.2 | 0.15 |

Severity capped at **medium**. Unusual TXT usage is a strong lead and a weak
verdict: the detector establishes that a client's TXT behaviour is anomalous
after excluding the standard lookups, not that the records carry attacker
content.

You will also see `dns_tunnel_suspected` fire for this client, at medium. That
is correct, not duplication — 32-character base32 labels under one parent over
TXT genuinely is a tunnel by every measure the tunnel detector takes. Two
independent detectors agreeing is stronger evidence than either alone.

## The ratio signal matters more than the count

`txt_query_ratio` is the share of the client's queries that were TXT. An
ordinary end-user device is well under 5%. A mail server is legitimately much
higher — which is exactly why volume alone does not raise this finding, and why
the ratio and the distinct-name count carry as much weight as the count does.

Reading a policy record means asking for the same few names repeatedly. Moving
data means asking for new ones. `distinct_txt_names` is what separates those.

## False-positive considerations

- **A mail security gateway using non-standard selector names.** The standard
  prefixes are excluded; a vendor that invents its own is not. If this is your
  case, add the vendor's domain to `detection.excluded_domains` rather than
  raising the thresholds — the threshold change costs you coverage everywhere,
  the exclusion costs it in one place.
- **Licence checks and anti-abuse services** that distribute state over TXT.
- **A bulk domain-verification exercise** during a migration will spike TXT
  volume legitimately for a day.

## Investigation steps

1. **Establish whether the client is a mail server.** If it is, the question is
   which selectors to exclude, not whether to tune thresholds.
2. **Look at the names.** Policy lookups repeat a handful of names; data
   transfer does not.
3. **Check whether `dns_tunnel_suspected` fired** for the same client and
   parent domain.
4. **Query the names yourself** from an analyst workstation and read the
   returned records. This is a TXT record — the contents are right there, and
   base64 in a TXT record answers the question immediately.
5. **Identify the parent domain's owner.**

## Mitigation

If confirmed, block the parent domain by policy. As with every behavioural
finding, DNS Daddy did not do this automatically and will not.

[T1071.004]: https://attack.mitre.org/techniques/T1071/004/
