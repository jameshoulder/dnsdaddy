# Lab: DNS tunnelling

**Client:** 172.30.0.32 (`127.0.0.3` when run natively) ·
**Expected finding:** `dns_tunnel_suspected`, high severity ·
**ATT&CK:** [T1071.004], [T1048.003], [T1132.001]

```bash
bin/dnsdaddy-lab -server 127.0.0.1:5353 -scenario dns-tunnelling -speed 10
```

## Objective

Show what DNS being used as a transport looks like from a resolver's seat, and
show that the finding explains itself well enough to act on.

## The mechanism being simulated

To move bytes over DNS you need somewhere to put them that a recursive resolver
will faithfully forward to a server you control. A query has exactly one
generous field: the name. So a tunnel encodes its payload into labels beneath a
domain whose authoritative nameserver the attacker runs, and the resolver
delivers it for them.

Two consequences follow, and they are what makes tunnelling detectable at all:

**Every name must be unique.** Repeat a name and the resolver answers from
cache, the query never reaches the attacker's server, and the tunnel stalls.
Uniqueness is not a stylistic choice by the tool author; it is a requirement of
the transport.

**The labels cannot look like words.** They are encoded binary — base32 or
base64 in practice, because a DNS label is case-insensitive and restricted in
character set.

The scenario sends one message roughly every second for six simulated minutes:
two base32 labels, 55 and 42 characters, beneath `tunnel.example`, over TXT.
TXT is used because it carries the most data back.

Real tools (iodine, dnscat2, dns2tcp) go considerably faster than this. The
scenario is deliberately modest.

## What you will see in the telemetry

In the **Query log**, several hundred rows for one client, all under one
parent, no two names alike:

```
mfzwizltoqycu4ylbmnqxgzjan52geylumfzwi.zltoqycu4ylbmnqxgzjan52g.tunnel.example  TXT
n5zgs3tfnvsw45djnzsxg43fmnzgs5dbnzsxg.4tfnvsw45djnzsxg43fmnzg.tunnel.example  TXT
...
```

In **Detections**, one finding with seven measurements. Expect roughly:

| Signal | Measured | Band | Contributed |
|---|---|---|---|
| `unique_subdomains` | ~384 | 20 – 200 | 0.28 |
| `mean_subdomain_entropy` | ~4.45 | 3.2 – 4.2 | 0.18 |
| `mean_qname_length` | ~113 | 45 – 100 | 0.14 |
| `max_label_length` | 55 | 30 – 63 | 0.08 |
| `encoded_label_ratio` | 1.00 | 0.25 – 0.85 | 0.12 |
| `payload_qtype_ratio` | 1.00 | 0.10 – 0.60 | 0.10 |
| `nxdomain_ratio` | 0.00 | 0.20 – 0.80 | 0.00 |

Score around 0.90, severity **high**, confidence around 0.98.

## Why DNS Daddy detected it

Not because of any one measurement. The detector requires at least three
signals to be meaningfully present before it will raise anything, and here six
are. Each one alone has an innocent explanation — a CDN generates unique
subdomains, a hash lookup has high entropy, a service-discovery name is long,
TXT is used by every mail server on earth. All six together, sustained, from
one client, under one parent, do not.

Note that `nxdomain_ratio` contributed **nothing**, because the lab's
attacker-controlled domain resolves — as a real one must. The finding is raised
on the other six signals, which is the point of not requiring any particular
one.

## ATT&CK mapping

- **[T1071.004] Application Layer Protocol: DNS** — the measured behaviour *is*
  the mechanism the technique describes: name resolution used as a data
  carrier rather than to look up an address.
- **[T1048.003] Exfiltration Over Unencrypted Non-C2 Protocol** — attached as a
  *hypothesis*. If the tunnel is carrying data outbound then the query labels
  are the payload and this applies. DNS Daddy sees volume, structure and
  entropy; it does not decode the payload, so it cannot establish direction.
  Something to test during triage, not a determination.
- **[T1132.001] Data Encoding: Standard Encoding** — rests specifically on the
  `encoded_label_ratio` signal. Where that signal did not contribute, this
  mapping is weaker.

## False-positive considerations

This is where most of the engineering went, because the traffic shape is not
unique to attackers.

**DNSBL and file-reputation lookups.** A mail server checking an IP against
Spamhaus, or an endpoint agent checking a file hash against a vendor's DNS
service, encodes the thing being checked into the label and looks it up —
thousands of times an hour, one unique high-entropy name each. By shape this is
*indistinguishable* from a tunnel. It is not caught by cleverer scoring; it is
excluded by a shipped list of provider domains.

You can see this for yourself. `internal/detect/exclusions.go` lists them, and
a test asserts that the same corpus fires with the list disabled and stays
quiet with it enabled — so if that trade-off ever silently stops being the
reason, the test fails.

**The residual risk is real and worth stating.** An attacker who tunnels
through a domain that looks like a security vendor's, or who compromises one,
gets past this. Exclusion lists trade coverage for usability; that is what they
are for, and pretending otherwise would be worse than the trade.

**CDNs** issue per-request hostnames. The common ones are excluded; a SaaS
vendor yours uses may not be.

**IPv6 reverse DNS** is 32 single-hex-character labels per lookup — maximal
cardinality and near-maximal entropy, entirely routine. `.arpa` is excluded
outright, and it is the single most important entry on the list.

## Investigation steps

1. **Identify the parent domain's owner.** Whois, and whether the business has
   any reason to talk to them. A tunnel's domain is usually recently
   registered and belongs to nobody recognisable.
2. **Check the nameservers.** A tunnel requires the attacker to run
   authoritative DNS for the domain. Recently changed or self-hosted NS
   records on an otherwise unremarkable domain is a strong corroborator.
3. **Check the shape over time** in the query log. A tunnel that is actively
   moving data is continuous; one that is idling still checks in.
4. **Go to the endpoint.** A tunnel needs a process holding it open. The
   resolver sees the symptom; the host has the cause.
5. **Check whether other hosts do the same thing.** One host is an incident.
   Every host of one type is a product you have not identified yet.

## Mitigation

If confirmed, add the parent domain to the policy block-list. That takes effect
on the next query — the answer cache is purged on a policy change specifically
so a decision made at 16:00 applies at 16:00.

Note that **DNS Daddy did not do this for you**, and that is deliberate.
Behavioural findings do not enforce. A false positive turned into a block is a
working service silently broken by a heuristic, and the person who has to
explain that outage will not be comforted by the confidence score. Blocking is
a decision for a human with context, or for the curated threat intelligence in
the feeds.

Longer term, the durable control is not DNS filtering at all: it is preventing
clients from reaching any resolver but yours, so a tunnel cannot simply be
pointed at 8.8.8.8. See
[docs/dns-security/encrypted-dns.md](../docs/dns-security/encrypted-dns.md).

[T1071.004]: https://attack.mitre.org/techniques/T1071/004/
[T1048.003]: https://attack.mitre.org/techniques/T1048/003/
[T1132.001]: https://attack.mitre.org/techniques/T1132/001/
