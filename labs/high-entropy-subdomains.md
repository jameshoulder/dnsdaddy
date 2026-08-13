# Lab: high-entropy subdomains

**Client:** 172.30.0.33 (`127.0.0.4` when run natively) ·
**Expected finding: none.** That is the whole point of this scenario.

```bash
bin/dnsdaddy-lab -server 127.0.0.1:5353 -scenario high-entropy-subdomains -speed 10
```

## Objective

Refute the single most common bad assumption in DNS detection: **that high
entropy means malicious**.

This scenario generates labels that are genuinely random — drawn uniformly from
a 32-character alphabet by a PRNG, with entropy indistinguishable from a
tunnel's payload — and DNS Daddy must stay silent.

## What is simulated

A client resolving names like:

```
kzq2w7vx3mb5nr.widgets.example
mfzwizltoqyc4y.widgets.example
n5zgs3tfnvsw45.widgets.example
```

Five hundred lookups over six simulated minutes, from a pool of forty names
that repeat. Every label is random. Nothing else about the traffic looks like a
channel:

| Property | This scenario | A tunnel |
|---|---|---|
| Label entropy | **high** | high |
| Distinct subdomains | 40 | hundreds, never repeating |
| Name length | ~31 chars | 100+ chars |
| Longest label | 14 | 40–63 |
| Record type | A | TXT / NULL / CNAME |
| Resolution | succeeds | often fails |

This is not a contrived shape. Cache-busting tokens, session identifiers,
per-device telemetry hostnames and short content hashes all look exactly like
this on a real network.

## Why nothing fires

The tunnel detector takes seven measurements and requires **at least three** to
be meaningfully present before raising anything. Here, one is.

| Signal | Measured | Band | Normalised |
|---|---|---|---|
| `mean_subdomain_entropy` | ~3.7 | 3.2 – 4.2 | 0.5 ✓ contributes |
| `unique_subdomains` | 40 | 20 – 200 | 0.11 |
| `mean_qname_length` | ~31 | 45 – 100 | 0.00 |
| `max_label_length` | 14 | 30 – 63 | 0.00 |
| `encoded_label_ratio` | 0.00 | 0.25 – 0.85 | 0.00 |
| `payload_qtype_ratio` | 0.00 | 0.10 – 0.60 | 0.00 |
| `nxdomain_ratio` | 0.00 | 0.20 – 0.80 | 0.00 |

One contributing signal, three required, no finding. Even the raw score — about
0.09 — is far below the 0.40 floor.

Two details are worth pulling out.

**The labels are 14 characters, and `encoded_label_ratio` is zero.** The
encoded-label test requires at least 16 characters, because below that a
character-set conformity test is measuring the alphabet rather than the
encoding. Fourteen random base32 characters *are* base32 — they are just too
short for that observation to mean anything.

**Entropy is measured only on labels of 12 characters or more.** Shannon
entropy per character is bounded above by log2(length): an eight-character
string cannot exceed 3 bits/char however random it is. Comparing a short label
against a 4-bit threshold measures length, not randomness. The detector
publishes how many labels went into the average (`entropy_label_samples`) so
this is checkable rather than assumed.

## The general lesson

Entropy is a *weak* signal used alone and a *good* one used in combination.

A detector built on "entropy above 4.0 = alert" would fire on this scenario, on
every CDN, on every hash-based reputation lookup, and on every session token in
a hostname. It would be switched off inside a week, and the operator would be
right to switch it off.

The interesting property of a real tunnel is not that its labels are random. It
is that they are random **and** never repeat **and** are near the protocol
length limit **and** use a payload-capable record type **and** all point at one
parent domain — because that combination is what the transport requires, not
what the tool author chose.

That is why the detector scores several independent properties and gates on how
many are present, rather than thresholding the most obvious one.

## Investigation steps

If this scenario *does* produce a finding on your build, that is a regression
worth reporting — the behaviour is pinned by
`TestTunnelDetectorRespectsGates/high_entropy_alone_is_not_enough` in
`internal/detect/tunnel_test.go`, which asserts exactly this using the same
generator.

On a real network, if you see high-entropy subdomains and want to know whether
they matter, the questions in order are:

1. **Do the names repeat?** A pool that recurs is identifiers. Names that never
   repeat are a channel or a per-request hostname.
2. **How long are they?** A tunnel wants throughput and pushes towards 253
   bytes. An identifier is as short as it can be.
3. **What record type?** An address lookup is a client trying to connect
   somewhere. TXT and NULL are a client trying to *receive* something.
4. **Who owns the parent domain?** This resolves most cases immediately.

## Related

- [dns-tunnelling](dns-tunnelling.md) — the same entropy, with everything else
- [docs/detection/dns-tunnelling.md](../docs/detection/dns-tunnelling.md) — the
  full signal model and its thresholds
