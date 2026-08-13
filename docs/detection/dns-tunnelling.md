# DNS tunnelling

What it is, why it works, why it is hard to detect well, and exactly what DNS
Daddy does about it.

See also: the [lab scenario](../../labs/dns-tunnelling.md) to watch it fire,
and the [threat hunt](../threat-hunting/README.md#hunt-1--dns-tunnelling) to
look for it in your own telemetry.

---

## The concept

DNS is a request/response protocol that almost every network permits outbound,
because without it nothing works. It is also *delegated*: if you own
`example.com`, queries for anything beneath it are eventually forwarded to a
nameserver **you control**, by resolvers that have no opinion about the
content.

That is a message channel. The client encodes data into a name and asks for it;
the resolver dutifully carries the question to the attacker's server; the
server encodes a reply into the answer record.

```
   client                 recursive resolver           attacker's NS
     │                          │                            │
     │ TXT <data>.tunnel.evil   │                            │
     │─────────────────────────▶│  TXT <data>.tunnel.evil    │
     │                          │───────────────────────────▶│
     │                          │                            │  decode
     │                          │◀───────────────────────────│  respond
     │◀─────────────────────────│  TXT "<reply>"             │
```

Neither the client nor the server needs any other connectivity. On a network
where the only thing that works is DNS — a hotel captive portal, a segmented
OT network, a locked-down corporate VLAN — this is often the only channel
available, which is why it is used both by attackers and by people getting
free airport wifi.

**Capacity.** A name is at most 253 bytes; a label at most 63. After encoding
overhead and the carrier domain, a realistic upstream payload is 100–180 bytes
per query, with a TXT answer returning up to a few hundred. Tunnels are slow —
tens of kilobytes per second at best — which is fine for tasking, for a shell,
and for exfiltrating credentials or a customer list.

**Tools.** `iodine`, `dnscat2`, `dns2tcp`, `sliver`'s DNS transport, and
`Cobalt Strike`'s DNS beacon are the common ones. They differ in encoding and
record type, not in the underlying shape.

## Why it is detectable at all

Two properties are *required by the transport*, not chosen by the tool author.
That distinction matters: an attacker can change what they choose, but not what
the mechanism demands.

**Every query name must be unique.** Repeat a name and the recursive resolver
answers from its cache. The query never reaches the attacker's nameserver and
the tunnel stalls. So cardinality under one parent domain rises without bound.

**The labels cannot be words.** They carry encoded binary. Whatever alphabet is
used — base32 is most common, since DNS labels are case-insensitive — the
character distribution does not look like language.

Everything else is negotiable. Record type can vary. Query rate can be throttled
to a crawl. Names can be padded to mimic a CDN. Which is why a detector resting
on any one property is one blog post away from being useless.

## Why it is hard to detect *well*

Because legitimate services do the same thing on purpose.

**Reputation lookups.** A mail server checking an IP against a DNSBL asks for
`4.3.2.1.zen.spamhaus.org`. An endpoint agent checking a file hash asks for
`<sha256>.reputation.vendor.example`. Thousands an hour, every name unique,
high entropy, mostly NXDOMAIN. **By shape this is indistinguishable from a
tunnel.** It is not separable by cleverer scoring, because it genuinely is the
same mechanism — encoding a query into a DNS label and looking it up.

**CDNs and cloud edges** issue per-request hostnames to steer traffic.

**IPv6 reverse DNS** is 32 single-hex-character labels per lookup. Maximal
cardinality, near-maximal entropy, entirely routine.

**Service discovery and telemetry** encode identifiers into hostnames.

This is why the naive detector — "entropy above 4.0" or "more than N
subdomains" — fires constantly on production networks and gets switched off
within a week. The operator is right to switch it off.

---

## What DNS Daddy does

Keyed on **(client, registered domain)** over a **5-minute tumbling window**.

Grouping on the registered domain (eTLD+1, from the public suffix list) is what
makes "many subdomains under one parent" mean the same thing for `example.com`
and `example.co.uk`. Grouping on the last two labels instead would treat every
`.co.uk` site as a subdomain of `co.uk`, and a tunnel under a country-code
domain would be invisible.

### The gates

Nothing is scored until:

- **≥ 30 queries** for that (client, domain) pair in the window
- **≥ 15 distinct subdomains**

A handful of odd names is not evidence of a channel, and inference on a small
sample is guessing. Refusing to produce a finding is the honest way to say
"not enough evidence".

### The seven signals

| Signal | Band | Weight | What it measures |
|---|---|---|---|
| `unique_subdomains` | 20 – 200 | 0.28 | Distinct names below the parent. The transport requires uniqueness. |
| `mean_subdomain_entropy` | 3.2 – 4.2 | 0.18 | Shannon entropy, bits/char, over labels ≥12 chars. |
| `mean_qname_length` | 45 – 100 | 0.14 | Tunnels push towards the 253-byte limit for throughput. |
| `max_label_length` | 30 – 63 | 0.10 | Against the 63-byte protocol maximum. |
| `encoded_label_ratio` | 0.25 – 0.85 | 0.12 | Labels matching an encoding alphabet rather than language. |
| `payload_qtype_ratio` | 0.10 – 0.60 | 0.10 | TXT, NULL, CNAME, MX — types that can carry data back. |
| `nxdomain_ratio` | 0.20 – 0.80 | 0.08 | Some tunnel modes never expect an answer. Policy blocks excluded. |

Weights sum to 1.0, asserted by a test.

### The multi-signal gate

**At least three signals must reach a normalised value of 0.25 before any
finding is raised**, regardless of score.

This is the single most important design decision in the detector, and it is
what separates it from the naive versions. Each signal alone has a common
benign cause — the list above. Three at once, sustained, from one client, under
one parent, is difficult to produce by accident.

The lab's [high-entropy-subdomains](../../labs/high-entropy-subdomains.md)
scenario demonstrates it: genuinely random labels, drawn uniformly from a
32-character alphabet, and no finding — because entropy is the only signal
present.

### A note on entropy

Shannon entropy per character is bounded above by log2(length). An
eight-character string cannot exceed 3 bits/char however random it is, so
comparing a short label against a 4-bit threshold measures **length, not
randomness**.

Entropy is therefore averaged only over labels of 12 characters or more, and
the finding publishes `entropy_label_samples` so the reader can see how many
labels went into the average. A finding built on three long labels and a
hundred short ones is a different thing from one built on all hundred.

### Encoded-label detection

A label is "encoded-looking" if it is 16–63 characters and either:

- **pure hex** with at least one digit — no natural-language name is 16+
  characters drawn only from `[0-9a-f]`;
- **pure base32** (`[a-z2-7]`) with at least one digit from that range;
- or passes a **mix test**: vowel ratio below 12% for an all-letter label, or
  below 20% with a digit fraction of 20%+.

Written English runs about 38% vowels; a uniform draw from a 32-character
alphabet gives roughly 16%.

**Known limitation:** names are lowercased before analysis (for consistency
with the policy engine), so base64 and base32 collapse into the same
observable. This function cannot distinguish them and does not try.

### Exclusions

The reputation-lookup problem is not solved by scoring. It is solved by a list
of parent domains — DNSBL providers, endpoint security vendors, CDNs, and
`.arpa` outright — in
[`internal/detect/exclusions.go`](../../internal/detect/exclusions.go), each
with a comment explaining why it is there.

**Residual risk, stated rather than glossed:** an attacker who tunnels through
a domain resembling a security vendor's, or who compromises one, evades this
completely. That is what an exclusion list costs. The alternative — no list —
is a detector nobody leaves enabled, which costs everything.

`TestDNSBLTrafficWouldFireWithoutExclusions` pins both directions, so if the
exclusions ever stop being the reason that traffic is quiet, a test fails.

---

## Worked example

From the [lab scenario](../../labs/dns-tunnelling.md): 384 queries over five
minutes, two base32 labels (55 and 42 chars) beneath `tunnel.example`, TXT.

| Signal | Measured | Normalised | × weight | = |
|---|---|---|---|---|
| `unique_subdomains` | 384 | 1.00 | 0.28 | **0.28** |
| `mean_subdomain_entropy` | 4.45 | 1.00 | 0.18 | **0.18** |
| `mean_qname_length` | 113 | 1.00 | 0.14 | **0.14** |
| `max_label_length` | 55 | 0.76 | 0.10 | **0.08** |
| `encoded_label_ratio` | 1.00 | 1.00 | 0.12 | **0.12** |
| `payload_qtype_ratio` | 1.00 | 1.00 | 0.10 | **0.10** |
| `nxdomain_ratio` | 0.00 | 0.00 | 0.08 | **0.00** |
| | | | **score** | **0.90** |

Six contributing signals, three required. Score 0.90 → **high**. Confidence
0.98 after sample-size damping at 384 queries.

Note `nxdomain_ratio` contributed nothing, because the attacker's domain
resolves — as a real one must. The finding does not depend on it, which is the
point of not requiring any particular signal.

---

## What this will not catch

Stated plainly, because a detection page that only lists successes is a
marketing page.

**A slow tunnel.** A few messages an hour falls below the volume gates by
design. Raising sensitivity to catch it means alerting on every CDN. This is a
genuine trade and the gates are set where they are deliberately.

**A tunnel through an excluded domain.** As above.

**A tunnel using few, reused names** — for instance encoding data in the query
*type* or timing rather than the name. Low cardinality, low entropy, and this
detector says nothing. Such channels are much lower bandwidth, which is why
they are rare, not why they are detected.

**A tunnel that pads its labels to look like a CDN** and uses A records only.
It loses `payload_qtype_ratio` and `encoded_label_ratio` and would need to
score on the remaining five.

**Anything after the fact.** This is detection, not prevention. The finding
tells you a tunnel ran; it does not mean it was stopped. Nothing is blocked
automatically — see [README.md](README.md#observe-score-explain-alert--never-block).

## Prevention, as opposed to detection

The controls that actually stop this, roughly in order of effectiveness:

1. **Force all DNS through DNS Daddy.** Block outbound 53 and 853 to everything
   else at the firewall. A tunnel pointed at `8.8.8.8` never reaches you.
2. **Handle encrypted DNS.** DoH is HTTPS on 443 and cannot be blocked by port.
   See [../dns-security/encrypted-dns.md](../dns-security/encrypted-dns.md).
3. **Block confirmed tunnel domains by policy.** Effective on the next query —
   the answer cache is purged on a policy change.
4. **Block newly registered domains.** Tunnel carrier domains are usually days
   old. On by category, off by default because of the false positives.
5. **Endpoint controls.** A tunnel needs a process holding it open. This is
   where it is actually solved.

## Further reading

- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — DNS format; the 63-byte
  label and 253-byte name limits a tunnel works against
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) — DNS over HTTPS
- [MITRE T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE T1048.003](https://attack.mitre.org/techniques/T1048/003/)
- [SANS: Detecting DNS Tunneling](https://www.sans.org/white-papers/34152/)
