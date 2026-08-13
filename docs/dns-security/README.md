# DNS as a security control point

Why a protocol designed in 1983 to save people memorising IP addresses ended up
being one of the more useful places to put a security control — and what that
position can and cannot do.

## The observation

Almost everything a device does starts with a DNS lookup.

Opening a page, checking for updates, syncing a file, phoning home, fetching a
second-stage payload, exfiltrating a customer list — nearly all of it begins
with "what is the address of…". The exceptions are worth naming, because they
are exactly the blind spots: connections to hard-coded IP addresses, traffic
inside an already-established tunnel, and anything resolving somewhere other
than your resolver.

Three properties follow, and they are what make DNS interesting:

**It is early.** The lookup happens before the connection. Stopping the lookup
stops the connection before a single packet reaches the destination — no TLS
handshake, no HTTP request, no payload delivered.

**It is universal.** One control point covers every device on the network. No
agent, no certificate on the endpoint, nothing to install on the smart TV or
the label printer or the contractor's laptop.

**It is cheap.** A lookup is one UDP packet. Filtering millions a day costs
less compute than inspecting a single TLS session.

And one property that is the whole difficulty:

**It is easy to route around.** A device configured to use `8.8.8.8`, or an
external DoH resolver, never asks you anything. See
[encrypted-dns.md](encrypted-dns.md).

## Protective DNS

"Protective DNS" (PDNS) is the term for a resolver that applies a security
policy to what it will resolve — checking each name against threat intelligence
and refusing to answer for known-malicious domains.

It is not a new idea, and it is not a product category so much as a
configuration. The UK's [NCSC PDNS] service does it for the public sector;
[Quad9] and [Cloudflare for Families] do it publicly; commercial secure web
gateways do it as one feature among many. [CISA] and NCSC both publish guidance
recommending it.

What a protective resolver adds over a plain one:

| | |
|---|---|
| **Blocking** | Known-malicious domains do not resolve. |
| **Visibility** | A record of what was asked for, by whom, and what happened. |
| **Policy** | Different rules for different parts of the network. |
| **Detection** | Behavioural analysis of the query stream itself. |

The first is what people buy it for. The second is usually what turns out to be
more useful, because a complete record of what every device asked for is a
remarkable investigative resource and most networks do not have one.

### Why self-host it

Public protective resolvers block known-bad domains, and that is genuinely
worth having. What they cannot tell you is:

- which device made the request,
- why it was blocked,
- whether one endpoint has been quietly beaconing to the same infrastructure
  for three weeks,
- or anything you can inspect afterwards.

They also see all of your DNS traffic, which is a trade some organisations
cannot make.

Self-hosting moves that trust to you, along with the responsibility. Your users'
lookups become visible to you and retained on your terms. That is appropriate
for a network you administer where people know; it is worth thinking about
before pointing it at people who do not.

---

## The three layers, and what each actually protects

A common confusion is treating these as alternatives. They are orthogonal.

### 1. Reputation filtering — *is this domain known bad?*

Look the name up against curated threat intelligence and refuse to answer if it
is listed.

**Strength.** Cheap, fast, high confidence. A domain on a curated malware feed
is malicious because a human or a pipeline established that it was.

**Weakness.** Entirely reactive. A domain registered an hour ago is on nothing.
Feeds are always incomplete and always slightly stale.

This is DNS Daddy's blocking layer, and the only layer that blocks. See
[../threat-intel.md](../threat-intel.md).

### 2. Behavioural detection — *is this traffic shaped wrongly?*

Ignore reputation entirely and look at the query stream: cardinality, entropy,
timing, record types, failure rates.

**Strength.** Works on infrastructure nobody has catalogued, which is precisely
where reputation fails. A tunnel through a domain registered this morning has
no reputation and a very distinctive shape.

**Weakness.** Inference. Legitimate services produce the same shapes —
reputation lookups look exactly like tunnels, CDNs look like high-cardinality
enumeration, updaters look like beacons. False positives are inherent, not a
tuning problem.

This is DNS Daddy's detection layer, and it is **alert-only** for exactly that
reason. See [../detection/README.md](../detection/README.md).

### 3. Authenticity — *is this answer genuine?*

DNSSEC. Cryptographic proof that an answer is what the domain's owner
published.

**Strength.** Addresses a class of attack the other two cannot touch:
poisoning, hijacking, and a malicious resolver.

**Weakness.** Most domains are unsigned. It says nothing about whether a domain
is *trustworthy* — a phishing site can be perfectly signed.

DNS Daddy does not validate DNSSEC; it records the upstream's verdict. See
[dnssec.md](dnssec.md), which is explicit about what that is worth.

---

## What DNS filtering does not do

Worth stating clearly, because protective DNS is often over-sold.

**It does not stop a connection to an IP address.** Malware that skips DNS
skips this control entirely. Plenty does.

**It does not see inside anything.** A malicious file downloaded from a
perfectly reputable file-sharing domain resolves normally, because the domain
is fine.

**It does not stop a determined insider.** Anyone who can change their own DNS
settings, or use an external DoH resolver, is past it — unless the network
stops them, which is a firewall's job.

**It is not endpoint protection**, and treating it as a substitute is the most
expensive mistake available here. It is a wide, cheap net. Wide and cheap is
valuable; fine it is not.

The realistic framing: DNS filtering removes a large volume of commodity threat
cheaply, and gives you visibility you would otherwise have to buy separately.
It is one layer.

## Where DNS shows up in frameworks

- **[MITRE ATT&CK]** — DNS appears as [T1071.004] (C2 over DNS), [T1048.003]
  (exfiltration), [T1568.002] (DGAs), and [T1132.001] (encoding). The mappings
  DNS Daddy uses, and the ones it deliberately does not, are in
  [../detection/mitre.md](../detection/mitre.md).
- **CIS Controls v8** — 4.9 and 9.2 (DNS filtering), 8.2 and 8.5 (audit log
  collection and content), 13.x (network monitoring).
- **NIST CSF 2.0** — mostly DE.CM (continuous monitoring) with PR.PS/PR.IR
  (protective technology).
- **NCSC** — [Protective DNS guidance][NCSC PDNS].

DNS Daddy is not audited or certified against any of these. The mappings are
for orientation, not compliance.

## Further reading

- [dnssec.md](dnssec.md) — authenticity and integrity
- [encrypted-dns.md](encrypted-dns.md) — DoH, DoT, and bypass
- [../detection/README.md](../detection/README.md) — detection engineering
- [../threat-hunting/README.md](../threat-hunting/README.md) — hunting with DNS
- [../../labs/README.md](../../labs/README.md) — see it happen, offline
- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) /
  [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — the original DNS
  specification, still readable and still accurate
- [RFC 9499](https://www.rfc-editor.org/rfc/rfc9499) — DNS terminology, worth
  having open when reading anything else

[NCSC PDNS]: https://www.ncsc.gov.uk/information/pdns
[CISA]: https://www.cisa.gov/resources-tools/resources/selecting-protective-dns-service
[Quad9]: https://www.quad9.net/
[Cloudflare for Families]: https://one.one.one.one/family/
[MITRE ATT&CK]: https://attack.mitre.org/
[T1071.004]: https://attack.mitre.org/techniques/T1071/004/
[T1048.003]: https://attack.mitre.org/techniques/T1048/003/
[T1568.002]: https://attack.mitre.org/techniques/T1568/002/
[T1132.001]: https://attack.mitre.org/techniques/T1132/001/
