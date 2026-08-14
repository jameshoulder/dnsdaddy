# DNSSEC

What it does, what it does not do, what DNS Daddy can honestly tell you about
it, and where that stops.

## The problem DNSSEC solves

DNS was designed in 1983 with no authentication. A resolver asks a question and
believes the answer. Anything that can produce a plausible-looking response —
an off-path attacker guessing a query ID, a compromised nameserver, a malicious
resolver, a machine on the same wifi — can redirect a name anywhere.

That is not a bug in an implementation. It is the protocol.

**DNSSEC** ([RFC 4033]–[RFC 4035]) adds cryptographic signatures over DNS data.
Each zone signs its records; its parent signs a hash of its signing key; the
chain runs to the root, whose key is the trust anchor. A **validating resolver**
verifies that chain and refuses to serve data that fails.

The guarantee is: *this answer is what the domain's owner published, and it has
not been altered in transit or substituted by anyone along the way.*

## What DNSSEC does not do

Worth being exact about, because it is routinely overstated.

**It does not encrypt anything.** Queries and answers travel in plaintext.
Anyone on the path sees every name you resolve. DNSSEC is about *authenticity
and integrity*, not confidentiality — see
[encrypted-dns.md](encrypted-dns.md).

**It does not make a domain trustworthy.** A phishing site can be perfectly
signed. DNSSEC proves the answer came from whoever owns the domain; it says
nothing about whether they deserve your credentials.

**It does not protect the last mile by itself.** Between a validating resolver
and a stub client, the answer is an ordinary DNS response with an AD bit set —
and the AD bit is not cryptographic. If the path between your device and your
resolver is hostile, DNSSEC validation performed upstream of that path does not
help. Only a client that validates for itself gets an end-to-end guarantee.

**It is not universally deployed.** Most domains are unsigned. An unsigned zone
is not "insecure" in the DNSSEC sense; it is simply outside the system, and a
validating resolver returns its data unauthenticated.

## The four validation outcomes

[RFC 4035] defines four states, and the distinctions matter for reading what
DNS Daddy reports:

| State | Meaning |
|---|---|
| **Secure** | A chain of trust exists and validates. |
| **Insecure** | A chain of trust proves the zone is *unsigned*. Provably outside DNSSEC — not an error. |
| **Bogus** | A chain should exist but validation failed: bad signature, expired RRSIG, broken delegation. **A validator must not return this data.** |
| **Indeterminate** | The validator cannot decide, usually for want of a trust anchor. |

Note that **Insecure is a positive result**. Proving a zone is unsigned
requires validating an authenticated denial of existence for the DS record —
it is not the same as "we did not check".

That distinction is exactly where DNS Daddy's telemetry stops, and the reason
its statuses are named the way they are.

---

## What DNS Daddy actually does

**DNS Daddy does not validate DNSSEC.** It is a forwarding resolver: it does
not walk the root zone, does not hold a trust anchor, and does not verify a
single signature.

What it does is **ask the upstream to report its verdict, and record the
answer.**

### The mechanism

[RFC 6840] §5.7 defines the AD bit in a *query* as the requester saying it
understands and wants the AD bit in the response. DNS Daddy sets it on every
outgoing query when `dns.dnssec_telemetry` is on (the default).

This is deliberately **not** the DO bit. DO requests DNSSEC records be included
in the response, which inflates every answer. AD-in-query asks only for the
verdict. It costs one bit and changes nothing about the answer.

Two consequences:

**The AD bit is stripped again before answering a client that did not ask for
it.** [RFC 4035] §3.2.3 says a resolver must not set AD unless the client set
DO or AD in its own query. Because DNS Daddy now sets AD on every upstream
query for telemetry, verdicts come back on answers no client requested — and on
cache hits populated by a different client entirely. Passing that through would
tell a client its answer was authenticated when it never asked us to check,
which is precisely the assurance the AD bit is not permitted to give.

**A DNSSEC-aware client is unaffected.** A stub setting DO or AD gets the AD
bit as normal.

### The three statuses

Recorded per query, visible in the query log, the dashboard and the API:

| Status | What it means | What it does **not** mean |
|---|---|---|
| `validated` | The upstream set AD, having authenticated the answer. | That *we* verified anything. |
| `unvalidated` | No AD bit came back. | **Not** "insecure" in the RFC sense. This covers an unsigned zone *and* an upstream that does not validate, equally. |
| `servfail` | The upstream could not answer. | **Not** "bogus". Failed validation is one cause among several. |

`unvalidated` is the important one to read correctly. A forwarder cannot
distinguish "this zone is provably unsigned" from "this upstream does not do
DNSSEC" — both look like a missing bit. Calling it `insecure` would borrow the
RFC's specific meaning of *provably unsigned*, which is a stronger claim than
the measurement supports. Hence the deliberately duller word.

### Why this is worth doing anyway

It converts an untestable claim into a measurement.

"We forward to validating resolvers" is a statement about a configuration file.
`dnssec: validated` on 78% of your queries is an observation, and if that
number moves you can go and find out why.

It also gives you a cheap check for the failure mode nobody notices: an
upstream silently stopping validation. That looks like nothing at all until you
are watching the number.

### The limit that matters

**The AD bit is self-reported by the upstream, and a malicious upstream will
happily set it.** This telemetry tells you what the upstream *said*, and it is
worth exactly as much as your trust in that upstream.

If the upstream is the threat you are worried about, this does not help. Local
validation is the answer, and it is not implemented — see
[capabilities.md](../capabilities.md) and [roadmap.md](../roadmap.md).

---

## Reading the telemetry

Dashboard: the **Query log** has a DNSSEC column. Hover for what each value
means.

API:

```bash
# Validation status across recent queries
curl -H "Authorization: Bearer dnsd_…" \
  'https://your-server/api/v1/queries?limit=500' \
| jq -r '.queries[] | .dnssec' | sort | uniq -c | sort -rn
```

```
   340 validated
   142 unvalidated
     3 servfail
```

**A healthy picture** is a solid majority `validated` with a stable
`unvalidated` tail (unsigned domains — still the majority of the internet) and
`servfail` near zero.

**Worth investigating:**

- `validated` dropping towards zero → the upstream stopped validating, or you
  changed to one that does not.
- A domain that was `validated` yesterday and is `servfail` today → possible
  expired signature or broken delegation at that domain.
- `servfail` rising across *many* domains at once → your upstream or your
  network, not the domains.

### The resolution-failure finding

The `resolution_failure` detector reports registered domains where most lookups
return SERVFAIL.

It is **not** called `dnssec_validation_failure`, and that naming is the point.
DNS Daddy cannot tell a bogus signature from an unreachable nameserver, so the
finding lists every possible cause in its evidence:

```json
"possible_causes": [
  "authoritative nameservers unreachable",
  "broken delegation",
  "DNSSEC validation failure at the upstream resolver",
  "upstream resolver problem"
],
"local_dnssec_validation": false
```

It carries **no ATT&CK mapping**. Infrastructure breakage is not an adversary
technique, and mapping it to one because DNSSEC failures *can* accompany
hijacking would be decoration. See [../detection/mitre.md](../detection/mitre.md).

## Investigating a suspected DNSSEC failure

DNS Daddy can tell you a domain is failing. Confirming *why* needs a validating
resolver, which means tools rather than this dashboard:

```bash
# Does it fail everywhere, or just through your upstream?
dig +dnssec example.com @9.9.9.9
dig +dnssec example.com @1.1.1.1

# Full validation trace — this names the broken link
delv +rtrace example.com

# Does it work with validation disabled? If yes, it is DNSSEC.
dig +cd example.com @9.9.9.9
```

`+cd` (checking disabled) is the decisive test. If a name fails normally and
succeeds with `+cd`, validation is the cause.

[DNSViz](https://dnsviz.net/) renders the whole chain graphically and is the
fastest way to show a domain owner what is wrong with theirs.

## Algorithms

Current guidance ([RFC 8624], and its successors):

**Recommended for signing:** ECDSA P-256 with SHA-256 (algorithm 13), and
Ed25519 (algorithm 15) where supported. Both give strong security with small
signatures, which matters because DNSSEC responses are large and large UDP
responses fragment or force TCP retries.

**Do not use for new deployments:** RSA/SHA-1 (5, 7) — SHA-1 is broken and
these are deprecated. DSA (3, 6) — deprecated. RSA/MD5 (1) — must not be used.
RSA/SHA-256 (8) still validates widely but produces signatures several times
larger than ECDSA for no security benefit at typical key sizes.

DNS Daddy does not implement any of this — it does not validate, so it has no
algorithm policy. This is here because operators reading a DNSSEC page tend to
want it, and because outdated recommendations circulate widely.

DNS Daddy does **not** currently surface which algorithm signed an answer;
without local validation it does not see the DNSKEY records. That is on the
roadmap alongside validation itself.

## Further reading

- [RFC 4033], [RFC 4034], [RFC 4035] — DNSSEC specification
- [RFC 6840] — clarifications, including the AD-bit-in-query signal
- [RFC 8624] — algorithm implementation requirements
- [RFC 9364] — DNSSEC BCP, a good single entry point
- [DNSViz](https://dnsviz.net/) — visual chain-of-trust debugging
- [Internet Society DNSSEC basics](https://www.internetsociety.org/deploy360/dnssec/basics/)

[RFC 4033]: https://www.rfc-editor.org/rfc/rfc4033
[RFC 4034]: https://www.rfc-editor.org/rfc/rfc4034
[RFC 4035]: https://www.rfc-editor.org/rfc/rfc4035
[RFC 6840]: https://www.rfc-editor.org/rfc/rfc6840
[RFC 8624]: https://www.rfc-editor.org/rfc/rfc8624
[RFC 9364]: https://www.rfc-editor.org/rfc/rfc9364
