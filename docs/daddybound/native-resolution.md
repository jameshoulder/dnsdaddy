# Resolving DNS yourself

DNS Daddy can answer a query in one of two ways, and `dns.resolution_mode`
chooses which.

## Forward mode

```yaml
dns:
  resolution_mode: forward
  upstreams:
    - tls://9.9.9.9:853#dns.quad9.net
```

DNS Daddy sends each question to the configured upstream recursive resolvers and
returns what they say. This is what every deployment before this release did and
it remains the default.

What it means for DNSSEC: nothing is validated here. If an upstream sets the AD
bit, that is recorded as what it is — a claim by a machine somebody else
operates, about records this deployment never saw, over a link that may or may
not be authenticated. The query log spells that claim `validated`, which is
deliberately not the same word as the verdicts Daddybound reaches.

What it means for privacy: every query name goes to the configured upstreams,
and to nobody else. With DoT or DoH upstreams it goes encrypted.

## Native mode

```yaml
dns:
  resolution_mode: native
```

Daddybound resolves the question itself: root hints, then the TLD, then the
zone's own authoritative servers, and it authenticates what it read there
against the IANA root trust anchors. No upstream resolver is contacted and none
needs configuring.

**This is a production beta.** It is not the default and should be chosen
deliberately. See "Before you switch" below.

### What local validation actually guarantees

Precisely this: the records in the answer carry signatures that chain, through
DS and DNSKEY records this resolver fetched and checked itself, to a trust
anchor this resolver holds. Not "the answer is true" — DNSSEC says nothing about
whether a zone's operator is honest, only that the data is the data they
published and it has not been altered on the way here.

Four outcomes, and what each does to the answer a client receives:

| State | What it means | What the client gets |
|---|---|---|
| Secure | The records authenticate to a configured trust anchor. | The answer. AD set if the client asked. |
| Insecure | An authenticated proof shows the name is in an unsigned part of the namespace. A proof, not an absence of one. | The answer, AD clear. |
| Bogus | A secure delegation was established and the data failed to validate under it. | SERVFAIL, no records, EDE 6. |
| Indeterminate | This validator could not decide — no anchor covers the name, an algorithm it cannot read, a limit reached. | The answer, AD clear, EDE 5. |

Two of those are worth the argument.

**Bogus is SERVFAIL with nothing attached, and there is no way to soften it.**
Returning the records with a warning would be worse than useless: nothing on the
client side reads warnings and the records would be used. There is no fallback
to the forwarder either — a fallback would mean an attacker who forges one
answer gets it served anyway, and the validation would be theatre.

**Indeterminate returns the answer.** It is a statement about this resolver
rather than about the data. Refusing would take a deployment offline for the
entire unsigned Internet the moment a trust anchor went missing, and would let
anyone cause an outage by publishing something exotic.

### Trust anchors

The IANA root anchors are compiled in, as digests in the form IANA publishes.
Daddybound follows RFC 5011 from there: a key the root announces and signs for
becomes an anchor after a thirty-day hold-down served continuously, and a
self-signed revocation withdraws one. The managed state lives beside the
database in `daddybound-anchors.json`. Losing it costs hold-down progress, not
the ability to validate — the compiled-in digests are never discarded.

### What it costs

Authoritative queries leave this host over ordinary port 53, in the clear. There
is no DoT or DoH to the root or to a TLD because authoritative servers do not
offer it, and pretending otherwise would be pretending. QNAME minimisation
limits what each server on the path learns to the labels it needs — the root
sees only the TLD — but it does not remove the exposure. An operator who chose
DoT upstreams specifically so that no query names leave in plaintext should know
that native mode changes that.

Latency and CPU: see [benchmark.md](benchmark.md). The short version is that a
warm native query currently costs about 380 µs of CPU against about 21 µs for a
cache hit in forward mode, three quarters of it signature verification that is
repeated on every query.

### Before you switch

Native mode needs outbound UDP and TCP port 53 to arbitrary addresses on the
Internet. A network that only permits DNS to its own resolvers will make it fail
— and it fails honestly, as `unreachable`, rather than quietly falling back.

Learn mode is how to find that out first. In forward mode with
`dns.local_dnssec_validation: observe`, Daddybound resolves and validates the
same names alongside the forwarder without changing any answer, and records what
it found. A run with no `unreachable` rows is evidence that native mode would
work in this deployment. In native mode the separate Learn observer is not
started, because Daddybound is already resolving the answer the client receives
and a shadow resolution would double every query.

## Which address do clients use?

The dashboard's resolver card answers this, and the API does at
`GET /api/v1/resolver/status`.

On a LAN it is discovered from the machine's interfaces and no configuration is
needed. On a VPS it usually cannot be: the interface holds a private address and
the provider applies a public one by NAT, so nothing on the machine can see how
the world reaches it. Set it explicitly:

```yaml
dns:
  advertised_addresses:
    - 203.0.113.10
```

DNS Daddy does not ask a third-party "what is my IP" service. That would be a
self-hosted resolver making an outbound call to somebody else's server to learn
something the operator already knows, and reporting whatever came back as fact.

## Whichever mode you run

The client ACL applies identically. Native recursion does not turn a public host
into an open resolver: the ACL is checked before anything reaches a backend, so
an unauthorised client is refused *and* no resolution happens on its behalf —
which matters, because a resolver that answered REFUSED after walking from the
root would still have spent the bandwidth and done the attacker's lookup.
