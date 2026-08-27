# Running DNS Daddy alongside Pi-hole

**Short answer:** put DNS Daddy in front, with Pi-hole as its upstream.

```
Clients ──► DNS Daddy ──► Pi-hole ──► Upstream
```

The reverse order costs DNS Daddy almost everything that makes it worth
running. This page explains why, so you can check the reasoning rather than
take the recommendation on faith.

> **Status: reasoned from the code, not measured.** Neither topology has been
> deployed and benchmarked. Every claim below is traceable to a named part of
> the implementation, and the section at the end lists what would have to be
> measured to upgrade this from analysis to evidence.

---

## DNS Daddy is not trying to replace Pi-hole

Pi-hole is very good at what it does: network-wide ad and tracker blocking,
with a mature ecosystem, per-client groups, and local DNS records. If ad
blocking is what you want, Pi-hole on its own is a complete answer and DNS
Daddy adds nothing you need.

DNS Daddy is aimed at a different question — not "what should I not download?"
but "what is happening on my network, and should I be worried about it?"
Protective DNS, per-network policy, threat-intelligence attribution, and
behavioural detection that explains itself. The two overlap only at the point
where both can return NXDOMAIN.

So this is not a migration guide. It is about keeping Pi-hole doing its job
while DNS Daddy does a different one.

---

## The constraint everything follows from

**A DNS forwarder cannot tell the next resolver who the original client was.**

When DNS Daddy forwards to Pi-hole, the query arrives at Pi-hole from DNS
Daddy's address. When Pi-hole forwards to DNS Daddy, it arrives from Pi-hole's
address. There is no header to carry the original client, because DNS has no
such thing in general use.

EDNS Client Subnet (RFC 7871) is the closest mechanism, and it does not help
here: **DNS Daddy does not implement ECS** in either direction. Even if it did,
ECS carries a truncated subnet for CDN geolocation, not a host identity, and
Pi-hole does not attribute clients from it.

So whichever resolver the clients point at keeps client identity, and the one
behind it sees a single address. Everything below is a consequence of that.

---

## Topology A — DNS Daddy first (recommended)

```
Clients ──► DNS Daddy :53 ──► Pi-hole :53 ──► Upstream
```

| | |
|---|---|
| **Client identity in DNS Daddy** | Preserved. Real source addresses. |
| **Client identity in Pi-hole** | Lost. Every query appears to come from DNS Daddy. |
| **DNS Daddy per-network policy** | Works. Networks, policies and per-client naming all function normally. |
| **DNS Daddy behavioural detection** | Works. Detectors key on `<client>\|<domain>`, so per-client beaconing, tunnelling, NXDOMAIN and DGA analysis are meaningful. |
| **Pi-hole ad blocking** | Works, for everything DNS Daddy forwards. |
| **Pi-hole per-client groups** | **Broken.** Group management is per-client, and Pi-hole now has one client. |
| **Pi-hole per-client statistics** | Collapse to a single client. |

**What you give up:** Pi-hole's per-client features. If you rely on Pi-hole
groups to give the kids' tablets a different blocklist from the office
machines, that stops working — move those distinctions into DNS Daddy's
networks and policies instead, where they will work.

### Two consequences worth knowing about

**1. A Pi-hole block looks like a normal answer to DNS Daddy.** When Pi-hole
blocks a domain it returns `0.0.0.0`, `NXDOMAIN` or a null address. DNS Daddy
receives that as an ordinary upstream response and records the query as
`Resolved`. Your DNS Daddy query log will therefore show ad domains as allowed,
because from DNS Daddy's seat they were — it forwarded them and got an answer.

This is not a bug and it is not fixable without DNS Daddy guessing at another
resolver's intent, which it will not do. Read block counts for ads in Pi-hole
and block counts for threats in DNS Daddy.

**2. DNS Daddy's cache sits in front of Pi-hole's.** A cache hit in DNS Daddy
never reaches Pi-hole, so Pi-hole's statistics undercount, and a domain you add
to a Pi-hole blocklist keeps resolving until DNS Daddy's cached entry expires
(`cache.max_ttl`, default 24 h; `cache.min_ttl` sets the floor). If that
latency bothers you, lower `cache.max_ttl`, or flush by restarting DNS Daddy.

DNS Daddy's *own* blocking is unaffected by this: the policy decision is made
**before** the cache is consulted (`dnsserver.Handler.Handle` evaluates policy,
and only then calls `resolver.Resolve`), so a newly blocked domain is blocked
immediately regardless of what is cached.

### Configuring it

On DNS Daddy, point the upstream at Pi-hole:

```yaml
dns:
  upstreams: ["udp://192.168.1.5:53"]   # your Pi-hole
```

or `DNSDADDY_UPSTREAMS=udp://192.168.1.5:53`.

Two things to be deliberate about:

- **That leg is unencrypted.** DNS Daddy defaults to DNS-over-TLS upstreams;
  pointing it at Pi-hole over plain UDP replaces that. The leg is inside your
  LAN, which is usually fine — but the *encrypted* leg is now Pi-hole's
  responsibility, so configure Pi-hole with an encrypted upstream (cloudflared
  or similar) if you want that property back.
- **Pi-hole must permit DNS Daddy's address.** Set Pi-hole's interface
  behaviour to allow queries from it.

Point DHCP at DNS Daddy, and run `dnsdaddy doctor` before you do.

---

## Topology B — Pi-hole first (not recommended)

```
Clients ──► Pi-hole :53 ──► DNS Daddy :53 ──► Upstream
```

| | |
|---|---|
| **Client identity in Pi-hole** | Preserved. |
| **Client identity in DNS Daddy** | **Lost.** Every query arrives from Pi-hole's address. |
| **DNS Daddy per-network policy** | **Collapses.** One source address means one network, so one policy applies to your whole estate. |
| **DNS Daddy behavioural detection** | **Substantially defeated.** See below. |
| **DNS Daddy query log** | Incomplete. Pi-hole's cache absorbs repeats, and anything Pi-hole blocks never arrives. |
| **Pi-hole ad blocking and groups** | All work normally. |

**Why the detection loss is the decisive problem.** The detectors are
client-scoped by construction — the tracker key is `<client>|<domain>`. With
every device behind one address, "this host is beaconing at a fixed interval"
becomes "the aggregate of forty devices contains something periodic", which is
true of every network and means nothing. Volume-gated detectors like the
NXDOMAIN and DGA analysers see forty machines' combined miss rate against
thresholds calibrated for one, so they misfire. You get noise where you wanted
signal, and you lose the ability to answer "which device did this?", which is
the question DNS Daddy exists to answer.

Add to that: any domain Pi-hole blocks never reaches DNS Daddy, so DNS Daddy
never sees it — including any that its threat feeds would have flagged as
malware or C2. You lose threat visibility for exactly the traffic most likely
to be interesting.

**When Topology B is nonetheless reasonable:** if you have an established
Pi-hole deployment you are not willing to move, and you want DNS Daddy purely
as an upstream filtering layer with aggregate reporting, it works. Set
expectations accordingly, put a single network covering Pi-hole's address in
DNS Daddy, and consider turning behavioural detection off
(`DNSDADDY_DETECTION_ENABLED=false`) rather than reading findings that cannot
mean what they appear to.

---

## Failure modes

Both topologies chain two resolvers, so either one going down takes DNS with
it for anything not already cached.

- **Topology A, Pi-hole down:** DNS Daddy's only upstream fails. Uncached
  queries return SERVFAIL. `dnsdaddy doctor` reports this under `UPSTREAM`.
  Mitigation: list a public resolver as a second upstream, accepting that ads
  are unblocked while Pi-hole is down.
- **Topology B, DNS Daddy down:** Pi-hole's upstream fails. Pi-hole has its own
  fallback upstream configuration; use it.
- **Either, front resolver down:** the network has no DNS. This is true of any
  single-resolver deployment and is why `docs/deploy.md` recommends testing one
  client before changing DHCP.

---

## Summary

| | A — DNS Daddy first | B — Pi-hole first |
|---|---|---|
| DNS Daddy client attribution | ✅ | ❌ |
| DNS Daddy per-network policy | ✅ | ❌ |
| DNS Daddy behavioural detection | ✅ | ❌ |
| DNS Daddy threat visibility | ✅ full | ⚠️ partial |
| Pi-hole ad blocking | ✅ | ✅ |
| Pi-hole per-client groups | ❌ | ✅ |
| Pi-hole per-client statistics | ❌ | ✅ |

**Recommendation: Topology A.** Pi-hole keeps blocking ads, which is what it is
excellent at. DNS Daddy keeps the client identity it needs to do anything
useful. The cost is Pi-hole's per-client features, and those distinctions can
be expressed as DNS Daddy networks and policies instead.

If you need Pi-hole's per-client groups more than you need DNS Daddy's
per-client visibility, run Pi-hole alone. That is a legitimate answer, and a
better one than running both in an order that makes one of them ornamental.

---

## What would make this evidence rather than analysis

Contributions welcome. To upgrade this page:

1. Deploy both topologies on a real LAN with at least three distinct clients.
2. Record, in each: what DNS Daddy's Networks page shows, what the query log
   attributes, and whether a `dnsdaddy-lab` beaconing scenario produces a
   finding naming the right client.
3. Record what Pi-hole's client list and per-client statistics show.
4. Measure added latency for a cache miss through two hops.
5. Kill each resolver in turn and record what clients actually experience.

Open a pull request with the results — including the ones that contradict this
page.
