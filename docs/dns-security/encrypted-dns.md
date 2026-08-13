# DoH, DoT, and encrypted DNS

Encrypted DNS transport, how DNS Daddy uses it, and the honest position on
clients that use it to route around you.

## The single most confused point in DNS security

**DNSSEC and encrypted transport solve different problems. Neither replaces
the other.**

| | Protects | Does not protect |
|---|---|---|
| **DNSSEC** | *Authenticity and integrity.* This answer is what the domain owner published and has not been altered. | Confidentiality. Every query is still in plaintext for anyone on the path. |
| **DoH / DoT** | *Confidentiality and integrity in transit.* Nobody between you and the resolver can read or alter your queries. | Authenticity of the data. Your resolver can still lie to you, perfectly encrypted. |

The failure mode of confusing them is real and common: "we use DNS over HTTPS,
so our DNS is secure" means nobody on the coffee-shop wifi can see your lookups
and says nothing whatever about whether the answers are genuine.

Together they are complementary — encrypted transport to a resolver you trust,
which validates DNSSEC for you. See [dnssec.md](dnssec.md).

## The protocols

**DNS-over-TLS (DoT)**, [RFC 7858], port **853**. Ordinary DNS wire format
inside a TLS connection. Because it has its own port, it is trivially
identifiable on a network — which makes it easy for an operator to allow to
their own resolver and block elsewhere, and correspondingly unattractive to
anything trying to hide.

**DNS-over-HTTPS (DoH)**, [RFC 8484], port **443**. DNS messages inside HTTPS
requests, on the same port as all web traffic, often to the same CDNs. This is
the crux: **DoH is designed to be indistinguishable from web browsing.** That
is a genuine privacy win against a hostile network, and it is precisely what
makes it unblockable by port for a network operator who *is* the legitimate
administrator.

**DNS-over-QUIC (DoQ)**, [RFC 9250], port 853/UDP. Less common. DNS Daddy does
not implement it.

---

## What DNS Daddy does

### Upstream: encrypted by default

The shipped configuration forwards over DoT with certificate verification:

```yaml
dns:
  upstreams:
    - "tls://9.9.9.9:853#dns.quad9.net"
    - "tls://1.1.1.1:853#cloudflare-dns.com"
```

The `#hostname` is not decoration — it is the name the upstream's certificate
is verified against. Without verification, TLS gives you encryption to
*somebody*, which is not the point.

This means your ISP, and anyone between you and the upstream, cannot read or
tamper with the lookups DNS Daddy forwards. It also removes off-path cache
poisoning entirely: an attacker cannot inject a forged answer into a TLS
session.

Configuring a plaintext upstream is possible and logs a warning at startup.

### Serving clients

| Transport | Where | Authentication |
|---|---|---|
| UDP/TCP :53 | Always | Source IP against the client ACL |
| DoT :853 | If a certificate is configured | Per-network token via TLS |
| DoH :443 | `/dns-query/<token>` behind your reverse proxy | The token in the path |

**The DoH token is what makes roaming work.** A laptop in a hotel has no IP you
can allow-list, so each network carries a random token forming a DoH URL;
presenting it applies that network's policy from anywhere. An unknown token
returns 404 rather than falling back to IP attribution — falling back would
quietly apply the wrong policy, which is worse than a visible error.

**The bare `/dns-query` path requires a token by default.** Behind a public
reverse proxy, an untokenised path would be an open DoH resolver for anyone who
found it. `http.allow_untokenized_doh` exists and defaults to off.

---

## Clients bypassing DNS Daddy

The part where being straightforward matters more than sounding capable.

**DNS Daddy cannot prevent a device from using an external encrypted resolver,
and does not claim to.**

A browser or application configured for DoH opens an HTTPS connection to
`cloudflare-dns.com` or `dns.google` and resolves there. DNS Daddy never sees
the query. It is not blocked, not logged, not filtered — it is *absent*.

That is not a gap in the implementation. Distinguishing DoH from ordinary HTTPS
requires TLS interception or SNI-based filtering at the network layer, which is
a different class of product operating at a different point in the network.

### What actually works

These are **network controls the operator configures**, not DNS Daddy features.
Listed by effectiveness:

**1. Block outbound 53 and 853 except to DNS Daddy.** Stops every plaintext and
DoT bypass. Cheap, effective, and the first thing to do. It does nothing about
DoH.

```
# Allow only DNS Daddy to talk DNS outbound
allow  from <dnsdaddy-ip> to any port 53,853
block  from <lan>         to any port 53,853
```

**2. Block the known DoH endpoints.** Maintain a list of public DoH provider
hostnames and IPs and block them at the firewall, or block them in DNS Daddy
itself so the *bootstrap* lookup fails. Partial and requires maintenance —
there are hundreds of public DoH endpoints and more appear — but it covers the
handful that browsers use by default, which is most of the real-world bypass.

**3. Use the canary domain to stop browser auto-upgrade.** Firefox checks
`use-application-dns.net` before enabling DoH automatically; returning NXDOMAIN
for it disables that. Add it to a policy block-list. Note this is a *courtesy
mechanism* honoured by Firefox, not an enforcement control, and it does nothing
about a user who enables DoH deliberately.

**4. Manage the endpoints.** Group Policy, MDM, or configuration profiles can
disable DoH in Chrome, Edge and Firefox and pin the system resolver. On a
managed estate this is the durable answer.

**5. Detect the absence.** A device on the network that resolves *nothing*
through DNS Daddy while clearly being online is bypassing it. DNS Daddy does
not do this correlation today — it would need endpoint or flow data it does not
have — but the query log is the input to that hunt if you have the other half.

### The honest summary

On a **managed** network, blocking 53/853, managing browser policy, and
blocking known DoH endpoints gets you most of the way, and the remaining bypass
requires a user acting deliberately.

On an **unmanaged** network — BYOD, guests, a home network with a teenager —
you cannot prevent it, and any product claiming otherwise is either doing TLS
interception or overstating.

This is listed **out of scope** in [SECURITY.md](../../SECURITY.md): a device
resolving elsewhere is a property of DNS, not a vulnerability in DNS Daddy.

---

## Privacy: the other side

Encrypted DNS is usually discussed as an attacker's evasion route, which is
one-sided.

DoH exists because plaintext DNS leaks every site you visit to every network
you connect to, and that has been used for surveillance, injection, and
advertising by ISPs and public wifi operators alike. For a person on a hostile
network it is a real protection.

Running DNS Daddy takes a position in that debate, and it is worth being
explicit about which: **it moves the trust from a public resolver to you.** Your
users' lookups are visible to you, logged by you, and retained on your terms.
That is appropriate for a network you administer and where the users know. It
is worth thinking about before pointing it at people who have not been told.

[docs/privacy.md](../privacy.md) covers what is stored and how to store less.
`log.query_log: false` keeps the statistics and drops the per-query rows;
`log.log_client_ip: false` keeps the rows and drops the device attribution.

## Further reading

- [RFC 7858] — DNS over TLS
- [RFC 8484] — DNS over HTTPS
- [RFC 9250] — DNS over QUIC
- [RFC 8932] — Privacy considerations for DNS recursive operators
- [dnssec.md](dnssec.md) — the other half of the picture
- [../integrations.md](../integrations.md) — firewall configuration for
  pfSense, OPNsense, UniFi and FortiGate

[RFC 7858]: https://www.rfc-editor.org/rfc/rfc7858
[RFC 8484]: https://www.rfc-editor.org/rfc/rfc8484
[RFC 9250]: https://www.rfc-editor.org/rfc/rfc9250
[RFC 8932]: https://www.rfc-editor.org/rfc/rfc8932
