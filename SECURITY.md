# Security

DNS Daddy sits in front of every name lookup on a network. A compromise here is
a compromise of everything downstream. We would rather hear about a problem than
not.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting: on this repository, go to
**Security → Report a vulnerability**.

Useful to include: what you found, how to reproduce it, the version
(`dnsdaddy -version`), and what an attacker gets out of it.

What to expect:

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix for a critical issue | as fast as we can, with a coordinated release |
| Credit | in the release notes, unless you would rather not be named |

This is a small project. We will tell you honestly if something will take a
while rather than leaving you wondering.

We do not run a paid bug bounty. We will not threaten you for reporting in good
faith.

## What this project is, before you rely on it

**DNS Daddy is an experimental, unaudited, AI-assisted personal project.** It
has had no independent adversarial security review. Automated scanning runs in
CI, and a clean scanner run is evidence of very little — tools find the bugs
they have rules for, and design flaws are not among them.

It sits in the resolution path of every lookup on a network, which is a
position that deserves more scrutiny than one person can give it. That is the
main reason it is public.

What that means practically:

- Treat "no known vulnerabilities" as "nobody qualified has looked hard",
  because that is what it is.
- The behavioural detectors are **experimental** and **alert-only**. They are
  not a control to depend on.
- [docs/capabilities.md](docs/capabilities.md) is the authoritative statement of
  what is implemented. If anything in this repository claims more than that
  page supports, that is a bug worth reporting.

If you have security review experience and are willing to spend an hour
attacking this, that is the most valuable thing anyone could contribute.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Anything older | No — upgrade before reporting |
| `main` | Yes, and reports against it are welcome |

Only the latest release gets fixes. This is a one-person project: maintaining
backports would mean fixing things more slowly, and there is no version of that
trade where the older branch wins.

Fixes ship as a new release. There is no long-term-support line, and promising
one would be a promise nobody could keep.

## In scope

- Remote code execution, memory corruption, or crashes triggered by a crafted
  DNS message, a DoH request, or a malicious feed file
- Authentication bypass on the management API or dashboard
- Cache poisoning, or answers being returned for the wrong question
- A client being attributed to the wrong network, and so getting the wrong policy
- Query-log data exposed to an unauthenticated caller
- Blocklist bypass: a listed domain resolving when policy says it should not
- Stored or reflected XSS in the dashboard
- Secrets written to logs, or to disk in recoverable form
- **Behavioural findings or query-log data reachable without authentication**
- **A crafted DNS name that causes unbounded memory or CPU use in the detection
  engine.** Its state is bounded deliberately; a way around that is a
  vulnerability, not a tuning issue
- **A detection finding that changes a DNS answer.** Behavioural detection is
  alert-only by design, and anything that makes it affect resolution is a bug
  of the most serious kind
- **The AD bit being set on a response to a client that did not request it**,
  which would assert an authenticity guarantee the client never asked us to
  check

## Out of scope

- **Browser DoH bypass.** A device can resolve directly over HTTPS and skip us.
  This is a property of DNS, documented in
  [integrations.md](docs/integrations.md#stopping-doh-bypass), not a bug.
- **Running an open resolver.** If you expose port 53 to the internet without a
  firewall you will be abused for amplification. Documented in
  [deploy.md](docs/deploy.md#4-never-run-an-open-resolver).
- **Missing DNSSEC validation.** DNS Daddy forwards rather than validating, and
  records the upstream's verdict. This is documented at length in
  [docs/dns-security/dnssec.md](docs/dns-security/dnssec.md), including the
  point that a lying upstream will set the AD bit happily. Local validation is
  a feature request, not a vulnerability.
- **False positives from behavioural detectors.** Every one is marked
  *experimental* and none of them block anything. A detector firing on your
  mail gateway is expected, wanted as a report, and is
  [its own issue template](https://github.com/jameshoulder/dnsdaddy/issues/new?template=false-positive.yml)
  rather than a security issue.
- **Evading a behavioural detector.** A slow tunnel, a word-list DGA, or a
  tunnel through an excluded domain will not be detected.
  [docs/capabilities.md](docs/capabilities.md) and each detector's own
  documentation say what they miss. Detection gaps that are documented are
  limitations; undocumented ones are worth telling us about.
- **False positives and negatives in third-party feeds.** Report those upstream;
  see [threat-intel.md](docs/threat-intel.md).
- **Someone with the admin password doing admin things.**
- Missing security headers with no demonstrated impact, or scanner output
  without a working proof of concept.

## Threat model

A full threat model — assets, trust boundaries, actors, twenty threats, and the
**residual risk left after each mitigation** — is in
[docs/threat-model.md](docs/threat-model.md). In summary:

**Assumed trusted:** the host, the operator, and anyone holding the admin
password or an API token.

**Assumed hostile:** every DNS query, every DoH request, every byte of every
downloaded feed, and any device on the network the resolver serves.

That second list is why parsing is defensive: a malformed feed line is counted
and skipped rather than aborting a load, DoH bodies are size-capped before
parsing, and query names are normalised before they reach any lookup.

## Design decisions that carry security weight

**Upstream is encrypted by default.** Ships with DNS-over-TLS to Quad9 and
Cloudflare, with certificate names verified. A `tls://` upstream with no
`#servername` derives one from the host rather than silently skipping
verification. The dashboard flags plaintext upstreams in amber, and the resolver
logs a warning at startup.

**The dashboard has a strict CSP** with no `unsafe-inline` for script or style.
Dynamic values are applied through the CSSOM, not `style=` attributes. All
interpolation in the dashboard goes through an escaping template — domain names
in the query log are attacker-controlled strings.

**API tokens are stored as SHA-256 hashes** and compared in constant time. The
plaintext secret is returned exactly once, at creation. Every token carries the
`dnsd_` prefix so a leaked one is recognisable in a log or a secret scanner.

**The admin password is bcrypt-hashed.** Login attempts are rate limited per
source address.

**No forwarding header is trusted by default.** `X-Forwarded-For`,
`X-Real-IP`, and `X-Forwarded-Proto` are honoured only from a peer listed in
`http.trusted_proxy_cidrs`, because trusting them on a directly exposed port
would let any client claim any source address — and with it, any network's
policy. When a trusted proxy is configured, `X-Forwarded-For` is walked
right-to-left past our own hops: a client can prepend arbitrary values, so the
left-most entry is attacker-controlled and the right-most untrusted one is the
real client.

**It refuses to start as an open resolver.** `dns.allowed_client_cidrs` ships
covering loopback, RFC 1918, CGNAT, link-local, and IPv6 ULA. Emptying it while
bound to a non-loopback address is a startup error unless you set
`dns.allow_public_resolver: true`. Queries from outside the ACL are REFUSED
before any upstream work and deliberately write no query-log row, so the ACL
cannot be turned into a way to fill the disk. This is redundant with your
firewall on purpose: an open resolver is found and conscripted into
amplification attacks within days, and "the operator was told to firewall it"
is not a control.

**ANY queries get a minimal RFC 8482 response** rather than being forwarded.
ANY replies are large, which is precisely the leverage a DNS amplification
attack needs.

**Cross-origin state changes are rejected.** A request authenticated by session
cookie that changes state must carry a same-origin `Origin` or `Referer`.
Bearer tokens are exempt because a browser never attaches them cross-site, so
CSRF does not apply to them.

**The session cookie's `Secure` flag is `http.secure_cookies`** — `auto`
(default), `always`, or `never`. `auto` sets it whenever the request actually
arrived over TLS. An unconditional `Secure` flag would make login impossible on
the plain-HTTP LAN deployments this software exists to serve: the browser
accepts the cookie and then never sends it back. Set `always` once TLS is in
front.

### Management access policy

These three rules are the supported deployment envelope for the dashboard and
management API. Everything above about cookies and forwarded headers assumes
them.

1. **Internet-facing management access requires HTTPS.** If the dashboard is
   reachable from the public internet, terminate TLS in front of it and set
   `http.secure_cookies: always`. Over plain HTTP the session cookie — and the
   password used to obtain it — travel in clear text to every device on the
   path.

2. **Forwarded protocol headers are only trusted from a configured proxy.**
   `X-Forwarded-Proto` is believed only when the peer appears in
   `http.trusted_proxy_cidrs`, and that setting is only correct when the HTTP
   listener cannot be reached directly. Bind it to loopback, or firewall it, so
   the proxy is the only path in. If a client can reach the listener directly
   while a proxy CIDR is trusted, it can assert its own protocol and source
   address.

3. **Plain HTTP is acceptable only on loopback or a private management
   network** you explicitly trust — a home LAN, a management VLAN, or a
   WireGuard/Tailscale interface. This is a supported mode, not an oversight:
   it is why `secure_cookies` defaults to `auto` rather than `true`. It is not
   acceptable on any interface reachable from the internet.

**The bare `/dns-query` DoH path requires a token** unless you set
`http.allow_untokenized_doh`. Behind a public reverse proxy it would otherwise
be an open DoH resolver for anyone who finds the path.

**Generated Markdown reports escape every database-controlled value.** Feed
names, network names, locations, policy names, category labels, and blocked
domains all pass through a table-cell escape that neutralises pipes, newlines,
and raw HTML delimiters. Reports are read by people outside the security team,
in applications that render HTML — a feed name is not a safe string.

**An unknown DoH token is rejected**, not silently fallen back to IP-based
attribution. Falling back would quietly apply the wrong policy to a roaming
device, which is worse than an error.

**`file://` blocklist feeds are disabled by default** and, when enabled, are
confined to `feeds.local_feed_dir` — checked both lexically and after symlink
resolution. Feed URLs arrive over the management API, so an unconfined
`file://` feed would be an arbitrary file read for anyone holding a session or
an API token.

**Query names are length-bounded** before the policy engine sees them. The
suffix walk is linear in name length, which is the cheap half of an asymmetric
attack.

**Blocklist matching is exact**, not hash-based. A hash collision would silently
block a legitimate domain; the memory saved is not worth that.

**The systemd unit is confined**: no new privileges, read-only system, a
seccomp filter, `CAP_NET_BIND_SERVICE` and nothing else, and memory limits. The
container runs as an unprivileged user and cannot bind port 53 at all — Compose
publishes the host port instead.

## Hardening checklist

- [ ] Port 53 firewalled to networks you control ([deploy.md](docs/deploy.md#4-never-run-an-open-resolver))
- [ ] `dns.allowed_client_cidrs` narrowed to the networks you actually serve
- [ ] `dns.allow_public_resolver` left off unless you really mean it
- [ ] Dashboard behind TLS, or bound to loopback
- [ ] `http.secure_cookies: always` once TLS is in front
- [ ] Admin password changed from the generated one, and `initial-password.txt` deleted
- [ ] `http.trusted_proxy_cidrs` set to your proxy only, and left empty otherwise
- [ ] `http.allow_untokenized_doh` left off on anything internet-facing
- [ ] `feeds.local_feed_dir` left empty unless you use `file://` feeds
- [ ] Upstreams using `tls://` or `https://`
- [ ] Query-log retention set to what you can justify ([privacy.md](docs/privacy.md))
- [ ] `/api/v1/health` monitored, alerting when `status` is `degraded`
- [ ] Backups running, and restored at least once

## Verifying a release

Release archives are published with `checksums.txt`; the installer verifies
against it automatically. Manually:

```bash
sha256sum -c checksums.txt --ignore-missing
```

To trust nothing at all, build from source — no cgo, no npm, and the dashboard
is embedded from files in this repository:

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy && make build
```
