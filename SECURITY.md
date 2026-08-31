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
source address, resolved through the same trusted-proxy rules as everything
else — behind a reverse proxy every request has the same peer, so keying the
limiter on the raw connection address would have put the whole internet in one
bucket and let one attacker lock the operator out.

**Sessions are server-side and revocable.** The cookie is 256 bits from
`crypto/rand` and means nothing on its own; the server stores its SHA-256 with
an expiry, so a copy of the database is not a set of live sessions. This
matters for three things that a self-contained signed cookie cannot do:

* **Logout revokes.** The row is deleted, so a cookie captured beforehand stops
  working immediately rather than at its expiry.
* **Changing the password signs everything out**, every browser including the
  one making the change. An operator who changes the password because they
  think somebody has been in gets what they were asking for.
* **There is no signing key to lose.** Sessions were previously
  `<expiry>.<hmac(expiry)>`, which made `<data_dir>/session.key` a permanent
  forgery capability for anyone who read it. That file is now deleted on
  startup; nothing reads it.

  What this does *not* solve: an attacker who steals a live cookie is that
  session until it expires or is revoked. Nothing short of binding the session
  to something uncopyable changes that, and this is a self-hosted dashboard.

**The management interface binds loopback by default.** `http.listen` is
`127.0.0.1:8080`, and a wildcard (`:8080`, `0.0.0.0`, `[::]`) or a globally
routable address is refused unless `http.allow_public_bind` is also set. A
named private address such as `192.168.1.50:8080` needs no acknowledgement —
typing it is already a statement of intent, and it is how the LAN deployment is
configured.

This is a property of the program, not of the container. The image does set
`DNSDADDY_ALLOW_PUBLIC_BIND`, because inside a network namespace a wildcard
reaches nothing until Compose publishes the port, and Compose publishes it to
`127.0.0.1` — but running that image with `--network host` removes that
boundary and makes the wildcard real.

**The health endpoint answers in two tiers.** `/api/v1/health` is deliberately
unauthenticated, which in the HTTPS deployment makes it the one management path
the reverse proxy publishes to the internet. Every caller gets `{"status":"ok"}`
and nothing else — not the version, not the uptime, not the size of the threat
index, not whether a configuration reload has failed. An entitled caller gets
all of that: entitled means authenticated, or a peer address that is loopback,
which is how `dnsdaddy doctor` and the container's own health check read the
live index without a credential.

Entitlement is decided from the address that opened the socket and never from a
forwarding header, so `X-Forwarded-For: 127.0.0.1` buys nothing — including
from the reverse proxy itself, whose forwarded requests all originate on the
internet.

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

### The three deployment modes, and what each exposes

`./deploy/install-docker.sh` offers exactly three, and none of them publishes
the management interface in plaintext.

| | Management access | Listening publicly | DNS Daddy binds |
|---|---|---|---|
| **1. Home / LAN** | `http://<lan-ip>:8080` | the dashboard, on your LAN | the LAN address |
| **2. Public VPS — SSH tunnel** | `http://127.0.0.1:8080` through `ssh -L` | nothing | loopback |
| **3. Public VPS — HTTPS** | `https://<name-or-ip>` | Caddy, on 80 and 443 | loopback |

Mode 1 is for a machine with no public address. The installer refuses to
publish the dashboard on an address it can see is publicly routable, and warns
that a private address on the NIC is not evidence a host has no public one —
on AWS, GCP, Azure and Hetzner the public address is NATed onto a private NIC,
and that inference has caused a real exposure here before.

Modes 2 and 3 both keep DNS Daddy itself on `127.0.0.1:8080`. In mode 3 the
reverse proxy is the internet-facing component and the only thing listening on
a public interface; the application is unchanged between the two.

**Mode 3 fails closed.** If a publicly trusted certificate cannot be obtained,
the installer restores the previous Caddyfile — or removes the one it
generated — reverts the HTTPS settings in `.env`, and leaves the deployment in
mode 2's posture. It never falls back to plaintext on a public address, and it
never reports success on the strength of having run the commands: the check is
`curl` *without* `-k`, so a certificate this machine does not trust counts as a
failure.

That last point is not theoretical. Left to itself, Caddy issues a certificate
from its own internal CA for a name it considers unnameable — which would put a
certificate no browser trusts in front of the management interface and let the
installer call it done. The generated IP site pins the public ACME issuer
explicitly so that cannot happen quietly, and success requires a `curl` that
verifies against this machine's trust store.

**Raw-IP HTTPS needs Caddy 2.11 or newer.** 2.11 is the first release whose
bundled CertMagic knows that Let's Encrypt issues IP-address certificates;
before it, the request was refused locally and no order was ever sent. The
installer checks the version before writing anything and says how to get a
current Caddy rather than producing a parse error. Distribution packages are
usually far behind — Debian 13 ships **Caddy 2.6.2** — so the upstream
repository matters here, and the installer now reports which one it used.

**Firewall exposure**, for the operator to configure — the installer does not
open ports:

```
53/udp, 53/tcp    DNS, only where you intend to serve clients
80/tcp, 443/tcp   mode 3 only, for Caddy and the ACME challenge
8080/tcp          never publicly, in any mode
```

Cloud-provider firewalls are separate from `ufw` and cannot be seen from the
machine. Docker's port publishing bypasses `ufw` entirely, which is why the
bind address rather than a firewall rule is the control that matters.

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

## Known limitations

Stated here rather than left to be discovered. Each is a real property of the
current code, not a hypothetical.

**A stolen live session cookie is that session.** Logout and a password change
both revoke, and sessions expire after twelve hours, but nothing binds a
session to the browser holding it. If a cookie is captured — a shared machine,
a proxy log, a backup — it works until one of those three things happens.
Changing the admin password is the response, and it is now an effective one.

**Raw-IP HTTPS has never been observed issuing a real certificate here.** What
is now verified goes further than it did: against Let's Encrypt *staging*, with
Caddy 2.11.4 and CertMagic v0.25.3, an ACME **order for an IP identifier was
accepted** and both `tls-alpn-01` and `http-01` challenges were offered. The
order failed only at the callback — `urn:ietf:params:acme:error:connection`,
connection refused — because the challenge could not reach the address from the
internet. So the capability is real and the remaining unknown is narrow:
issuance itself, which needs ports 80 and 443 reachable at the address being
certified.

An earlier version of this paragraph rested on `ACMEIssuer.PreCheck` returning
"proceed", and a real attempt on a public VPS then failed. PreCheck was the
wrong layer to test — it is one gate of several — and the claim was replaced
rather than restated. Rows D4 and D5 of
[docs/deployment-matrix.md](docs/deployment-matrix.md), with
[docs/vps-validation.md](docs/vps-validation.md) as the procedure, are what
close the gap.

**The login rate limiter is in-process and in-memory.** It resets on restart,
and it counts nothing an attacker cannot cause it to forget by waiting fifteen
minutes. It raises the cost of online guessing; it is not a lockout, and the
admin password's entropy is what actually protects the account.

**There is no CSRF token.** State-changing cookie-authenticated requests are
protected by `SameSite=Lax` plus a server-side `Origin`/`Referer` check. That
combination is sound for a same-origin single-page dashboard and is what the
tests pin, but a synchroniser token would be the belt to that pair of braces.

**Sessions cannot be listed or revoked individually.** "Revoke everything" is a
password change. A per-session view — when it was created, when it was last
used, revoke this one — is data the table already holds and the UI does not yet
show.

**The installer has now run against a real Docker daemon, in containers rather
than VMs.** Clean Debian 13 and Ubuntu 24.04, real `dockerd` 29.3.1, real
Compose, real Caddy 2.11.4 — options 1 and 2, the HTTPS failure path, port-53
conflict detection, and the resulting sockets and Docker bindings inspected
directly. The shipped `Dockerfile` has since been built and run as well: the
image reaches its `HEALTHCHECK`'s healthy state, a network created through the
API survives `docker restart` in its named volume, and `/api/v1/health` over
the published port answers `{"status":"ok"}` and nothing more, because the peer
is the Docker bridge rather than loopback.
[docs/deployment-matrix.md](docs/deployment-matrix.md) records exactly what was
checked and how.

What that still does not cover: a hypervisor, a real NIC, a second physical
client on a LAN, and a machine with a public address. So ACME issuance has
never completed here, IPv6 was tested as classification logic rather than as a
live socket (this host has no IPv6 stack), and per-client attribution across a
real subnet is unverified.

**`Forwarded` (RFC 7239) is not parsed.** That is safe in this direction — an
unparsed header is an ignored one — and there is a test that fails if it ever
starts being honoured without the trusted-peer check being applied to it.

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
