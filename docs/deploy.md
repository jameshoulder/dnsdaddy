# Deploying DNS Daddy

The reference deployment is a 1 GB / 1 vCPU VPS — a $5 Linode Nanode, a Hetzner
CX22, a DigitalOcean basic droplet. This guide walks that through end to end.

Budget an hour. Most of it is waiting for feeds to download and letting a test
device run for a while before you touch anyone else's DNS.

---

## 1. Provision

Any current Debian or Ubuntu LTS is fine. You need:

- 1 GB RAM (512 MB works with a smaller blocklist; 1 GB is comfortable)
- 25 GB disk (query logs are the only thing that grows)
- A static IP

Pick a region close to your users. DNS latency is felt directly — every page
load starts with a lookup — so a London box for a UK office beats a cheaper one
in Virginia.

## 2. Lock down the box first

Do this before DNS Daddy is listening, not after.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ufw fail2ban

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
```

## 3. Install

```bash
curl -fsSL https://raw.githubusercontent.com/jameshoulder/dnsdaddy/main/deploy/install.sh | sudo bash
```

Or with Docker, which is the supported path and does the rest of this page's
first-run steps for you:

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
./deploy/install-docker.sh
```

It creates `.env`, checks the ports, starts the stack, waits for readiness,
runs `dnsdaddy doctor` and prints your DNS address, dashboard URL and admin
password. `--dry-run` shows what it would do; `--upgrade` and `--uninstall` are
covered in [Upgrades](#11-upgrades) and [Uninstalling](#12-uninstalling).

By hand, if you would rather:

```bash
docker compose up -d
docker compose exec dnsdaddy cat /var/lib/dnsdaddy/initial-password.txt
```

The generated password is written to that file with mode `0600` on first run.
It is deliberately **not** written to the log: a credential in
`docker compose logs` outlives the session and reaches every log shipper
pointed at the container.

Check it came up:

```bash
curl -s http://127.0.0.1:8080/api/v1/health
# {"status":"degraded",...,"blocklistSize":0}
```

`degraded` with `blocklistSize: 0` is expected on a brand-new install — the
resolver is answering but has no blocklist yet. That is exactly what the next
step fixes, and why the health endpoint says so rather than reporting a
cheerful green.

## 4. Never run an open resolver

This is the one mistake that turns your server into somebody else's problem.
An open recursive resolver on the public internet will be found within days and
used to amplify DDoS attacks — you will get abuse mail and your provider may
null-route you.

**Only allow port 53 from addresses you control.**

```bash
# Replace with your office's public IP and any site that will use this.
sudo ufw allow from 203.0.113.42 to any port 53 proto udp
sudo ufw allow from 203.0.113.42 to any port 53 proto tcp

# Same again for each additional site.
sudo ufw allow from 198.51.100.10 to any port 53 proto udp
sudo ufw allow from 198.51.100.10 to any port 53 proto tcp
```

Verify from somewhere *outside* your allowed ranges — it must time out:

```bash
dig @<your-server> example.com +timeout=3
```

If that returns an answer, stop and fix the firewall.

**Roaming devices and dynamic IPs.** Do not open port 53 to the world for
them. Use the per-network DNS-over-HTTPS URL instead (step 6): it works from any
address, and the token in the path is the credential.

### Who may use the resolver

Independently of your firewall, DNS Daddy keeps its own list of source
addresses it will answer, and refuses everything else before doing any work.
That is deliberately redundant with the firewall: an open resolver gets found
and abused within days, and "the operator was told to firewall it" is not a
control.

The **effective ACL** is built from two sources, combined by union:

| Source | Where | Changing it |
|---|---|---|
| **Bootstrap** | `dns.allowed_client_cidrs`, or `DNSDADDY_ALLOWED_CLIENT_CIDRS` | needs a restart |
| **Dashboard** | **Networks →** *Allow this network to use DNS Daddy* | on the next query, no restart |

A permission grants; nothing else revokes it. Both sources are listed
separately by `dnsdaddy doctor`, at `GET /api/v1/diagnostics`, and on the
Networks page, so you can always see which one is responsible for a given
range.

**That decides which source to put a range in.** A range in the bootstrap list
is permitted whatever the dashboard says about it: unticking *Allow this
network to use DNS Daddy*, disabling the network, or deleting it outright
cannot withdraw a permission that configuration is also granting. So put a
range in `.env` when you want it fixed by deployment — Ansible, a Compose file,
an image build — and add it as a Network when you want to be able to revoke it
from the dashboard. Putting it in both leaves you with a revocation control
that appears to work and does not.

A dashboard change is stored and then applied to the running resolver, and
those are two steps. Normally the second follows immediately and the change is
in force on the next query. If it fails — a transient database error between
the two — the write is kept, the response says DNS Daddy could not confirm what
is being enforced, and `doctor` and the diagnostics keep saying so until a
reload succeeds. The Networks page reports the ACL as it stands rather than as
it was asked to stand, so a permission stored but not applied shows as *Allowed,
not in force* rather than as allowed.

Four properties worth knowing before you rely on it:

**An empty bootstrap ACL stays unrestricted.** An empty
`dns.allowed_client_cidrs` means "refuse nothing", which DNS Daddy only starts
with when the listeners are loopback-only or you set
`dns.allow_public_resolver`. Adding the first dashboard permission does *not*
narrow that to "only this range" — a click in the dashboard must not change who
your running resolver serves as a side effect. Permissions are recorded and
take effect the moment an ACL is configured.

**There are no deny rules.** A narrower network without permission does not
carve a hole in a broader permitted range. If `10.0.0.0/8` is permitted, a
`10.50.0.0/16` network with the box unticked still resolves — because something
wider already permits it. Diagnostics report exactly this case rather than
leaving you to find it; to stop those clients, narrow the wider range.

**Permitting the catch-all grants nothing.** A network with no ranges has no
addresses of its own, so ticking *Allow this network to use DNS Daddy* on it
adds nothing to the ACL — the permission is stored and contributes no range.
Whether a client the catch-all matches is served depends entirely on that
client's own address, which is why the Networks page badges it *Depends on the
client* rather than allowed or refused. To permit a client, permit a network
that actually lists its address.

**A public range needs an explicit acknowledgement, and `0.0.0.0/0` is
refused outright.** Permitting a publicly routable range means DNS Daddy will
accept requests from the internet, so the dashboard asks you to confirm it and
reminds you that your provider's firewall is yours to configure — DNS Daddy
cannot see it and does not change it. A default route is not offered at any
level of confirmation: `dns.allow_public_resolver` is the setting for that, it
lives in configuration, and changing it is a deliberate act with a restart
attached.

**Public exposure is reported from either source.** If you permit a publicly
routable range — in the dashboard *or* through
`DNSDADDY_ALLOWED_CLIENT_CIDRS` — diagnostics warn about it every time they
run, naming the range and which of the two settings is responsible. The warning
never resolves itself and never claims a firewall state: DNS Daddy cannot see
your provider's security group and does not change it.

**It is about source addresses, not about credentials.** A DNS-over-HTTPS or
DNS-over-TLS client presenting a network's token is identified by that token
rather than by where it connects from — which is the entire point of a roaming
profile, and why the token in the URL is a credential. Such a client keeps
resolving whether or not the network's addresses are permitted. To cut one off,
disable the network or rotate its token.

**Upgrading from an earlier version?** Nothing changes. Every network that
predates this feature starts unpermitted, so your bootstrap ACL alone keeps
admitting exactly who it admitted before. DoH and DoT tokens are unaffected for
the same reason: they never depended on the client ACL.

## 5. Put TLS in front of the dashboard

The dashboard authenticates with a password. Over plain HTTP on the public
internet, that password crosses the network in the clear. On a LAN-only
deployment you can accept that; on anything internet-facing, do not.

### The three access modes

`./deploy/install-docker.sh` asks which of these you want, and none of them
publishes the management interface over plaintext HTTP.

| Mode | Flag | Dashboard reached by | Backend binds | Needs |
|---|---|---|---|---|
| LAN / homelab | `--lan` | `http://<lan-ip>:8080` | the named LAN address | a private address |
| VPS, SSH tunnel | `--vps` (default) | `http://127.0.0.1:8080` through SSH | `127.0.0.1` | nothing |
| VPS, HTTPS, hostname | `--https` | `https://<hostname>` | `127.0.0.1` | DNS pointing here, 80+443 open |
| VPS, HTTPS, public IP | `--https` | `https://<public-ip>` | `127.0.0.1` | Caddy ≥ 2.11, 80+443 open |

Mode 3 automates what the rest of this section describes by hand. It writes
`/etc/caddy/Caddyfile` (backing up any existing one), validates it, reloads
Caddy, and then requires a **publicly trusted** certificate before reporting
success — the check is `curl` without `-k`, so a certificate this machine does
not trust counts as a failure. It sets `DNSDADDY_BASE_URL`, forces
`DNSDADDY_SECURE_COOKIES=always` and narrows `DNSDADDY_TRUSTED_PROXY_CIDRS` to
the Docker bridge subnet. It does **not** set `DNSDADDY_DASHBOARD_BIND`, so the
container stays on loopback and Caddy is the only process listening publicly.

If it cannot get a certificate it puts all of that back — the previous
Caddyfile, and those three `.env` keys — and leaves you in mode 2's posture,
reachable over the SSH tunnel. Reverting `DNSDADDY_SECURE_COOKIES` matters:
left set, the browser accepts the session cookie over the tunnel and never
sends it back, and login fails with nothing to explain why.

Non-interactively:

```bash
# A hostname whose A/AAAA record already points at this machine.
DNSDADDY_HTTPS_HOSTNAME=dns.example.com ./deploy/install-docker.sh --https --yes

# Or this machine's own public address, detected from its interfaces.
DNSDADDY_HTTPS_HOSTNAME=ip ./deploy/install-docker.sh --https --yes
```

#### Caddy's access log

The generated Caddyfile sends Caddy's access log to **stderr**, which systemd
collects into the journal:

```bash
journalctl -u caddy -f
```

It does not write to `/var/log/caddy/`. That directory has to exist and be
writable by the Caddy *service account* — not by root — and on a real Debian 13
VPS it was not, so Caddy exited at start-up with `opening log writer ...
permission denied`. An access log is not worth a failure mode that stops the
management interface coming up.

#### HTTPS on a bare IP address

Supported, with one requirement worth knowing about.

Let's Encrypt has issued certificates for IP addresses since January 2026, but
**only** through the `shortlived` ACME profile — a 160-hour certificate, renewed
automatically. Caddy learned that in **2.11**: earlier releases refuse an IP
subject locally and never send the order. The installer checks the version
before writing anything and tells you how to get a current Caddy rather than
producing a parse error.

Distribution packages are usually well behind — **Debian 13 ships Caddy
2.6.2** — so install from
[Caddy's own repository](https://caddyserver.com/docs/install#debian-ubuntu-raspbian).
The installer does this for you and reports which repository it used; if the
upstream one is unreachable it says so rather than quietly accepting whatever
`apt` offers.

A hostname needs none of this and works on much older Caddy. Use an IP when you
have no name for the machine; use a name when you do.

**This has been done for real, once.** On Debian 13 (trixie) with Docker 26.1.5
and Caddy 2.11.4, Let's Encrypt issued a publicly trusted certificate directly
for the VPS's IPv4 address under the `shortlived` profile. The certificate
verified against the system CA store with ordinary `curl`, HSTS was enabled,
plain HTTP redirected with a 308, Caddy reached the backend on
`127.0.0.1:8080`, and host port 8080 was confirmed unreachable from outside.

That is one host on one distribution behind one provider's firewall. It is not
a claim that every distribution or provider behaves the same way.

**If you are developing or testing the installer, do not point it at production
Let's Encrypt.** Repeated attempts burn the duplicate-certificate and
failed-authorisation limits for that identifier, and those reset in days, not
minutes. Use the staging endpoint. The installer's own test suite contacts no
ACME server at all.

### Known OS-specific behaviour

Observed on clean Debian 13 and Ubuntu 24.04 with a real Docker daemon, not
inferred.

**Ubuntu: systemd-resolved holds port 53.** Almost every Ubuntu install binds
`127.0.0.53:53`. The installer detects it, names it, and refuses to change it
for you — altering how a remote machine resolves names is how people lose
remote machines. Do it first:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/dnsdaddy.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved

ss -lnup 'sport = :53'      # should now be empty
getent hosts deb.debian.org # this machine can still resolve
```

Debian's minimal images generally do not run it, so port 53 is usually free.

**Debian 13: `apt-get install caddy` gets Caddy 2.6.2.** That is a 2022 release.
It is fine as a TLS-terminating proxy for a hostname, and it cannot do
IP-address certificates at all. Install from Caddy's own repository, which the
installer does — and which it now reports on, because a silent fallback to the
distribution package is how a four-year-old proxy ends up in front of a
management interface.

**Both: Docker's port publishing bypasses `ufw`.** A published port is reachable
whatever your firewall rules say, which is why the *bind address* rather than a
firewall rule is the control that matters here. Your cloud provider's firewall
is separate again and cannot be seen from the machine; the installer says so
rather than implying it has checked.

### Four things that are not the same thing

Conflating these is what makes a healthy install look broken:

| | Controlled by |
|---|---|
| **DNS resolver reachability** | port 53, your firewall and your provider's |
| **Which clients may resolve** | the client ACL — Networks page, or `DNSDADDY_ALLOWED_CLIENT_CIDRS` |
| **Dashboard reachability** | `DNSDADDY_DASHBOARD_BIND`, and any reverse proxy |
| **TLS** | Caddy or whatever terminates it |

Making the dashboard reachable never changes who may resolve. Nothing in the
install modes above can turn DNS Daddy into an open resolver.

### If something already serves ports 80 or 443

Many VPS images ship Apache or Nginx. The installer detects what holds each port
and reports it, and **does not** stop, disable, reconfigure or uninstall it, or
take the port.

In modes 1 and 2 that is only a reporting matter: DNS Daddy was never published
on port 80, so `http://<vps-ip>` reaching Apache is expected. The installer says
so explicitly, because the silence is what previously made this look like a
failed install.

In mode 3 it is a conflict, and TLS setup stands down with the service named.
The resolver still installs and runs. To proceed, either free the ports, or
point your existing web server at `127.0.0.1:8080` yourself — the same
`reverse_proxy` target Caddy would use.

### Doing it by hand

Caddy is two lines and handles certificates itself:

```bash
sudo apt install -y caddy
```

`/etc/caddy/Caddyfile`:

```caddy
dns.example.co.uk {
	reverse_proxy 127.0.0.1:8080
}
```

```bash
sudo systemctl reload caddy
sudo ufw allow 80,443/tcp
```

Then tell DNS Daddy it is behind a proxy, so the DoH URLs it displays are right
and client attribution uses the forwarded address:

```yaml
http:
  listen: "127.0.0.1:8080"
  base_url: "https://dns.example.co.uk"
  trusted_proxy_cidrs: ["127.0.0.1/32"]
  secure_cookies: always
```

> `trusted_proxy_cidrs` lists the peers whose `X-Forwarded-For`,
> `X-Real-IP`, and `X-Forwarded-Proto` headers DNS Daddy believes. List your
> proxy and nothing else. A client can prepend anything it likes to
> `X-Forwarded-For`, so trusting the header from an untrusted peer lets any
> caller claim any source address — and with it, any network's policy.
>
> Set it to the address the proxy connects *from*, which for a proxy on the
> same host is `127.0.0.1/32`, not the address it listens on.

> `secure_cookies: always` is correct once TLS is in front: the session cookie
> then never travels over plain HTTP. The default is `auto`, which sets the
> flag whenever the request actually arrived over TLS — that is what keeps
> plain-HTTP LAN deployments able to log in at all.

**Management access rules.** Three things must hold, and the second is the one
people get wrong:

1. Internet-facing management access requires HTTPS. Terminate TLS in front and
   set `secure_cookies: always`.
2. `trusted_proxy_cidrs` is only safe when the HTTP listener cannot be reached
   directly — hence `listen: "127.0.0.1:8080"` above. If a client can reach the
   listener while a proxy CIDR is trusted, it can assert its own protocol and
   source address and pick up another network's policy. Verify with the `curl`
   check below.
3. Plain HTTP is acceptable only on loopback or a private management network
   you explicitly trust (home LAN, management VLAN, WireGuard/Tailscale). That
   is a supported mode — it is why `secure_cookies` defaults to `auto` — but
   never on an interface reachable from the internet.

Behind a public proxy, also decide about DNS-over-HTTPS. The bare `/dns-query`
path has no client authentication, so it is refused by default:

```yaml
http:
  # Leave this off unless you intend to run a DoH resolver open to anyone who
  # finds the path. Per-network token URLs (/dns-query/<token>, shown on the
  # Setup page) keep working either way and are what clients should use.
  allow_untokenized_doh: false
```

Restart, and confirm the API port is no longer directly reachable:

```bash
sudo systemctl restart dnsdaddy
curl -m 3 http://<public-ip>:8080/     # must fail
```

## 6. Configure

Sign in, change the admin password under **Settings**, then delete the
first-run file:

```bash
sudo rm /var/lib/dnsdaddy/initial-password.txt
```

**Threat feeds → Refresh now.** This downloads several hundred thousand domains
and takes a minute or two on a single vCPU. Watch it land:

```bash
watch -n5 'curl -s localhost:8080/api/v1/health'
```

**Networks.** Add one per site or VLAN, with the public IP ranges its queries
arrive from:

| Network | Client ranges | Policy |
|---|---|---|
| HQ — London | `203.0.113.42/32` | Standard business |
| Warehouse | `198.51.100.10/32` | Standard business |
| Production floor | `198.51.100.11/32` | Strict |

The seeded **Default** network has no ranges, which makes it the catch-all for
anything unmatched. Keep it. Note that it decides *policy* for those clients
and nothing about whether they may resolve: permitting it grants no range, so
its access column reads *Depends on the client*.

Most specific prefix wins, so a `/32` exception inside a `/24` behaves the way
you would expect.

**Setup page.** This shows the exact addresses to paste into your firewall,
plus a per-network DoH URL for roaming devices.

## 7. Roll out — carefully

Do not change your DHCP scope yet.

1. Point **one** machine at the resolver manually.
2. Use it normally for a few hours. Watch the **Query log**.
3. Allow-list anything wrongly blocked — it applies on the next query.
4. Move a low-risk VLAN (guest Wi-Fi) and leave it a day.
5. Then change DHCP for everyone.
6. Finally, block outbound port 53 to everything *except* DNS Daddy, so devices
   with hard-coded resolvers cannot route around you:

   ```
   # On your edge firewall
   allow  LAN → <dnsdaddy-ip>  port 53
   deny   LAN → any            port 53
   ```

Per-platform instructions: [integrations.md](integrations.md).

## 8. Redundancy

One server is a single point of failure for every lookup on your network. Two
options, in increasing order of effort:

**Give clients a second resolver.** Most DHCP scopes take two DNS servers. Set
DNS Daddy first and a public resolver second — you lose filtering when DNS
Daddy is down, but nobody loses the internet. This is the pragmatic choice for
most SMEs, and it is an honest trade: availability over enforcement.

**Run two DNS Daddy instances.** Two Nanodes in different regions, both in your
DHCP scope. They do not share state — configure both, and treat the query logs
as two halves of the picture. Cheap and effective; ~$10/month total.

If filtering is a compliance control you must not lose, use the second option.
If it is a security improvement you would rather not trade uptime for, use the
first.

## 8a. Surviving reboots, crashes and updates

A DNS resolver that needs somebody to SSH in and run `docker compose up` is not
a production service. Four things must all be true, and three of them are not
the default.

**1. Docker must start at boot.** Nothing else matters if the daemon is not
running — `restart:` policies are enforced *by* Docker, so they cannot bring
anything back on their own.

```bash
sudo systemctl enable docker
systemctl is-enabled docker      # must print: enabled
```

**2. The restart policy must be `always`, not `unless-stopped`.** They differ in
exactly one case, and it is the case that hurts: `unless-stopped` remembers a
manual `docker stop` across a reboot. Stop the container once during
maintenance, reboot a month later, and DNS never comes back — silently. The
shipped `docker-compose.yml` uses `always`.

```bash
docker inspect dnsdaddy --format '{{.HostConfig.RestartPolicy.Name}}'   # always
```

**3. Install the Compose systemd unit.** Docker's policy restores the container
it already knows about; the unit re-applies `docker-compose.yml` at boot, fails
loudly if the stack cannot come up, and gives you one place to stop everything.

```bash
sudo cp deploy/dnsdaddy-compose.service /etc/systemd/system/
sudo $EDITOR /etc/systemd/system/dnsdaddy-compose.service   # set WorkingDirectory
sudo systemctl daemon-reload
sudo systemctl enable --now dnsdaddy-compose
```

It is `Type=oneshot` with `RemainAfterExit=yes`, so systemd brings the stack up
and then steps back — Docker keeps ownership of the container lifecycle. The two
never fight over restarts.

**4. Only one deployment may be active.** The Docker stack and the native
`dnsdaddy.service` both bind port 53 and port 8080. Running both means whichever
starts second dies with "address already in use", and which one wins varies by
boot. Pick one:

```bash
# Using Docker (recommended, and what the README documents)
sudo systemctl disable --now dnsdaddy

# Using the native binary instead
sudo systemctl disable --now dnsdaddy-compose
cd /opt/dnsdaddy && docker compose down
```

The unit declares `Conflicts=dnsdaddy.service`, so systemd refuses to run both
at once — but only for services it starts.

Verify the whole thing without rebooting:

```bash
docker restart dnsdaddy && sleep 10 && ./deploy/healthcheck.sh   # crash recovery
sudo systemctl restart docker && sleep 20 && ./deploy/healthcheck.sh   # daemon restart
```

## 9. Monitoring

`/api/v1/health` needs no authentication and is safe to point an external
monitor at:

```json
{"status": "ok", "version": "v1.0.0", "uptimeSeconds": 84210, "blocklistSize": 412887}
```

`status` is `degraded` when no blocklist is loaded — the resolver answers but
filters nothing. Alert on that, not just on the process being up.

**HTTP 200 is not proof the service is working.** The dashboard can be perfectly
healthy while DNS answers `REFUSED` to every real client, because the client ACL
is enforced on the DNS path and has nothing to do with the API. Check all four
layers together:

```bash
./deploy/healthcheck.sh
```

It verifies the container is running and not crash-looping, that the API reports
`status=ok` with a non-empty blocklist, that a real DNS query is answered (and
tells you specifically if the answer is `REFUSED`), and that the public HTTPS
dashboard responds. Exit codes: `0` healthy, `1` degraded, `2` down.

Run it from cron and be told only when something breaks:

```cron
*/5 * * * * DNSDADDY_PUBLIC_URL=https://dns.example.co.uk /opt/dnsdaddy/deploy/healthcheck.sh --quiet
```

When something is already wrong, collect everything at once:

```bash
sudo ./deploy/diagnose.sh > diag.txt 2>&1
```

Prometheus metrics at `/metrics` (authenticated). The ones worth alerting on:

| Metric | Why |
|---|---|
| `dnsdaddy_upstream_failures_total` | Rising means every upstream is failing — resolution is broken. |
| `dnsdaddy_blocklist_domains` | A sudden drop means a feed refresh went wrong. |
| `dnsdaddy_querylog_dropped_total` | Non-zero means logging cannot keep up with query volume. |
| `dnsdaddy_memory_bytes` | Should be flat. Growth means something is wrong. |

## 10. Backups

Everything lives in the data directory. The database is the only thing you
cannot regenerate — feed caches re-download, and sessions live in the database
itself, so restoring a backup restores whatever sessions were live when it was
taken (revoke them with a password change if that matters).

```bash
sudo systemctl stop dnsdaddy
sudo tar -czf /root/dnsdaddy-$(date +%F).tar.gz -C /var/lib dnsdaddy
sudo systemctl start dnsdaddy
```

For a hot backup without stopping the service, use SQLite's own online backup —
copying the file while it is being written can capture a torn WAL:

```bash
sudo -u dnsdaddy sqlite3 /var/lib/dnsdaddy/dnsdaddy.db \
  ".backup '/root/dnsdaddy-$(date +%F).db'"
```

The query log dominates the size. To back up configuration only, take the
backup and delete the bulk tables from the copy:

```bash
sqlite3 /root/dnsdaddy-backup.db \
  "DELETE FROM query_log; DELETE FROM stats_hourly; VACUUM;"
```

## 11. Upgrades

### Breaking changes in the hardening release

Two changes will stop a working deployment if you upgrade without acting on
them. Both are deliberate; neither announces itself clearly at runtime.

**1. `trusted_proxy` no longer exists.** If you have a `config.yaml` containing
it, the service refuses to start — unknown keys are rejected rather than
silently ignored:

```
dnsdaddy: parse config.yaml: yaml: unmarshal errors:
  line N: field trusted_proxy not found in type config.HTTP
```

Replace it with `trusted_proxy_cidrs`. Under Docker, the equivalent env var
`DNSDADDY_TRUSTED_PROXY` is simply **not read** — it fails quietly instead, so
proxy handling you believed was configured is not. Use
`DNSDADDY_TRUSTED_PROXY_CIDRS`.

**2. `allowed_client_cidrs` now defaults to loopback and the private ranges.**
On a VPS this is the one that bites: your clients arrive from public addresses,
so every real query gets `REFUSED` while `/api/v1/health` still returns
`"status":"ok"`. DNS looks dead; the dashboard looks fine.

```yaml
dns:
  allowed_client_cidrs:
    - "127.0.0.0/8"
    - "172.16.0.0/12"      # Docker bridge, if running in Docker
    - "203.0.113.42/32"    # your sites — the same IPs as your ufw rules
```

Under Docker you can set `DNSDADDY_ALLOWED_CLIENT_CIDRS` in `.env`, or — from
v0.3.0 — simply tick **Allow this network to use DNS Daddy** on the network in
the dashboard, which needs no restart. Confirm either way with
`./deploy/healthcheck.sh` or `dnsdaddy doctor`, both of which name this failure
explicitly.

### Performing the upgrade

Docker:

```bash
cd /opt/dnsdaddy
docker compose exec dnsdaddy sh -c 'cd /var/lib/dnsdaddy && tar cz .' > ~/dnsdaddy-backup-$(date +%F).tgz
git pull
./deploy/install-docker.sh --upgrade
```

`--upgrade` keeps the data volume and your `.env`, rebuilds, waits for the
service to answer, runs `dnsdaddy doctor`, and stops with the recovery command
if it does not come up healthy. It reconciles only the keys it owns: a
`DNSDADDY_DASHBOARD_BIND` you set by hand is reported and left alone, while one
an older version of the installer generated on a public address is commented
out, because that was never a choice you made.

By hand, if you prefer:

```bash
$EDITOR .env                      # apply any breaking changes above
docker compose up -d --build
./deploy/healthcheck.sh
```

Never use `docker compose down -v` — `-v` deletes the `dnsdaddy-data` volume
holding the database and cached feeds.

systemd — re-running the installer upgrades the binary and leaves your config
and database alone:

```bash
curl -fsSL https://raw.githubusercontent.com/jameshoulder/dnsdaddy/main/deploy/install.sh | sudo bash
```

The schema is applied idempotently at startup and built-in feed metadata is
refreshed, so an upgrade can correct a feed URL that has moved. Your
enabled/disabled choices are preserved.

Take a backup first anyway.

## 12. Uninstalling

Two different operations. Be deliberate about which one you are performing —
the data volume holds your configuration, your policies, your query history and
your findings, and nothing warns you twice.

### Keep the data

Stops DNS Daddy and leaves everything recoverable. Bringing it back is
`docker compose up -d` or `systemctl start dnsdaddy`.

```bash
# Docker
./deploy/install-docker.sh --uninstall
# or, equivalently:
docker compose down                 # NOT -v; that deletes the volume
# The named volume dnsdaddy-data survives.

# systemd
sudo systemctl disable --now dnsdaddy
sudo rm /etc/systemd/system/dnsdaddy.service /usr/local/bin/dnsdaddy
sudo systemctl daemon-reload
# /var/lib/dnsdaddy and /etc/dnsdaddy survive.
```

**Give the network its DNS back first.** Point DHCP at your router or a public
resolver and confirm one client resolves *before* you stop DNS Daddy. Otherwise
you take the network's name resolution down with it.

If the installer disabled the systemd-resolved stub listener, restore it:

```bash
sudo rm /etc/systemd/resolved.conf.d/dnsdaddy.conf
sudo systemctl restart systemd-resolved
```

### Delete everything, permanently

Irreversible. Take a backup first (§10) if there is any chance you want the
history.

```bash
# Docker — asks you to type DELETE, and refuses entirely when unattended
./deploy/install-docker.sh --uninstall --purge
# or, equivalently and with no confirmation at all:
docker compose down -v              # -v deletes the named volume
docker volume rm dnsdaddy-data 2>/dev/null || true

# systemd — after the removal steps above
sudo rm -rf /var/lib/dnsdaddy /etc/dnsdaddy
sudo userdel dnsdaddy
```

This removes the database, cached feeds, the generated password, and every
stored finding.

---

## Troubleshooting

### Start here: `dnsdaddy doctor`

```bash
sudo dnsdaddy doctor                              # native install
docker compose exec dnsdaddy dnsdaddy doctor      # docker
```

It reads your configuration, reads the database, and sends real DNS queries — at
your own listeners and through each configured upstream. It changes nothing (the
database is opened strictly read-only), and it exits non-zero if any check
fails, so it can gate a deployment script. `--json` emits the same findings for
a monitoring system.

Under Docker it must be run **inside the container**: the dashboard is published
on loopback only and the database lives in a named volume, so a run on the host
would report failures that are artefacts of where it was run. Each affected
check says so rather than reporting a false failure.

#### What `doctor` cannot see from inside a container

The dashboard backend listens on `:8080` **inside the container**, and that is
correct — a container that bound its own `127.0.0.1` could not be reached by the
host at all, so the port mapping would never work. What that bind reaches is
decided by how Compose publishes it:

```
127.0.0.1:8080:8080     the dashboard is on the host's loopback only  (what DNS Daddy configures)
0.0.0.0:8080:8080       the dashboard is published to every interface (what you must not do)
```

Those two produce an **identical** listener inside the container. `doctor` runs
in there and cannot tell which one it got, so for a container-internal wildcard
bind it reports a **warning, not a failure**, and says why. It used to report
this as definite public exposure, which was false on every correctly deployed
Docker install.

Check the mapping from the host, where the answer actually is:

```bash
docker compose port dnsdaddy 8080     # expect 127.0.0.1:8080
```

Two things are unaffected by any of this:

- a bind to a **specific public address** inside a container is still a
  failure — no port mapping makes `203.0.113.10` private;
- a management request that has **actually arrived from a public address over
  plain HTTP** is still a failure, container or not. Observation outranks
  inference, and that particular observation is proof the mapping is open.

What it tells apart, which `dig` alone cannot:

| Symptom | What doctor says |
|---|---|
| Clients get no answer at all | whether **nothing is listening** or **another process holds the port** — and names that process |
| Clients get `REFUSED` | that the resolver is **working and declining this source address**, and which ranges it will accept |
| A network exists but gets nothing | that the network is **not permitted to use the resolver**, quoting the effective ACL and naming the tick-box that fixes it |
| Everything resolves, nothing blocked | that the **threat index is empty**, or is enforcing last-known-good data that is stale |
| Names fail intermittently | which **upstreams** resolved a real test query and which did not — and, for one that answered `REFUSED` or `SERVFAIL`, that the transport is fine and the problem is the resolver itself |

### The most common first-install failure

**Symptom.** The dashboard loads, `/api/v1/health` reports `ok`, `docker ps`
says healthy, you have added your network — and every client says the DNS server
is not responding, or `dig` returns `REFUSED`.

**Cause.** A **Network** and its resolver access are two different decisions.
The network decides *which policy* an address gets once it is allowed to
resolve. Its **Allow this network to use DNS Daddy** permission — and
`dns.allowed_client_cidrs` — decide *whether it may resolve at all*, and that
is checked first, before anything else happens. Adding a network on its own
does not grant access.

**Check.** `dnsdaddy doctor`, or `GET /api/v1/diagnostics`, or the
`dnsdaddy_client_refused_total` metric — a number climbing there means clients
are being turned away on their source address, which rules out firewalls,
routing and port conflicts in one step.

**Fix.** Open the dashboard, go to **Networks**, and tick **Allow this network
to use DNS Daddy** on it. It takes effect on the next query — no restart, no
file to edit.

For a headless deployment, add the range to `DNSDADDY_ALLOWED_CLIENT_CIDRS`
instead and restart. Note that setting that variable **replaces** the built-in
list rather than adding to it — the built-in list already covers loopback,
every RFC 1918 range, carrier-grade NAT, link-local, the IPv6 equivalents and
the Docker bridge, so on a LAN you should usually not set it at all.

### Other symptoms

**`bind: address already in use` on :53**

`systemd-resolved`. The installer handles this; manually:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
echo -e '[Resolve]\nDNSStubListener=no' | sudo tee /etc/systemd/resolved.conf.d/dnsdaddy.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved dnsdaddy
```

**Queries time out from a client, work on the server**

Firewall. Check `sudo ufw status` includes that client's public IP, and that
the client's own egress allows port 53 outbound.

**A network shows "No traffic yet"**

Its queries are not arriving from the ranges you configured. Check the Query
log for the actual source address — NAT often means the public IP, not the
internal one.

**Everything resolves but nothing is blocked**

Check `blocklistSize` in `/api/v1/health`. If zero, refresh feeds. If non-zero,
check the policy assigned to that network actually enables categories — a
network on **Monitor only** logs everything and blocks nothing by design.

**Memory climbing**

Check `dnsdaddy_blocklist_domains`. Enabling the ads and adult feeds adds
hundreds of thousands of domains. If you are near the limit, disable a feed or
set `GOMEMLIMIT` lower to make Go collect more aggressively.

**Where are the logs**

```bash
journalctl -u dnsdaddy -f          # systemd
docker compose logs -f dnsdaddy    # docker
```

Run with `-log-level debug` for per-query detail. It is verbose — do not leave
it on.
