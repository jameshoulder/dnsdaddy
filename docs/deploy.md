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

Or with Docker:

```bash
git clone https://github.com/jameshoulder/dnsdaddy.git
cd dnsdaddy
docker compose up -d
docker compose logs dnsdaddy | grep -i password
```

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

## 5. Put TLS in front of the dashboard

The dashboard authenticates with a password. Over plain HTTP on the public
internet, that password crosses the network in the clear. On a LAN-only
deployment you can accept that; on anything internet-facing, do not.

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
anything unmatched. Keep it.

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
cannot regenerate — feed caches re-download and the session key regenerates
(logging everyone out, which is survivable).

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

Under Docker set `DNSDADDY_ALLOWED_CLIENT_CIDRS` in `.env`. Confirm with
`./deploy/healthcheck.sh`, which names this failure explicitly.

### Performing the upgrade

Docker:

```bash
cd /opt/dnsdaddy
docker compose exec dnsdaddy sh -c 'cd /var/lib/dnsdaddy && tar cz .' > ~/dnsdaddy-backup-$(date +%F).tgz
git pull
$EDITOR .env                      # apply the two changes above
docker compose up -d --build
./deploy/healthcheck.sh
```

Never use `docker compose down -v` — `-v` deletes the `dnsdaddy-data` volume
holding the database, session key and cached feeds.

systemd — re-running the installer upgrades the binary and leaves your config
and database alone:

```bash
curl -fsSL https://raw.githubusercontent.com/jameshoulder/dnsdaddy/main/deploy/install.sh | sudo bash
```

The schema is applied idempotently at startup and built-in feed metadata is
refreshed, so an upgrade can correct a feed URL that has moved. Your
enabled/disabled choices are preserved.

Take a backup first anyway.

## Troubleshooting

### Start here: `dnsdaddy doctor`

```bash
sudo dnsdaddy doctor                              # native install
docker compose exec dnsdaddy dnsdaddy doctor      # docker
```

It reads your configuration, reads the database, and sends real DNS queries at
your own listeners. It changes nothing, and it exits non-zero if any check
fails, so it can gate a deployment script. `--json` emits the same findings for
a monitoring system.

Under Docker it must be run **inside the container**: the dashboard is published
on loopback only and the database lives in a named volume, so a run on the host
would report failures that are artefacts of where it was run. Each affected
check says so rather than reporting a false failure.

What it tells apart, which `dig` alone cannot:

| Symptom | What doctor says |
|---|---|
| Clients get no answer at all | whether **nothing is listening** or **another process holds the port** — and names that process |
| Clients get `REFUSED` | that the resolver is **working and declining this source address**, and which ranges it will accept |
| A network exists but gets nothing | that the network is **not in `dns.allowed_client_cidrs`**, with both values quoted |
| Everything resolves, nothing blocked | that the **threat index is empty**, or is enforcing last-known-good data that is stale |
| Names fail intermittently | which **upstreams** answered and which did not |

### The most common first-install failure

**Symptom.** The dashboard loads, `/api/v1/health` reports `ok`, `docker ps`
says healthy, you have added your network — and every client says the DNS server
is not responding, or `dig` returns `REFUSED`.

**Cause.** A **Network** in the dashboard and `dns.allowed_client_cidrs` are two
different settings. The network decides *which policy* an address gets once it
is allowed to resolve. `dns.allowed_client_cidrs` decides *whether it may
resolve at all*, and it is checked first, before anything else happens. Adding a
network does not grant access.

**Check.** `dnsdaddy doctor`, or `GET /api/v1/diagnostics`, or the
`dnsdaddy_client_refused_total` metric — a number climbing there means clients
are being turned away on their source address, which rules out firewalls,
routing and port conflicts in one step.

**Fix.** Add the range to `DNSDADDY_ALLOWED_CLIENT_CIDRS` (or
`dns.allowed_client_cidrs`) and restart. Note that setting this variable
**replaces** the built-in list rather than adding to it — the built-in list
already covers loopback, every RFC 1918 range, carrier-grade NAT, link-local,
the IPv6 equivalents and the Docker bridge, so on a LAN you should usually not
set it at all.

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
