# Guided setup: from installation to a working client

Open **Setup** or **Networks** after signing in. The **Connect a device or network**
assistant appears above the existing advanced controls. Existing installations,
policies, upstreams, Forward/Learn/Live choices and network permissions are not
reset by opening it. A preview performs no network requests outside this resolver.

## Two addresses, two different jobs

**Server address** is where the device sends DNS questions. **Client source
addresses** decide who may ask. Do not put the server's own IP into a network
permission unless the server itself is the intended client.

The browser's dashboard URL is a third thing: it may point to HTTPS, a proxy or
an SSH tunnel. The guide never turns the browser's Host header or the management
connection's source into a DNS destination or an automatic permission.

| Preset | Server destination | Client source permission |
| --- | --- | --- |
| Home / office LAN | DNS server host's LAN IP | Actual LAN subnet, or the router IP when the router forwards DNS |
| One device | Reachable server LAN/VPN IP | One device's IPv4 /32 or IPv6 /128 |
| Public VPS / fixed site | VPS public/NAT-facing IP | Home/office public egress IP, not its private LAN subnet |
| Private VPN | Server's VPN IP | The client's VPN IP or its actual assigned VPN prefix |
| Roaming encrypted DNS | Server IP plus separately configured HTTPS identity | Dedicated enabled network token; no source-IP grant |
| Local development / SSH-only | Loopback on the server | Loopback only; default test port 5353 |

The VPN and HTTPS presets do not install a VPN, issue a certificate or change
cloud firewalls. Use the existing installation procedures for those prerequisites.
A public address cannot be inferred reliably from inside a container or behind
NAT. Confirm it from your deployment, then save it explicitly.

## Complete the setup

1. Choose the preset. Enter the **client-facing server IP** and **published DNS
   port**, normally 53. Use **Save display address** to make Overview show that
   endpoint. The save persists, takes effect on subsequent dashboard reads, and
   is recorded in configuration history. It does not open any listener or grant
   any client access.
2. Create a named network or select an existing one. Choose its policy and enter
   the actual client source addresses. **Preview configuration and access** shows
   the canonical prefixes, scope, warnings and destination. Editing an existing
   network replaces its ranges and enables it but preserves its token. Other
   networks and Default are untouched; permissions remain additive.
3. Review the preview and, for public client ranges, explicitly acknowledge the
   grant. **Apply network access** uses the existing Networks API, including
   public acknowledgement, open-resolver guards, audit history and live reload.
   A reload warning is not a successful live change. Inspect Networks and
   Diagnostics before retrying an ambiguous failed response.
4. Run the generated UDP and TCP tests from a permitted device. A localhost
   health check is not proof that a remote client can resolve. NOERROR with an
   answer is a successful test; REFUSED, SERVFAIL and timeout need different
   diagnoses. For tokenised DoH, use the encrypted client instructions in Setup
   instead of the plaintext test commands.

The guided grant works with Default ad-hoc access off: it does not depend on
changing the first-run default or on PR #84. It also does not remove access that
was granted elsewhere. A narrow grant cannot carve a denial out of a broader one.

## Address examples

These are examples, not addresses to copy into a real deployment.

- `192.168.1.50` becomes `192.168.1.50/32`, one IPv4 address.
- `192.168.1.50/24` is normalised to `192.168.1.0/24`; the preview makes the
  whole-subnet effect visible before anything is saved.
- `2001:db8::50` becomes `2001:db8::50/128`, one IPv6 address. `2001:db8::/32`
  is documentation space, not a real client assignment.

Multiple entries can be separated by commas or new lines. The guide rejects
URLs, hostnames, embedded ports, dash ranges, wildcard routes and overly broad
prefixes. A bare IP is sufficient; no need to learn CIDR syntax for one device.
Advanced network controls remain available for deliberately managed deployments.

A public IPv4 `/32` may admit **every device behind that NAT router**, not just
one computer. A device name is not an identity credential. For changing ISP IPs,
mobile connections or IPv6 privacy addresses, use a stable private VPN identity
or tokenised DoH rather than continually broadening public permissions. Reserve
LAN addresses in DHCP when permissions depend on those addresses. A router
forwarding DNS may hide the individual devices behind its own source address.

## Ready starter files and their limits

Every preset can generate an environment starter, a Docker Compose port override,
and native YAML. The mode selector produces Forward, Learn or Live variants:

- Forward starter: existing Cloudflare HTTPS primary/backup endpoints and no local
  validation runtime. The provider is named explicitly, not silently switched on
  your running installation.
- Learn starter: forwarding plus separate native DNSSEC observations; outbound
  UDP/TCP 53 is needed for native observations.
- Live starter: experimental native DNSSEC enforcement. Bogus/inconclusive answers
  fail closed. There is no automatic weaker forwarding fallback.

Those choices affect **exported files only**. Existing runtime mode and encrypted
transport controls remain below the guide. Approved upstream DoH2/DoH3/DoQ profiles
still use those existing controls; this guide does not promise new incoming DoQ
support or provision TLS certificates. Explicit mode settings in exported files
pin that mode; remove the setting and restart to return control to the dashboard.

The exports deliberately keep bootstrap admission loopback-only, with ordinary
clients admitted by the reviewed named Network. That avoids reliance on differing
first-run defaults. Apply the intended network on the target installation after
it starts; downloading a file alone does not copy this installation's database,
policies, credentials or network grants elsewhere.

For a **new Docker installation**, save the environment as `.env.ready` and the
port file as `compose.ready.yaml` beside the repository's `docker-compose.yml`:

```sh
docker compose --env-file .env.ready -f docker-compose.yml -f compose.ready.yaml config
docker compose --env-file .env.ready -f docker-compose.yml -f compose.ready.yaml up -d --build
```

Inspect the rendered Compose configuration before starting it. The port override
uses `!override`, requiring Docker Compose 2.24.4+, so the original wildcard
published ports are replaced rather than accidentally retained alongside the new
ones. LAN/VPN host-bind addresses must exist on that host. VPS public addresses
may be NATed, so the VPS starter does not try to bind a nonexistent public NIC IP.
Roaming Docker starters publish no plaintext DNS port. Management remains bound
to `127.0.0.1:8080` in every generated starter.

Do not deploy starter files over an existing custom install without reviewing
and merging settings. The guide does not overwrite `.env`, restart containers,
change system services, or delete volumes. Never use `docker compose down -v` as
an access repair.

Reach a loopback dashboard through your existing SSH tunnel. For example, run
this on your own computer, substituting your server and SSH account:

```sh
ssh -N -L 8080:127.0.0.1:8080 user@YOUR_SERVER
```

Then open `http://127.0.0.1:8080` on that computer. This tunnel is for management;
it does not make UDP DNS available at your computer's loopback address. Use the
existing `deploy/install-docker.sh --https` workflow for publicly reachable HTTPS
management/tokenised DoH, with your own hostname and certificate prerequisites.

For a native installation, install the generated YAML through your normal native
service configuration procedure, preserving permissions and data. Binding a DNS
port below 1024 requires the existing service's port-binding capability.

## Configuration precedence

`DNSDADDY_ADVERTISED_DNS` / `dns.advertised_endpoint` remains authoritative when
set. The dashboard explains that the address is locked; edit or remove that
setting and restart before managing the address in the UI. A saved dashboard
address is used otherwise. Both are operator configuration, not externally
verified reachability. The API also supports clearing the dashboard override.

The saved address is read through `GET /api/v1/server-addresses`, so the existing
Overview card prefers it over Docker-internal addresses. No request-header or
third-party public-IP discovery is introduced. Concurrent address edits using
`previous` are rejected when based on stale state.

## Tests and API contract

`internal/setupguide` tests presets, canonicalisation, source-scope checks,
IPv4/IPv6, modes and generated port mappings. API tests exercise authentication,
CSRF, config precedence, stale writes, audit history, non-mutating previews,
display-only saves and generated YAML through the actual configuration parser.
Dashboard tests cover review gates, public acknowledgement, escaping and token
roaming. Embedded-script tests cover extension delivery and cache invalidation.

The served `/openapi.yaml` includes the setup paths from
`internal/api/openapi-setup.yaml` alongside the existing specification. Setup
preview is offline. Network grants use the existing authenticated Networks API;
there is no separate unaudited permission backdoor.
