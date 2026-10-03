# Docker setup: use the host address, not the container address

The host-aware entry point is **`./install.sh` in the repository root**.
It checks the host and Docker before invoking the existing installer, then
checks the running container. It does not add another dashboard wizard.

```sh
# Public VPS; the dashboard stays behind SSH unless HTTPS is explicitly chosen.
./install.sh

# Trusted home/office LAN.
./install.sh --lan

# Upgrade an existing VPS, preserving its configuration and data.
./install.sh --upgrade

# For a LAN installation, retain its deployment choice when upgrading.
./install.sh --lan --upgrade
```

On a normal host with one suitable stable address, that address is supplied
automatically and appears on Setup and Overview. When NAT hides the public
address, or several interfaces are equally plausible, setup asks once for the
server IP. Non-interactive runs can supply `--server-ip YOUR_SERVER_IP`.
This is the **server destination**, never a permission for a client.

The entry point requires Linux, Python 3, iproute2 and local Docker Engine 28+
with Compose. Python is host tooling only; the DNS resolver image and Go runtime
do not acquire a Python dependency. Existing HTTPS setup can be requested with
`./install.sh --https`; it retains the existing certificate prerequisites.

After installation, open Setup, connect the intended client and copy the DNS IP.
No YAML exports or Docker-internal address are needed for that ordinary path.
A saved network is not proof of a successful lookup: test from that actual client.

## Security boundaries

The resolver keeps bridge-network isolation, its non-root image user, dropped
capabilities and no-new-privileges. The new host checks reject privileged mode,
host networking, host PID, additional capabilities, host-root mounts and Docker
socket mounts. The application is never given access to the Docker control socket.

The host helper only reads local interface and Docker information. It makes no
public-IP discovery or cloud-metadata requests. An egress address reported by an
Internet service would not prove that incoming DNS reaches this server, even if
several services agreed. Direct host addresses and operator-supplied NAT addresses
are configuration, not external reachability measurements.

Both UDP and TCP DNS publications must match the chosen destination and port.
The post-start check reads the actual running container, not just the Compose
file. It also checks that the address was passed to that process and that the
process is configured as non-root. This verifies a configuration/publication
handoff, **not a complete container security audit or a client-side DNS test**.

Remote Docker contexts and Docker Desktop are not treated as local Linux Docker:
the machine running the installer cannot safely advertise its own address for a
container running elsewhere. Rootless Docker receives a source-address warning;
IP preservation depends on the forwarding driver and version and must be tested.
Do not allow a Docker gateway merely to make an access refusal disappear.

### Docker and firewalls

**Ordinary UFW allow/deny rules are not sufficient evidence that a Docker-published
port is filtered.** Docker's NAT/forwarding path can bypass those host rules.
The native-install UFW examples in other deployment documentation must not be
interpreted as proof that a Docker deployment has the same boundary.

Keep the application's client permissions, restrict incoming DNS at the provider
firewall or a correctly configured Docker-aware host firewall, and test from both
an intended client and a source outside the permitted ranges. On Docker's iptables
backend, operator filtering normally belongs in DOCKER-USER. Docker's nftables
backend has different integration rules; do not paste an iptables recipe into it.
The installer does not flush, invent or rewrite firewall rules.

Management stays loopback-bound for VPS mode. LAN publication requires an explicit
LAN choice and is not a claim that cloud NAT cannot expose that address. Use HTTPS
or SSH on an Internet-facing host. Engine releases older than 28 are rejected by
the new entry point because their localhost-published ports can be reachable from
the same layer-2 network. This minimum is not a substitute for current security
updates to Docker, Linux and the resolver image.

Official deployment references:

- [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/)
- [Docker packet filtering and UFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [Docker iptables integration](https://docs.docker.com/engine/network/firewall-iptables/)
- [Docker nftables integration](https://docs.docker.com/engine/network/firewall-nftables/)
- [Docker daemon security](https://docs.docker.com/engine/security/)
- [Rootless networking limitations](https://docs.docker.com/engine/security/rootless/troubleshoot/)

## Configuration and upgrades

The host helper writes only **DNSDADDY_DEPLOYMENT_DNS** to `.env`. It uses an atomic
replacement with mode 0600, preserves the other values and existing owner when run
as root, and rejects symlinks, hard-linked files and files writable by other users.
A manually set hint is not overwritten. New host checks do not print the complete
Compose environment, Docker environment or stored credentials.

The displayed address has this precedence:

1. Explicit `DNSDADDY_ADVERTISED_DNS` / `dns.advertised_endpoint` configuration.
2. The address explicitly saved in the dashboard.
3. The host installer's `DNSDADDY_DEPLOYMENT_DNS` hint.

Only the first locks dashboard editing. Existing saved addresses, even mistaken
ones, are not silently overwritten. Correct a mistaken saved address once in
Setup. Clearing the saved override exposes the installer hint again. The API
labels its source as `installation_hint` and does not label it remotely verified.
Invalid selected hints produce an actionable error, not a guessed container IP.

No source permissions, Default switch, upstreams, Forward/Learn/Live choice,
privacy settings, tokens, certificates, database schema or data volumes are
changed by this handoff. A failed post-start check leaves the running service and
data in place, reports failure and does not try to repair it by opening access.
The existing installer still owns service startup, HTTPS and rollback behavior.

The low-level `deploy/install-docker.sh` and direct `docker compose up` remain
available, but **bypass the new host preflight**. Direct Compose still passes an
existing hint from `.env`. Use the root entry point to refresh detection and check
the handoff after a host address or port mapping changes. Advanced custom network
modes, different container listener ports, or encrypted-only port layouts are not
automatically migrated by this helper; preserve and review those configurations
through their existing deployment path.

Use `./install.sh --dry-run` to inspect the plan. No `.env` or service changes are
made by that path. Do not use volume deletion, unrestricted resolver access or
extra container privileges as a repair.
