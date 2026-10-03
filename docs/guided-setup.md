# Connect a device

Open **Setup** or **Networks** and use **Connect to DNS Daddy**.

1. Choose where DNS Daddy is running.
2. Check the **DNS server IP** and enter the **device or network IP**.
3. Press **Connect**, then copy the DNS IP into the device or router's DNS settings.

A single private device needs no separate preview, name, policy selection, port
selection, display-save button or resolver-access checkbox. The default filtering
policy is already selected and shown. Resolver modes and upstreams are unchanged.

For a public address, whole subnet, multiple addresses or an existing connection
being replaced, the app shows the exact ranges and asks for confirmation first.
Public addresses retain the explicit ownership/access acknowledgement. A public
internet address can represent every device sharing that router connection.

After saving, the form gives way to **Copy DNS IP** and **Add another device or
network**. Existing connections remain visible in **Your connections**, with an
**Edit** button and their reported access status. **Access saved** is not a claim
that the device has been tested: open a website on the device and check Overview
for DNS activity. A failed reload is shown as **Saved — needs attention**.

## Which IP goes where?

The **DNS server IP** is where the device sends its questions. The **device or
network IP** is who you permit to ask.

| Connection | DNS server IP | Device or network IP |
| --- | --- | --- |
| At home or work | The server's LAN IP | The device's LAN IP, or your actual LAN subnet |
| On a cloud server | The cloud server's public IP | Your home/office's public internet IP |
| Through a VPN | The server's VPN IP | The device's VPN IP or assigned VPN subnet |
| Only on the server itself | Loopback on that server | Loopback only |
| Roaming device | Your configured server destination; HTTPS must already exist | No IP grant; use the network's private HTTPS link |

A router forwarding DNS may hide individual devices behind its own address.
For changing internet addresses, a VPN or tokenised HTTPS connection avoids
continually editing public-IP permissions. These options still need their VPN
or HTTPS infrastructure configured separately.

**Use this connection** fills the source seen for your dashboard connection only
when it is not loopback or link-local. It does not grant anything. Use it only
when DNS will follow the same connection; proxies, SSH tunnels and VPNs may differ.
The browser hostname is never treated as the DNS server address.

The server address is filled from saved configuration. On a native host, a
preferred local interface matching both DNS listeners can be suggested and is
labelled as a suggestion. A container-internal address is never substituted for
an unknown host/public IP: enter the real server address once.

Bare IPv4 and IPv6 addresses work without typing `/32` or `/128`. To permit a
subnet, enter its actual prefix, for example `192.168.1.0/24`; the confirmation
shows the whole range. Multiple entries can be comma-separated. URLs, hostnames,
ports inside an IP, dash ranges and wildcard/default routes are not accepted by
the guide. Examples are not automatically permitted.

## Customisation is optional

**More options** contains a custom connection name, policy, published DNS port
and the existing-connection selector. Normal DNS uses port 53; custom ports need
client support and must match the deployment. The guide does not change listeners.

**Advanced settings** contains the previous setup/network controls, DNS transport,
address diagnostics and encrypted connection instructions. These controls are
closed on the normal screen, not removed. The roaming completion link opens
fresh encrypted instructions so the newly created network is included.

Optional Forward starter text and command-line tests remain under
**Troubleshooting and configuration files** after a save. They are not required
for normal post-install connection. The backend setup-preview API still supports
all six deployment presets and all three exported modes; its contract is in the
served `/openapi.yaml`. Nothing here switches the running resolution mode or
upstream provider. Forward/Learn/Live runtime controls remain in the application.

Starter files are for a new installation, not an in-place upgrade or a transfer
of the current database. They keep bootstrap access loopback-only, require a
reviewed named client grant on the target installation, and do not provision VPN,
TLS, firewall or NAT rules. Compose port replacement uses `!override` and requires
Compose 2.24.4+. Do not overwrite an existing custom `.env`, delete volumes or
change an entire network's DHCP before verifying one client.

## Saved settings and errors

Connect validates first, saves the displayed DNS address when needed, then saves
the named client grant through the existing authenticated, audited APIs. These
are two operations, not an atomic transaction. If the address save fails, no
network grant is attempted. If a network response is lost, the address may already
be saved and the grant may have committed: the app blocks blind retries and asks
you to refresh and inspect Your connections. A known saved network ID is retained
so a retry does not create a duplicate.

Explicit `DNSDADDY_ADVERTISED_DNS` / `dns.advertised_endpoint` configuration stays
authoritative and is read-only in this form. Public acknowledgement, access
checks, Default permissions, policy enforcement and DNSSEC are not bypassed.
See [upgrade notes](guided-setup-upgrade-notes.md) for the existing Default
fallback correction introduced with the original guided-setup implementation.
