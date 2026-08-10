# Pointing your network at DNS Daddy

Instructions for the kit small IT teams actually run. In every case the pattern
is the same: set DNS Daddy as the resolver, then block everything else from
reaching port 53 so devices cannot route around it.

Throughout, `198.51.100.5` stands for your DNS Daddy server.

---

## pfSense

**Set the resolver**

*System → General Setup → DNS Server Settings*

- DNS Server 1: `198.51.100.5`
- DNS Server 2: a second DNS Daddy instance, or a public resolver as a fallback
- Untick **DNS Server Override** so your ISP cannot replace it via DHCP/PPPoE

**Stop pfSense resolving on its own**

*Services → DNS Resolver* → untick **Enable DNS Resolver**, then
*Services → DNS Forwarder* → tick **Enable DNS Forwarder**. Otherwise Unbound
recurses directly and never asks DNS Daddy.

**Hand it to clients**

*Services → DHCP Server → [interface] → DNS Servers*: `198.51.100.5`

**Force everything through it**

*Firewall → NAT → Port Forward*, on your LAN interface:

| Field | Value |
|---|---|
| Interface | LAN |
| Protocol | TCP/UDP |
| Destination | `! LAN address` (invert match) |
| Destination port | 53 |
| Redirect target IP | `198.51.100.5` |
| Redirect target port | 53 |

This silently redirects a device with a hard-coded `8.8.8.8` to DNS Daddy
instead. Add a firewall rule blocking outbound 53 for anything that must not be
redirected.

---

## OPNsense

Same shape as pfSense.

- *System → Settings → General* → DNS servers: `198.51.100.5`, and untick
  **Allow DNS server list to be overridden by DHCP/PPP on WAN**
- *Services → Unbound DNS → General* → untick **Enable Unbound**
- *Services → DHCPv4 → [interface]* → DNS servers: `198.51.100.5`
- *Firewall → NAT → Port Forward* → the same redirect rule as above

---

## UniFi

*Settings → Networks → [your LAN] → DHCP Name Server* → **Manual**

- DNS Server 1: `198.51.100.5`
- DNS Server 2: your fallback

Clients pick this up on their next DHCP renew, which can take up to the lease
time. Reboot a test device rather than waiting.

**Block the bypass**

*Settings → Firewall & Security → Firewall Rules → LAN In*, new rule:

- Type: LAN In · Action: Drop
- Protocol: TCP/UDP · Destination port: 53
- Source: your LAN network
- Destination: any *except* `198.51.100.5`

Order it below any rule that permits DNS to DNS Daddy.

**A note on UniFi's own DNS shield.** Recent controllers can force clients
through UniFi's own filtering DNS. Turn that off, or it will take precedence and
your query log will stay empty.

---

## FortiGate

```
config system dns
    set primary 198.51.100.5
    set secondary 198.51.100.6
end
```

DHCP scope:

```
config system dhcp server
    edit 1
        set dns-service specify
        set dns-server1 198.51.100.5
    next
end
```

Then a policy denying LAN→WAN on the `DNS` service for everything except DNS
Daddy, placed above your general outbound allow. If DNS Daddy is on the LAN
side, no policy is needed for it.

---

## SonicWall

*Network → DNS* → **Specify DNS Servers Manually** → `198.51.100.5`

*Network → DHCP Server → [scope] → DNS/WINS* → same address.

Add an access rule: LAN → WAN, service **DNS (Name Service)**, action **Deny**,
with a rule above it permitting the DNS Daddy address.

---

## Windows Server / Active Directory

Do **not** point domain-joined clients directly at DNS Daddy. They must keep
using your domain controllers, or AD name resolution breaks in ways that are
tedious to diagnose.

Instead, forward from the DC:

*DNS Manager → right-click the server → Properties → Forwarders → Edit*

Remove the existing forwarders and add `198.51.100.5`.

Or in PowerShell:

```powershell
Set-DnsServerForwarder -IPAddress "198.51.100.5" -PassThru

# Root hints let the DC recurse on its own and skip your forwarder entirely.
Set-DnsServerRecursion -Enable $true -UseRootHint $false
```

Verify:

```powershell
Resolve-DnsName example.com -Server 127.0.0.1
Get-DnsServerForwarder
```

Client queries now arrive at DNS Daddy from the DC's address, so the query log
attributes them to the DC rather than to individual machines. That is a real
limitation of forwarding through AD. If you need per-device attribution, either
point non-domain devices (guest Wi-Fi, IoT VLANs, printers) straight at DNS
Daddy, or read device attribution from the DC's own logs.

---

## Individual machines

**Linux (systemd-resolved)**

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/dnsdaddy.conf <<'EOF'
[Resolve]
DNS=198.51.100.5
Domains=~.
EOF
sudo systemctl restart systemd-resolved
resolvectl status
```

**macOS**

```bash
networksetup -setdnsservers Wi-Fi 198.51.100.5
networksetup -getdnsservers Wi-Fi
```

**Windows**

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "198.51.100.5"
Clear-DnsClientCache
```

---

## Roaming laptops

A laptop in a coffee shop is not on your network and does not arrive from an IP
you can allow-list. Use DNS-over-HTTPS with that network's token instead: it
works from anywhere, and the token in the path applies the right policy.

Find the URL under **Setup → DNS-over-HTTPS**. It looks like:

```
https://dns.example.co.uk/dns-query/YOUR_NETWORK_DOH_TOKEN
```

> Treat that URL as a credential. Anyone holding it resolves under that
> network's policy. If one leaks, rotate it:
> `POST /api/v1/networks/{id}/rotate-token`.

**Windows 11** (native DoH, needs the resolver's IP registered first):

```powershell
Add-DnsClientDohServerAddress -ServerAddress 198.51.100.5 `
  -DohTemplate "https://dns.example.co.uk/dns-query/YOUR_NETWORK_DOH_TOKEN" -AllowFallbackToUdp $false
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "198.51.100.5"
```

**macOS / iOS** — install a DNS profile (`.mobileconfig`) with a
`DNSSettings` payload of type `HTTPS` and the URL as `ServerURL`. Deploy it
through your MDM.

**Firefox** — *Settings → Privacy & Security → DNS over HTTPS → Max Protection*,
Custom, with the URL above.

**Any platform** — the DoH URL works in any RFC 8484 client, including
`dnscrypt-proxy` and `cloudflared`.

---

## Stopping DoH bypass

Be straight with yourself about this: a determined user with admin rights on
their own laptop can resolve DNS over HTTPS directly to a public resolver and
skip you entirely. DNS filtering is a control against malware, accidents, and
casual browsing — not against a motivated insider.

What actually helps, roughly in order of effectiveness:

**1. Block known DoH endpoints at the firewall.** Public resolvers publish their
DoH addresses. Blocking those IPs on 443 causes most browsers to fall back to
system DNS. Maintained lists exist; treat this as ongoing maintenance, not a
one-off.

**2. Turn off browser DoH by policy.** This is the highest-value single change,
because browser defaults are what turn DoH on for most people.

*Chrome / Edge* (Group Policy → Administrative Templates → Google Chrome):
```
DnsOverHttpsMode = "off"
```

*Firefox* (`policies.json` or GPO):
```json
{ "policies": { "DNSOverHTTPS": { "Enabled": false, "Locked": true } } }
```

**3. Serve `use-application-dns.net` as NXDOMAIN.** Firefox uses this canary
domain: if it does not resolve, Firefox disables automatic DoH. DNS Daddy
answers NXDOMAIN for anything on a blocklist, so add it to your policy's custom
block list and Firefox will stand down on your network.

**4. Block outbound 53 except to DNS Daddy** (above). Catches hard-coded plain
DNS, which is far more common in malware than DoH is.

**5. Accept the residual risk.** Document it. "Protective DNS is deployed
network-wide; encrypted DNS bypass is mitigated by browser policy and endpoint
configuration" is a defensible answer on a security questionnaire, and an
honest one.

---

## Verifying it works

From a client that should be filtered:

```bash
# Should resolve normally
dig @198.51.100.5 example.com

# Should be NXDOMAIN — add this to your policy's block list first
dig @198.51.100.5 blocked-test.example

# Check the whole chain, not just the resolver
nslookup example.com
```

Then confirm the query appears in the dashboard's **Query log** with the right
network attributed to it. If it does not, the client is not reaching DNS Daddy
— check the firewall and the DHCP lease before anything else.
