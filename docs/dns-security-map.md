# DNS Security Map

Phase 1 investigation workspace for retained DNS evidence: which observed
clients belong to which configured network contexts, which exact names they
queried, and which of those queries were allowed, policy-blocked or failed.

Dashboard route: **Workspace → DNS Security Map** (`#/security-map`).
API: authenticated `GET /api/v1/network-map`.

This is a DNS activity and security relationship map. It is **not** physical
network discovery, a packet-flow map, device fingerprinting, or proof that a
device connected to a website.

## What each node and edge means

| Element | Meaning |
|---|---|
| Network container | A configured network from Networks settings. Grouping uses the `networkId` **recorded on each query row**, not a fresh CIDR reclassification of history. |
| Client node | An observed source IP (plus optional operator/recorded name) in that recorded network context for the selected window. |
| Domain node | An exact normalised queried name (`domainutil`), not a registrable-domain rollup of the last two labels. |
| Queried edge | DNS queries recorded in the selected retained-data window between that client context and that name. |
| Finding marker | Related experimental finding metadata attached by identity match. Findings never invent queried edges. |

Client→domain edges do **not** mean connected to, visited, downloaded from, or
exfiltrated to.

## What the map cannot observe

- Physical links, VLANs, switch ports, ARP/NDP, SNMP/LLDP/CDP or NetFlow.
- Authenticated device identity (NAT, forwarders, proxies and DHCP reuse can
  combine or reuse addresses).
- Outbound transport or Daddybound mode used for every historical query from a
  current resolver-status card (that card is runtime context only).
- Clients whose addresses were omitted by privacy controls — those identities
  are not reconstructed from other tables.
- Names or clients outside the retained query log and the processing caps.

## Client-identity limitations

An observed client IP is not an authenticated device. Identical private
addresses in different recorded network contexts stay separate. Shared
forwarder/proxy addresses appear as one client context with whatever traffic
they forwarded. First/last-seen labels are scoped to the selected retained
window, not the first time a device or domain ever existed.

## Data sources, privacy and retention

Built only from existing retained `query_log` rows, configured networks and
separately listed findings. Opening or refreshing the map does not resolve DNS,
enrich externally, refresh feeds, change trust anchors or modify policy.

Respects global query logging, policy `logQueries`, client-IP logging and
retention. Disabling logging stops **new** collection; it does not by itself
erase previously retained rows. When client attribution is unavailable the API
returns `available: false` with an explicit reason and empty client/domain
graph nodes.

Map responses use `Cache-Control: no-store`, never appear in public health or
login bodies, and are not written to `localStorage`. Logout clears the page's
transient viewport state. Labels are escaped through the dashboard's `html` /
`esc` helpers; CSP remains script/style `self` only.

## Dataset and output limits

Default display targets are about 80 clients / 70 domains / 300 edges, with hard
caps of 250 / 250 / 1,000. Source rows are capped (default 50,000; hard 100,000)
newest-first before aggregation. Truncation is reported in `limits` and
`limitations`; counts describe the processed/displayed subset. Unknown complete
totals stay unknown — the map does not invent an omitted count by scanning the
whole table.

Time presets: 15 minutes, 1 hour, 24 hours (longer windows are accepted up to
168 hours subject to retention).

## Safe offline demonstration

1. Enable query logging and client-IP logging.
2. Create two networks with distinct CIDRs and permit resolver access.
3. Generate a few queries from clients in each range (allowed, blocked and
   failed outcomes).
4. Open `#/security-map`, choose the 1-hour window, optionally filter by
   network, select a client and follow **Investigate client**.

No demonstration dataset is injected into empty production deployments.

## Related pages

- [Networks](../internal/web/static/index.html) configuration remains the editor;
  the map does not replace it.
- [Investigate](capabilities.md) APIs remain the detail workflow.
- Future optional topology sources (UniFi, pfSense/OPNsense, SNMPv3/LLDP) are
  sketched in [dns-security-map-topology.md](dns-security-map-topology.md) and
  are **not** implemented in Phase 1.
