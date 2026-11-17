# DNS Security Map — future topology phase (design note)

Phase 1 ships only the retained-DNS investigation map. A later, separate phase
may add optional topology context. That work must stay distinct from DNS
observation edges and must not ship empty placeholder collectors.

## Candidate optional sources

- Read-only UniFi controller integration (configured associations / reported
  clients), with explicit credentials and outbound disclosure.
- Optional pfSense/OPNsense or DHCP metadata (leases, aliases) when deliberately
  configured by the operator.
- Optional authorised SNMPv3 / LLDP topology sources on networks the operator
  can reach.
- A separate collector when internal networks cannot be reached from a VPS
  deployment — never require the resolver host to scan the LAN.

## Honesty requirements for any future implementation

- Every externally reported relationship carries source, timestamp and
  staleness.
- DNS observations, configured associations and externally reported physical
  connections remain visually and semantically distinct.
- Credentials, permissions and what leaves the host are documented before
  enablement; no silent enrichment.
- Do not invent device vendors, OS or port membership from an IP alone.
- Do not build an unused generic plugin framework ahead of a concrete source.

None of the above is implemented by the Phase 1 DNS Security Map.
