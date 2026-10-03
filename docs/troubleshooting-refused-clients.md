# Clients receive REFUSED

## Identify the failure before changing security settings

Run a DNS query from an affected client, not just inside the resolver container:

```sh
# Replace DNS_SERVER_IP with the resolver address configured on this client.
dig @DNS_SERVER_IP example.com A +time=3 +tries=1
dig @DNS_SERVER_IP example.com A +tcp +time=3 +tries=1
```

A timeout, REFUSED, NXDOMAIN and SERVFAIL are different failures. In particular,
Daddybound validation failures are not repaired by opening the client ACL.
Do not disable DNSSEC or introduce an automatic forwarding fallback to diagnose
an admission problem.

The live activity endpoint (`GET /api/v1/activity/live`, authenticated) separates
refused traffic from resolution errors. ACL refusals increment a counter but do
not persist individual query-log rows. Logged error rows can instead represent
upstream errors, native validation failures or response-protection decisions;
read their reason/source before attributing them to admission.

## Restore access on an existing installation

In Networks, create or edit a network with the source address DNS Daddy actually
receives. Keep the network enabled, assign the intended policy, and explicitly
enable its resolver-access permission (`allowResolver`). A policy assignment or
a friendly client name alone does not grant permission to use the resolver.

For a public VPS receiving direct DNS from a home or office router, the source
is normally that router's public egress address, not the client's private LAN
address and not the VPS's own address. Use a specific IPv4 `/32`, IPv6 `/128`, or
an intentionally managed network prefix. Public ranges require acknowledgement.
Do not add `0.0.0.0/0`, `::/0`, or disable open-resolver protection as a repair.

The management API persists this grant and reloads the live ACL. A successful
reload applies to the next query without a restart. Check for a reload warning
and check Diagnostics/the live effective CIDRs: a stored grant is not proof that
a failed reload applied it. Then repeat both UDP and TCP tests from the client.

A managed grant works even while Default ad-hoc access is off. This is the
narrowest repair for an existing restricted deployment. For an installation
whose whole configured bootstrap boundary is deliberately meant to be active,
review that boundary and explicitly enable Default ad-hoc access instead.
Do not make that decision based on a localhost-only health check.

Docker container/gateway addresses and trusted reverse-proxy addresses have
separate meanings. Do not grant a Docker gateway or trust forwarding headers
merely to make refusals disappear. Verify whether source addresses are preserved.

## First-run default correction

Previously `store.seed` created `n_default` with `allow_resolver = 0`.
`clientacl.Compute` then removed non-loopback bootstrap grants when it loaded
that row. This meant a fresh installation could have a configured allowed
client range, pass a localhost check, and still refuse every client in that range.

New databases now seed the Default gate on, so their configured
`dns.allowed_client_cidrs` boundary is honoured. This is a deliberate first-run
behaviour change, not removal of the ACL: no CIDRs are added, managed grants
remain explicit, and addresses outside the effective boundary remain refused.
Operators requiring named-network-only admission can still turn Default off.

Existing recorded access decisions are not changed by this correction. In
particular, upgrading an already initialised installation does not silently
turn an off decision on. Use the explicit managed-network repair above; do not
delete the database, reset installation markers, or remove Docker volumes.

Forward/Learn/Live choices, threat filtering, response protection, tokens and
open-resolver validation are unchanged.

## Regression coverage

`internal/dnsserver/first_run_acl_test.go` loads networks from the real seeded
store into the live ACL controller and sends requests through the DNS handler
with a local test upstream. It checks configured IPv4, IPv4-mapped IPv6 and IPv6
clients, out-of-range refusal, continued malware blocking, a narrow explicit
public bootstrap grant, and live grant/revocation while Default remains off.
These are deterministic handler-level tests, not a claim of live-VPS verification.

```sh
go test -race ./internal/store ./internal/clientacl ./internal/dnsserver ./internal/api
```
