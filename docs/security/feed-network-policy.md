# Remote feed network policy

Remote threat-intelligence feeds require HTTPS, certificate verification and a
public unicast destination by default. Both stored URLs and each actual resolved
connection are checked. HTTP, URL userinfo, loopback, link-local, cloud metadata,
multicast, unspecified and reserved destinations are refused. Environment HTTP
proxies are not used. Query/path authentication remains supported, but paths,
queries and raw transport errors are omitted from feed diagnostics.

Same-origin HTTPS redirects are supported within a five-request limit.
Cross-origin redirects require an explicit origin rule. Origin identity includes
the HTTPS scheme, hostname and effective port. All inherited headers are cleared
on origin changes; Referer is removed on every redirect. A redirect permission
never grants private-address permission to its target.

For an internal HTTPS feed, a trusted operator can configure narrowly scoped
startup rules (no database migration or dashboard privilege expansion):

```yaml
feeds:
  network_rules:
    - origin: "https://intel.corp.example:8443"
      private_cidrs: ["10.20.30.0/24", "fd12:3456:789a::/48"]
      redirect_origins: ["https://cdn.corp.example:8443"]
    - origin: "https://cdn.corp.example:8443"
      private_cidrs: ["10.20.31.0/24"]
```

Use only RFC1918/ULA CIDRs owned by the operator, limited to the actual feed
service. Rules apply to that exact origin, not arbitrary subdomains or ports,
and require restart to take effect. The policy never permits loopback, link-local
or the protected metadata endpoints, even within a configured private prefix.
There are at most 32 rules, 16 prefixes and 16 redirect origins per rule. A feed
publisher cannot create or expand these rules through an HTTP response.

All shipped catalogue URLs already use HTTPS; their live redirect chains and
service availability were not contacted during this isolated remediation. When
a publisher intentionally redirects across origins, configure its approved
HTTPS target or use its verified final HTTPS URL. Custom TLS roots, if required,
remain an operator platform trust-store decision; do not disable verification.

Existing HTTP/private feeds are not silently converted or deleted. An insecure
refresh fails before connection and reports a policy error; the previous valid
cache remains available. Migrate to a publisher-supported HTTPS URL or explicitly
approve a narrow private HTTPS rule. Do not remove a good cache as part of URL
migration. No plaintext fallback is provided.

Feed diagnostics now use feed IDs and safe constant errors/HTTP status codes.
Publisher-controlled Observatory source metadata is retained in parsed results
and cached content, but diagnostics emit only `source_present`, never its text.
Cache-load diagnostics classify missing, permission-denied and unreadable/invalid
copies without copying raw parser errors or field names into logs or API status.
Counts, feed IDs and typed timestamps remain available for troubleshooting.
Previously retained URL errors, logs and backups are not retroactively scrubbed.
Review their access/retention and rotate a credential if actual exposure is
established. The management API still returns configured feed URLs to its fully
authenticated administrator; query/path secrets remain recoverable configuration.
Separate encrypted feed credential storage is future work.

This change does not alter DNSSEC, DNS upstream transports, provider/webhook
consent, authentication, local file-copy bounds or resolver-token logging.
The local-file import and password findings remain separate remediation stages.
