# Local support export

Command: **`dnsdaddy support`**

Builds a **local** diagnostic package from an explicit allowlist. Default
collection makes **no outbound requests** and **uploads nothing**. Sharing is a
separate manual action by the operator.

## Usage

```bash
dnsdaddy support -config /etc/dnsdaddy/config.yaml -output ./dnsdaddy-support-out
```

Optional:

| Flag | Meaning |
| --- | --- |
| `-note` | Operator free text (UTF-8, bounded). May set `reviewRequired`. |
| `-repro` | Synthetic reproducer text (bounded). |
| `-include-doctor` | Run active `doctor` probes and attach a separately labelled section. May send network queries. |
| `-timeout` | Collection bound (default 30s). |

The output directory must not already exist. Files are created with mode `0600`
inside a `0700` directory.

## Allowlist (included)

- Version/revision and coarse OS/architecture
- Whether configuration loaded (without echoing secrets or absolute private paths)
- Whether UDP/TCP/HTTP listeners and data_dir are configured (booleans only)
- File-configured local DNSSEC mode and a coarse transport hint
- Bounded placeholder for counters (offline collector does not scrape a live process)
- Doctor section **only** when `-include-doctor` is set: section, status and a
  stable `checkId` hash — not names, summaries, evidence or actions (those can
  embed upstream URLs/tokens, listen addresses or network names)
- Omitted-field explanations and any `reviewRequired` warnings

## Default exclusions

- Query names/history, first-seen rows, findings, raw logs, database copies
- Client/public IPs, device/host names, private paths, environment dumps
- Passwords, cookies, API/DoH tokens, master keys, TLS private keys, backups
- Arbitrary headers, URL query strings, or raw error text that may contain secrets

This is not “copy everything then regex-redact”. Hashed domains/IPs are not
anonymous and are not included by default.

## Relationship to `doctor`

`dnsdaddy doctor` intentionally sends real probes. Support export defaults to
offline collection. Active diagnostics require `-include-doctor` and are labelled
`active-diagnostics` in the package.
