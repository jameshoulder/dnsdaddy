# What DNS Daddy stores

DNS query logs are among the most revealing records a business holds. They show
which sites each device visited, when, and how often — including health,
finance, job-hunting, and union activity. In the UK and EU, when a query is
linked to an identifiable person, that is personal data under UK GDPR and the
GDPR.

This document states exactly what is stored so you can answer that question
honestly, and shows how to store less.

Nothing here is legal advice. If you log DNS for a workforce, your DPIA and your
employee privacy notice are your responsibility.

---

## Nothing leaves your server

Self-hosted DNS Daddy makes exactly three kinds of outbound connection:

1. **Upstream DNS**, for names it does not block — over DNS-over-TLS by default,
   so your ISP cannot read or tamper with it.
2. **Feed downloads**, to the public URLs in
   [threat-intel.md](threat-intel.md), on a schedule you control.
3. Nothing else.

There is no telemetry, no analytics, no licence check, and no call home. Set
`feeds.refresh_interval` to `0` and configure a `file://` feed and it will run
with no outbound HTTP at all. You can verify this with `tcpdump` — please do.

**On the one DNS Daddy-operated feed.** The catalog includes our own DNS Daddy
Threat Observatory, and it ships **disabled** precisely so that the paragraph
above stays true out of the box. Every URL a stock install fetches belongs to
somebody else.

If you enable it, that becomes an outbound HTTPS request from your server to
ours on each refresh, and we see what any feed provider sees: your server's IP
address, its `dnsdaddy/<version>` User-Agent, and the refresh cadence. We do
not see your queries, your clients, or which indicators matched — the feed is a
file download and matching happens on your server. Disabling the feed ends it.
See [threat-intel.md](threat-intel.md#the-dns-daddy-threat-observatory).

## What is written to disk

Everything lives in one SQLite database in your data directory.

### Per-query rows — `query_log`

One row per DNS question, when query logging is on:

| Field | Example | Notes |
|---|---|---|
| `ts` | `2026-07-28T14:22:03Z` | |
| `client_ip` | `10.0.4.23` | Omitted entirely if `log_client_ip: false` |
| `client_name` | `laptop-07` | Only if you named that IP yourself |
| `network_id` | `n_hq` | |
| `qname` | `login.example.com` | **The domain requested** |
| `qtype` | `A` | |
| `action` | `blocked` | |
| `reason` | `Domain is on a phishing list` | |
| `category`, `source` | `phishing`, `Phishing Army` | |
| `dnssec` | `validated` | The upstream's validation verdict |
| `proto`, `elapsed_ms`, `cached` | | |

This is the sensitive table. `qname` plus `client_ip` is a browsing history.

**Default retention: 7 days.**

### Aggregates — `stats_hourly`, `blocked_domain_stats`

Counts per hour per network per category, and per-day counts of blocked domains.
No client IPs, no per-device attribution.

`blocked_domain_stats` does retain blocked *domain names* with counts. Those are
names your network attempted to reach and DNS Daddy stopped — the evidence that
makes reporting useful — but they are not tied to a device.

**Default retention: 90 days.**

Because aggregates are separate from the raw log, you can cut query-log
retention to a day and keep your charts and reports for three months. That is
the single most useful privacy dial in the product.

### Behavioural findings — `findings`

One row per security finding raised by the detection engine.

| Field | Example | Notes |
|---|---|---|
| `event_type`, `severity`, `confidence` | `dns_tunnel_suspected`, `high`, `0.87` | |
| `client_ip`, `client_name` | `10.0.4.23`, `laptop-07` | Empty if `log_client_ip: false` |
| `domain` | `example.com` | **The registered domain involved** |
| `summary` | `laptop-07 queried 187 distinct subdomains of…` | |
| `detail` | *(JSON)* | The full finding, including example names in its evidence |

**This is sensitive, and in one respect more so than the query log.** A finding
is a condensed, pre-analysed statement about a named device's behaviour —
exactly the shape of thing that is useful to an investigator and awkward in a
subject access request. The `detail` JSON also contains example domain names
drawn from the traffic.

**Default retention: 30 days** (`detection.retention_days`), deliberately
longer than the query log, because "has this host done this before?" is a
months-scale question and a finding is a few kilobytes where the traffic behind
it was thousands of rows.

Findings inherit the `log_client_ip` switch: with device attribution off, they
are attributed to the network rather than the device, and the finding says so
instead of quietly carrying an address you chose not to record.

### The findings file — `findings.jsonl`

**Off by default.** When `detection.findings_file` is set, every finding is
*also* written as newline-delimited JSON for a log shipper to collect.

That is a second copy of browsing-history-derived data, in a place designed to
be forwarded off the box. It is off by default for exactly that reason: sending
it to a SIEM should be a decision somebody makes, not something that happens
because a config file had a sensible-looking default. The file is written 0640
and rotated in place.

Whatever consumes it inherits the retention question. Your SIEM's retention
policy, not `detection.retention_days`, governs the copy it holds.

### The first-seen domain index — `first_seen_domains`

One row per registered domain this installation has ever been asked about.
This is the one table that **deliberately outlives your query-log retention**,
so it deserves reading carefully.

| Field | Example | Notes |
|---|---|---|
| `domain` | `example.com` | The registered domain (eTLD+1), never the full hostname |
| `first_seen` | `2026-02-11T09:03:41Z` | |
| `last_seen` | `2026-07-28T14:22:03Z` | |
| `query_count` | `4821` | How many times, installation-wide |

**No client IP, no network, no hostname.** It records that *this installation*
has resolved `example.com`, not who asked, not when any particular device asked,
and not that anybody asked for `secret-project.example.com`. Deleting a device's
query-log rows does not leave a trace of it here, because there was never one to
leave — the table cannot answer "which domains did that laptop visit", and that
is a property of its shape rather than a policy on top of it.

What it does mean is that "this network has resolved `example.com` at some point
since February" survives a query-log prune. If that is more history than you
want to keep, `dns.first_seen.enabled: false` turns the table off, and nothing
else changes: the index observes only and cannot affect an answer.

Bounded at `dns.first_seen.max_rows` (100,000 by default) with the stalest
domains evicted first, so it does not grow without end.

### Decision records — `decisions`, `decision_evidence`

One row per **blocked** query, plus the evidence that decision cited. Off by
default; `log.decision_records: true` turns it on.

| Field | Example | Notes |
|---|---|---|
| `domain` | `evil.example` | |
| `client_ip`, `client_name` | `192.0.2.10`, `workstation-14` | Same attribution the query log holds |
| `policy_path` | `network:Office → policy:Standard → category:malware → BLOCK` | |
| `explanation` | `Blocked because URLhaus listed as malware.` | Stored as written, not regenerated |
| cited evidence | feed name, category, claim, role | |

It is the same **categories** of personal data as the query log, for a much
smaller number of events — blocks are a fraction of traffic. Its own window,
`log.decision_retention_days` (30 by default), pruned on the same hourly
schedule as everything else.

Worth knowing if you turned query logging off for privacy reasons: decision
records are a separate switch and stay off unless you turn them on. If you want
neither, leave both off.

### The audit log — `audit_log`

One row per **configuration change**, not per query. Who changed what, when,
from where, and what the value was before and after.

| Field | Example | Notes |
|---|---|---|
| `action` | `policy.update` | Closed set of dotted verbs |
| `actor`, `actor_kind` | `admin`, `session` — or a token's name and `token` | |
| `source` | `dashboard`, `api`, `config-reload`, `seed` | |
| `target_type`, `target_id` | `policy`, `p_3` | What was changed |
| `before_json`, `after_json` | `{"categories":["malware"]}` → `{"categories":["malware","phishing"]}` | Redacted before the write; see below |

**This one is about the operator, not about the people using the network.** It
records that somebody changed a policy at 14:02. It holds no domains, no client
addresses, and no query data — a device's browsing history cannot be
reconstructed from it, and erasing a device's query rows does not need to touch
it.

**Secrets are redacted before the row is written, not on the way out.** A
password change stores `set`. A cleared provider key stores `cleared`. Bcrypt
hashes, raw API tokens, provider keys and session material never reach the
table in the first place, which matters because an audit export is the single
most likely thing an operator hands to an auditor, an insurer, or a support
engineer.

Kept for `log.audit_retention_days` (90 by default) — deliberately longer than
the query log, because "what changed before this started?" is asked about
incidents nobody noticed for weeks. Zero keeps everything. The table grows per
edit, not per lookup, so it stays small either way.

### Configuration

Networks, policies, allow and block lists, feed settings, hashed API tokens, and
the bcrypt hash of the admin password. No plaintext secrets.

## What is never stored

- Response contents. DNS Daddy records *that* `example.com` was resolved, not
  what it resolved to.
- Anything about the traffic that follows a lookup. It sees the question, not
  the connection.
- Cached answers are in memory only and disappear on restart.
- Behavioural detection state. The detectors hold counters and bounded sets in
  memory for a few minutes at a time and never write them to disk; only the
  resulting findings are persisted.
- Any link between a device and a domain in the first-seen index. That table is
  domains and counts only — see above.
- Any secret in the audit log. Credentials are replaced with `set` or `cleared`
  at the point of writing, so there is no version of the row that ever held one.

## Turning it down

### Keep statistics, drop per-query rows

The best default for most SMEs. You keep dashboards, reports, and category
breakdowns; you stop holding a per-device browsing history.

```yaml
log:
  query_log: false
```

Or per policy — useful when the finance VLAN needs less logging than the guest
network:

*Policies → [policy] → Log individual queries* (off)

### Keep query rows, drop device attribution

You can still see which domains were requested and blocked, but not by whom.

```yaml
log:
  log_client_ip: false
```

### Shorten retention

```yaml
log:
  retention_days: 1     # per-query rows
  rollup_days: 90       # statistics
```

Pruning runs hourly and a minute after startup, so an install that has been off
for a while reclaims disk before it starts writing again.

### Delete what is already there

```bash
sudo systemctl stop dnsdaddy
sudo -u dnsdaddy sqlite3 /var/lib/dnsdaddy/dnsdaddy.db \
  "DELETE FROM query_log; VACUUM;"
sudo systemctl start dnsdaddy
```

For a single device, before deleting:

```sql
DELETE FROM query_log WHERE client_ip = '10.0.4.23';
```

### Turn off behavioural detection entirely

```yaml
detection:
  enabled: false
```

Nothing is analysed and no findings are stored. Blocking and query logging are
unaffected — detection is a separate, alert-only layer.

A middle setting keeps the detection but stores less of it:

```yaml
detection:
  min_severity: high     # only the strongest findings are kept
  retention_days: 7      # matching the query log
  findings_file: ""      # no second copy for a shipper
```

## Subject access and erasure

If someone asks what you hold about their device use, and you log client IPs
with an IP you can tie to a person:

```bash
# Everything for one device
curl -H "Authorization: Bearer dnsd_…" \
  'https://dns.example.co.uk/api/v1/queries?clientIp=10.0.4.23&limit=500'
```

Erasure is the SQL above. Note that `stats_hourly` counts are not
device-attributable and generally need not be deleted to satisfy an erasure
request — but confirm that reasoning against your own advice.

## Telling your staff

Whatever you configure, tell people. A one-paragraph addition to your
acceptable-use policy is usually enough, and it is far better than a discovery
during a grievance:

> Our network uses protective DNS filtering to block malicious and fraudulent
> websites. Records of the domains requested from company devices are retained
> for N days for security purposes and are reviewed only when investigating a
> security incident. We do not monitor individual browsing for performance or
> disciplinary purposes.

Make that statement true, then keep it true.

## Compliance notes

**Cyber Essentials.** Protective DNS supports several controls, particularly
malware protection and boundary firewalls. The Markdown report
(`/api/v1/reports/summary?format=markdown`) is written to be attachable to an
assessment.

**ISO 27001.** Relevant to A.8.20 (network security), A.8.21 (network services
security), and A.8.7 (protection against malware). The report also serves as
evidence of ongoing monitoring.

**Cyber insurance.** Insurers increasingly ask whether protective DNS is
deployed. "Yes, self-hosted, with N days of query retention and monthly
reporting" is a stronger answer than a product name.

**Data residency.** Self-hosted, your data is wherever your server is. If you
need UK or EU residency, put the VPS in a UK or EU region. There is no other
copy.

## Reporting a privacy problem

If you find a bug that exposes query data beyond what this document describes —
a log leaking domains, an unauthenticated endpoint returning query rows — treat
it as a security issue: [SECURITY.md](../SECURITY.md).
