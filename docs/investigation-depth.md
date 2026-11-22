# Investigation Depth (Phase 4)

DNS Daddy already stores decisions and window-scoped activity. This pass adds
the missing durable investigation foundations: a registered-domain first-seen
index, extended decision fields, confidence-labelled device identity, and
opt-in answer telemetry.

## Registered-domain first-seen index

`domain_first_seen` holds one row per eTLD+1:

| Field | Meaning |
| --- | --- |
| `registeredDomain` | Public-suffix registered domain |
| `firstSeen` / `lastSeen` | First and most recent observation |
| `queryCount` | How many questions contributed |

The index is **independent of query-log retention length**. Pruning the log
does not erase recorded first-seen history. It still honours the same admission
decision as the query log: when `log.query_log` is false or the matched policy
disables `logQueries`, no observation is written. The recorder can also drop
observations when its queue is full, so a missing row is not proof that a
domain was never resolved — only that no observation was successfully recorded.
No client addresses are stored. Names without a registered domain (single
labels, public suffixes, private namespaces such as `.local`) are skipped.

Surfaced on domain Investigate as `firstSeen`, and controlled by
`log.first_seen_index` (default on).

**What this is not:** WHOIS registration age, threat intelligence, or proof a
domain is new on the Internet.

## Extended decision records

New decision rows also store:

- `blockMode` — response mode used for the block
- `feedId` / `feedName` — feed that listed the domain (category rules)

These are captured at decision time so a later policy or feed rename cannot
rewrite the historical record. Evidence snapshots remain the source of truth
for cited claims.

## Device identity

`GET /api/v1/investigate/client/{ip}` returns `subject.identity`:

| Confidence | Meaning |
| --- | --- |
| `unknown` | No operator-assigned name — a valid result |
| `operator` | Name set by an operator (`source: manual`) |

No active discovery, MAC-OUI inference, ARP/NDP, or automatic lease/PTR naming
is performed. Optional lease-file / reverse-DNS input remains future work.

## Opt-in answer telemetry

With `log.answer_telemetry: true`, query-log rows may carry:

- `answer.addrCount` — unique A/AAAA addresses in the answer
- `answer.addrSha256` — SHA-256 of sorted unique address strings
- `answer.minTtl` — lowest TTL among those records

TXT and other payloads are never collected. Full address lists and TXT contents
would require a separate explicit setting and privacy review.

## See also

[decision-records.md](decision-records.md), [privacy.md](privacy.md),
[threat-hunting/README.md](threat-hunting/README.md), [roadmap.md](roadmap.md).
