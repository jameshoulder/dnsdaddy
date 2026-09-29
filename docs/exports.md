# Complete, bounded exports

The authenticated management API exports retained queries, original decisions
and findings as newline-delimited JSON. Reads do not resolve domains, contact
providers, change configuration or train the local learner.

| Route | Record | Order | Default / maximum page size |
|---|---|---|---|
| `GET /api/v1/queries/export` | Original query-log fields plus its retained Daddybound observation, where available | Insertion ID ascending, including backdated events | 500 / 500 |
| `GET /api/v1/decisions/export` | Original decision and captured evidence, with evidence provenance | Time ascending, then ID ascending | 500 / 500 |
| `GET /api/v1/findings/export` | Complete detector document, including fields unknown to the current API build | Time ascending, then ID ascending | 1,000 / 1,000 |

These are bounded pages, not a single unbounded download. A full page is not
proof that collection is complete. Follow the `Link: <...>; rel="next"` header
until `X-Truncated: false`. The final page can contain exactly the requested
number of records and still be complete; the store checks one additional row
to distinguish it from a truncated page.

## Filters and time

All exports accept `hours` (default 24, 0 for all retained data, maximum 8,760),
`since` and `until` (RFC 3339 timestamps, inclusive to stored millisecond
precision), `limit` and `cursor`. An explicit `since` replaces the default
hours. Supplying both `since` and `hours` is rejected. Reversed or malformed
time bounds return 400.

| Dataset | Additional filters |
|---|---|
| Queries | `networkId`, `action`, `category`, substring `domain`, exact normalised `exactDomain`, `clientIp` or its `client` alias |
| Decisions | Exact normalised `domain`, `client`, `action` |
| Findings | `severity`, `type`, substring `domain`, `client`, `state` |

Client filters accept IP addresses, including IPv4-mapped IPv6 addresses. They
are normalised to the stored form. Review states are `new`, `acknowledged`,
`resolved` and `false_positive`. Review status is a filter, not a rewrite of the
original finding document.

The first export page freezes its time window and the table's insertion
boundary. Continuation cursors preserve both, so a long export does not lose
its oldest rows as a relative `hours` window advances. Records inserted after
that boundary, including backdated records, belong to a new export. A cursor
also identifies the dataset and filter query; changing filters or using a
finding cursor on a query export returns 400. Page size can change. Following
`Link` preserves the filters automatically.

Insertion boundaries use persistent monotonic counters, not `MAX(rowid)`.
Deleting the newest retained row cannot move a boundary backwards or admit a
later backdated row. Query IDs also continue past previously allocated IDs
after pruning and restart. The migration preserves existing record IDs and
evidence; it assigns retained decisions/findings an internal insertion position
once. This cannot reconstruct IDs that an older release had already reused
before the counter existed.

## Response headers

| Header | Meaning |
|---|---|
| `X-Export-Count` | Valid NDJSON lines actually present in this response |
| `X-Export-Scanned` | Stored records considered in this page |
| `X-Export-Skipped` | Corrupt stored JSON documents omitted from the stream; zero in a healthy export |
| `X-Truncated` | Whether another matching page remains |
| `X-Next-Cursor` | Opaque continuation token; absent on the final page |
| `Link` | Relative next-page URL with all filters preserved; absent on the final page |
| `X-Export-Since` | Frozen inclusive lower timestamp; absent for all retained history |
| `X-Export-Until` | Frozen inclusive upper timestamp |
| `X-Export-Snapshot` | Frozen insertion boundary; an implementation detail for checking page consistency |

Every finding document is compacted to one line without losing unknown
fields. A pretty-printed JSON document therefore does not break NDJSON.
Malformed stored documents never masquerade as successful exports: the skipped
count identifies them. A caller must check `X-Export-Skipped` on every page and
investigate any nonzero count. `X-Truncated: false` means no further page;
it does not waive a skipped-record warning.

## Retention, retries and continuous ingestion

The boundary is not a long-lived database transaction or a backup. Retention
can remove records between HTTP requests. Review-state filters are evaluated
against the current review on each page, so concurrent review changes can
change which rows match. For an immutable findings collection, omit `state`
and export the detector documents themselves. Do not run a collection across a
database restore or replacement; start a new export afterward.

Retrying a page is safe, but can return records already received. Deduplicate
using the original `id` within the same source installation. A later collection should use a fresh export with an
overlapping absolute time interval, then deduplicate again. A terminal export
cursor is not a durable change-feed checkpoint and does not promise exactly-once
delivery. For ongoing findings delivery, use the configured findings file or
the separately configured asynchronous delivery mechanism.

Query logs respect what was recorded. A disabled log or disabled client
attribution cannot be reconstructed by exporting; rollup statistics are a
different dataset. A query whose retained DNSSEC observation has expired keeps its original
recorded serving-path status and source, but its optional observation detail
will be absent. `dnssecSource` is `native`, `upstream`, or empty for a legacy
row whose source was not recorded; it is never inferred from the current mode.
An actual observation-store read failure fails the export request rather than
silently omitting all annotations.

## Historical evidence

New decision records include immutable evidence snapshots captured in the same
transaction as the decision. They survive feed refresh, deletion and evidence
expiry and are pruned with the original decision. Exports identify these as
`evidenceSource: recorded_snapshot`.

Older decisions retain their original explanations but may only have mutable
references. They explicitly return `evidenceSource: legacy_current_reference`
and `evidenceNote`. The upgrade does not pretend it can reconstruct historical
evidence that was never captured. See [decision-records.md](decision-records.md).

## Interactive continuation

`GET /api/v1/queries` returns a numeric `nextCursor` and
`GET /api/v1/decisions` returns a time/ID `nextCursor`. Their final values are
`0` and `""`, respectively. These list cursors are distinct from export tokens.
Use the same absolute `since`/`until`, exact domain and client filters to
continue a bounded investigation; the investigation response supplies its
window and decision cursor. Malformed cursors are rejected instead of silently
restarting a list.
