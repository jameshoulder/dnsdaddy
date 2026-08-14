# Architecture

DNS Daddy is one Go binary and one SQLite file. This document explains how a
query moves through it, and why the load-bearing decisions were made the way
they were.

The constraint that shapes everything: it must run well on 1 GB of RAM and one
vCPU, while sitting in the latency path of every page load on the network.

---

## The life of a query

```
   client
     │  UDP/TCP :53      DoT :853       DoH :443/dns-query[/token]
     ▼
┌─────────────────────────────────────────────────────────────┐
│ dnsserver.Handler                                           │
│                                                             │
│  1. attribute the client   policy.MatchClient(addr)         │
│     (or the DoH token)     policy.MatchNetworkID(id)        │
│                                    │                        │
│  2. normalise the name     domainutil.Normalize             │
│                                    │                        │
│  3. decide                 policy.Evaluate ──────────┐      │
│                                    │                 │      │
│                         ┌──────────┴──────────┐      │      │
│                    blocked                  allowed  │      │
│                         │                     │      │      │
│  4a. synthesise    NXDOMAIN / 0.0.0.0 /       │      │      │
│      the answer     REFUSED                   │      │      │
│                                               ▼      │      │
│  4b. resolve                        resolver.Resolve │      │
│                                     ├── answer cache │      │
│                                     ├── single-flight│      │
│                                     └── upstream DoT │      │
│                                               │      │      │
│  5. record (never blocking)   querylog.Record ◄──────┘      │
│     observe (never blocking)  detect.Observe                │
└─────────────────────────────────────────────────────────────┘
                    │                        │
      buffered channel, batched writer   buffered channel
                    ▼                        ▼
     SQLite: query_log + hourly rollups   detection engine
                                             │
                                    enrich → detectors →
                                    score → Finding
                                             │
                                   SQLite: findings
                                   log · findings.jsonl
```

Steps 1–4 touch no disk and no database. Every decision is served from
in-memory snapshots that are swapped atomically when configuration changes.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/dnsdaddy` | Wiring, startup order, signal handling |
| `internal/config` | Defaults → YAML → environment, with validation |
| `internal/store` | SQLite: schema, configuration CRUD, query log, rollups |
| `internal/catalog` | The category list and the default feed catalogue |
| `internal/domainutil` | Name normalisation and allocation-free suffix walking |
| `internal/blocklist` | Feed download, caching, parsing, and the in-memory index |
| `internal/policy` | Client → network → policy matching, and the block decision |
| `internal/resolver` | Answer cache, request collapsing, upstream transports |
| `internal/querylog` | Buffered, batched writes so the hot path never waits on disk |
| `internal/detect` | Behavioural detection: enrichment, detectors, findings, sinks |
| `internal/dnsserver` | UDP/TCP/DoT listeners and the DoH endpoint |
| `internal/api` | REST API, auth, metrics, OpenAPI |
| `internal/web` | The embedded dashboard |

Dependencies point one way: `dnsserver` → `policy` → `blocklist`/`store`.
Nothing in the resolution path imports `api`.

`detect` sits beside `querylog` rather than inside the resolution path: the
handler hands it a value and moves on. Nothing `detect` produces can reach back
into a DNS answer, which is a property worth keeping deliberately rather than
by habit — see below.

## Decisions worth explaining

### Go, one static binary

The DNS hot path wants predictable latency and low memory. Go gives both, plus
cross-compilation to a Nanode from a laptop with no toolchain fuss. The SQLite
driver is `modernc.org/sqlite`, which is pure Go — so `CGO_ENABLED=0` produces a
static binary, the container can be tiny, and there is no libc version to match.

### SQLite, not a database server

On a 1 GB box, Postgres would cost more memory than the resolver. The write
pattern here — batched appends from a single process — is exactly what SQLite in
WAL mode is good at, and the whole deployment stays as one file you can back up
with `cp`.

### An exact-match blocklist index

`map[string]Entry`, consulted with a suffix walk. Roughly 55 bytes per domain:
about 30 MB for 500,000 domains.

A Bloom filter or a 64-bit-hash set would use a fraction of that. Both admit
false positives. A false positive here means silently blocking a legitimate
domain, and the person who has to explain that to their MD will not care that it
saved 25 MB. Exactness is worth the memory.

The suffix walk (`domainutil.Suffixes`) allocates nothing: it re-slices the
string rather than splitting it, so a blocklist miss — the overwhelmingly common
case — costs a handful of map lookups and no garbage.

### Atomic snapshot swaps

Both the blocklist index (`blocklist.Holder`) and the compiled policy set
(`policy.Engine`) are held in an `atomic.Pointer`. A feed refresh or a
configuration change builds a complete replacement and swaps it in.

Readers never take a lock, never see a half-populated structure, and never
observe a window where the resolver has no blocklist.

### Generation-counted cache invalidation

Cache entries record the blocklist generation they were created under. A feed
refresh bumps the generation, so every cached answer is treated as stale
immediately.

Without this, a domain that appears on a feed at 09:00 would keep resolving from
cache until its TTL expired — up to a day. Policy changes purge the cache
outright for the same reason: when someone un-blocks a supplier's website at
4pm, they expect it to work at 4pm.

### Logging that cannot slow down DNS

`querylog.Logger` hands events to a buffered channel; one goroutine batches them
and writes in a transaction. If the buffer fills, events are **dropped and
counted** (`dnsdaddy_querylog_dropped_total`) rather than blocking.

Losing a log line under extreme load is acceptable. Adding milliseconds to every
lookup on the network is not.

Batching also collapses work: a 256-event batch typically becomes a handful of
rollup upserts rather than 256 of them.

### Detection cannot touch the answer

`detect.Engine` is fed the same way the query log is: a plain value onto a
buffered channel, dropped and counted if the buffer is full. The call sits
*after* the response has been decided on every path, including the error and
blocked ones.

That ordering is the whole design. Behavioural heuristics infer intent from
traffic shape, they have false positives, and giving one a vote on an answer is
how a false positive becomes an outage. The detectors observe, score, explain
and alert; blocking stays with the policy engine, which acts on curated
intelligence.

The property is enforced by a test rather than by convention: 200 queries are
driven through a handler whose detection queue is full and whose only detector
panics if it is ever reached, asserting that resolution neither stalls nor
changes.

Detector state is bounded per key with O(1) approximate-LRU eviction —
sampling a handful of entries and evicting the oldest of those, rather than
scanning for the true oldest. Scanning would hand an attacker quadratic work
per query and turn the detector into the amplifier. Eviction means missed
detections rather than exhausted memory, and it is reported through
`dnsdaddy_detection_dropped_total` rather than hidden.

### Statistics that outlive the query log

`query_log` holds one row per question and is pruned aggressively (7 days by
default). `stats_hourly` and `blocked_domain_stats` hold aggregates and are kept
for 90 days.

This decouples two things that are usually forced together: how much browsing
history you retain, and how much reporting history you keep. You can drop
per-query retention to one day and still produce a 90-day report.

### Request collapsing

Identical concurrent questions share a single upstream flight. A machine
spraying the same lookup — which is precisely what a beaconing implant looks
like — costs one upstream query rather than hundreds.

### Feeds cached to disk

Every successful download is written to `<data_dir>/feeds/`. On startup the
index is rebuilt from those files *before* any listener opens.

A restart is therefore fast, works offline, and never leaves a booting server
answering queries with an empty blocklist. Downloads use a temp file and rename,
so an interrupted transfer cannot leave a truncated file that would parse as a
shorter, silently weaker list.

### Category priority

Feeds are indexed in category-priority order (malware → phishing → C2 →
cryptomining → … → ads), and the first claim on a domain wins. A domain on both
a malware list and an ad list is reported as malware, so the reason in the query
log is the one that matters operationally.

### DoH tokens for roaming

A laptop in a coffee shop has no IP you can allow-list. Each network carries a
random token that forms a DoH path; presenting it applies that network's policy
from anywhere.

An unknown token returns 404 rather than falling back to IP attribution.
Falling back would quietly apply the wrong policy, which is worse than a visible
error.

### Configuration in a file, not the database

Networks, policies, and feeds are database state — they change through the UI
and belong there. Listen addresses, upstreams, retention, and cache sizing live
in the config file, and the dashboard shows them read-only.

The result is that a deployment is reproducible from its configuration rather
than from accumulated clicks, which matters when you rebuild the box.

### No build step for the dashboard

Hand-written HTML, CSS, and JavaScript embedded with `go:embed`. `go build`
produces the whole product.

For a self-hosted security tool the audit story matters: there is no npm
dependency tree to review before pointing your network at it, and the page works
on a box with no outbound internet. The cost is writing the SVG charts by hand,
which for two series over 24 points is a fair trade against 200 kB of charting
library.

## Performance notes

Measured on the reference target (1 vCPU, 1 GB):

- Blocklist miss: a few map lookups, zero allocations
- Cache hit: served from memory, sub-millisecond
- Cache miss: dominated by upstream round-trip time
- Feed rebuild: a few seconds for ~500,000 domains, off the query path

```bash
make bench    # blocklist lookup, policy evaluation, suffix walking
```

## Extending it

**A new category** — add it to `catalog.Categories` and a feed that fills it.
The dashboard, API, and policy editor pick it up automatically.

**A new feed format** — add a case to `blocklist.parseLine` and a `Format`
constant. Keep it forgiving: skip bad lines, never abort a load.

**A new upstream transport** — add a scheme to `resolver.ParseUpstream` and an
`Exchange` path.

**A new API endpoint** — add the route in `api.Handler()`, the handler beside
its neighbours, and the schema to `internal/api/openapi.yaml`. The spec is
served to clients; letting it drift defeats the point.

**A new detector** — implement `detect.Detector` and register it in
`buildDetector`. The house rules — bound the state, gate on volume, require
more than one signal, publish the bands, and write the *benign* corpus first —
are in [detection/README.md](detection/README.md#extending-it), and they matter
more than the code.
