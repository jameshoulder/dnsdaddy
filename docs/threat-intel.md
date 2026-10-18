# Where the blocking comes from

This document describes the built-in and operator-defined blocklist feeds.
Matching happens locally, and the shipped feed catalogue contains no DNS
Daddy-operated service. Optional external API reputation is configured
separately under [External APIs](external-apis.md). Local policy and Daddybound
observations have their own decision evidence.

The definitive list is
[`internal/catalog/catalog.go`](../internal/catalog/catalog.go). This document
explains what those feeds are and what to do when one of them is wrong.

---

## Default feeds

Enabled on a fresh install:

| Feed | Category | Source |
|---|---|---|
| abuse.ch URLhaus | malware | `urlhaus.abuse.ch/downloads/hostfile/` |
| HaGeZi Threat Intelligence (mini) | malware | `github.com/hagezi/dns-blocklists` |
| Phishing Army (extended) | phishing | `phishing.army` |
| The Block List Project — Phishing | phishing | `blocklistproject.github.io` |
| The Block List Project — Malware & C2 | c2 | `blocklistproject.github.io` |
| CoinBlockerLists | cryptomining | `github.com/ZeroDot1/CoinBlockerLists` |

Shipped but **disabled** — enable them deliberately:

| Feed | Category | Why it is off |
|---|---|---|
| Newly registered domains (30 day) | newly-registered | High volume and a real false-positive rate. Genuinely useful against phishing, but it will block a supplier's brand-new site. |
| StevenBlack unified hosts | ads | Ad blocking is a preference, not a security control. It also adds ~150,000 domains. |
| The Block List Project — Adult | adult | Content filtering is an HR decision, not a security one. |
| The Block List Project — Gambling | gambling | As above. |

A fresh install therefore blocks threats and nothing else. If a user complains
that a site is blocked on day one, it was on a malware, phishing, C2, or
cryptomining list.

## Why these sources

They share four properties that matter for something sitting in front of every
lookup on your network:

1. **Public and free.** No registration, no API key, no rate-limited free tier
   that changes terms later.
2. **Independently verifiable.** You can fetch the same URL and diff it.
   Nothing is transformed on the way to you.
3. **Actively maintained** with a visible update cadence, and a removal process.
4. **Security-focused.** URLhaus tracks live malware distribution; Phishing Army
   aggregates verified phishing. These are not general-purpose annoyance lists.

They are all third parties. We do not control what they list, and neither do
you — which is why the allow list exists and why it beats everything else.

There is no bundled first-party intelligence connector. Each optional API
provider is added and authenticated by the operator.

---

## Retired Threat Observatory connector

The dedicated Threat Observatory activation card and built-in feed are removed.
On upgrade, the original `dnsdaddy-observatory` built-in row is disabled before
feed scheduling and indexing. Its historical row/evidence is retained, but it
is omitted from the feed list and cannot be re-enabled or refreshed through
the management API. No automatic DNS Daddy-service request is made by this
connector. Ordinary operator-created feeds are not changed by this retirement.

For richer intelligence, add your own provider account under [External APIs](external-apis.md).
These requests use your credentials and require explicit sharing consent.

## Compatible JSON indicator feeds

The legacy format name `observatory` remains a parsing option for an
operator-owned JSON feed. It is a format identifier only; it does not connect
to a DNS Daddy service or enable a first-party feature. A custom feed can
contain an array of indicators, or a document with an `indicators` array:

```json
{
  "indicators": [
    {"value": "malicious.example", "type": "domain", "categories": ["malware", "c2"]},
    {"value": "phishing.example", "type": "domain", "categories": ["phishing"]}
  ]
}
```

Recognised domain indicators retain all mapped categories so the current
policy can choose which category applies. Unrecognised categories use the
feed's configured fallback. IPs and unsupported indicator types do not become
DNS block entries. A truncated or invalid JSON document is rejected; the last
valid cached copy remains available under the ordinary feed refresh rules.

Supply your HTTPS feed URL through the custom-feed form/API with
`format: "observatory"`. Local `file://` feeds still require confinement under
`feeds.local_feed_dir`. See `internal/blocklist/observatory.go` and its fixture
tests for the accepted fields; these compatibility names are retained so
existing custom feeds continue to parse.

## How a query is decided

In order, stopping at the first match:

1. **The policy's allow list.** Beats every blocklist, always. This is the
   escape hatch: an operator can clear a false positive without waiting for
   anyone else to correct anything.
2. **The policy's own block list.** Domains you added yourself.
3. **The threat-intelligence index**, filtered to the categories that policy
   enables.

Matching is by suffix, so blocking `evil.com` also blocks `login.evil.com`. It
is not substring matching: `notevil.com` is unaffected.

A domain can be listed under several categories at once — by two feeds that
disagree, or by one JSON indicator carrying both. **Every one of those
claims counts.** A policy blocks the domain if it enables any category claiming
it, so a malware-only policy and a C2-only policy both block a domain listed as
both, and neither operator needs to know about the other category.

The reason written to your query log names the category *your* policy enabled,
and the source names the feed that made that particular claim. When a policy
enables several of a domain's categories, the most severe one is reported, so
the reason is the one that matters.

A name listed only under categories you have not enabled does not shadow a
parent that you have: if `evil.com` is on a malware list, `login.evil.com` is
blocked by a malware-enabling policy even if it also turns up on an ad list.

## Refreshing

Feeds refresh every 12 hours by default (`feeds.refresh_interval`), and on
demand from **Threat feeds → Refresh now**.

Downloads are cached to disk under `<data_dir>/feeds/`. This matters more than
it sounds:

- A restart rebuilds the index from local files in a second or two. The
  resolver is protecting traffic before it makes a single HTTP request.
- A provider being down never leaves a booting server with an empty blocklist.
- Feed providers are not hammered on every restart.

`ETag` handling means an unchanged feed is not re-downloaded.

If a download fails, the previous cached copy stays in use and the error is
shown against that feed in the dashboard. One unreachable provider degrades one
category, not the whole blocklist.

A refresh bumps an internal generation counter, which invalidates the answer
cache. A newly listed domain stops resolving immediately rather than lingering
for the length of its TTL.

## False positives

They will happen. Public feeds occasionally list a shared CDN, a URL shortener,
or a legitimate site that was briefly compromised.

**Fix it in seconds:**

*Policies → [your policy] → Always allow* — add the domain, save. It applies on
the next query; the answer cache is purged so there is no TTL to wait out.

Or from the API:

```bash
curl -X POST -H "Authorization: Bearer dnsd_…" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"allow","domain":"supplier.example.com","note":"ticket 4412"}' \
  https://dns.example.co.uk/api/v1/policies/p_standard/rules
```

The `note` field is free text. Use it — in six months you will not remember why
a domain is on the list, and an unexplained allow-list entry is a small hole in
your own control.

**Then report it upstream** so everyone else benefits. Each project has its own
process; abuse.ch and The Block List Project both take issues on their trackers.

## Diagnosing a block

The query log records the exact feed that matched, in the `source` field:

```bash
curl -H "Authorization: Bearer dnsd_…" \
  'https://dns.example.co.uk/api/v1/queries?domain=example.com&action=blocked'
```

```json
{
  "domain": "login.example.com",
  "action": "blocked",
  "category": "phishing",
  "reason": "Domain is on a phishing list",
  "source": "Phishing Army (extended)",
  "clientName": "laptop-07"
}
```

That gives you everything needed to answer the user, evaluate whether the
listing is right, and go upstream if it is not.

## Adding your own feed

**Threat feeds → Add a custom feed.** Any URL serving one of:

- **hosts** — `0.0.0.0 evil.com`
- **domains** — one bare domain per line
- **adblock** — `||evil.com^`
- **auto** — sniffed per line, which handles mixed files
- **observatory** — compatible JSON indicators, described
  [above](#compatible-json-indicator-feeds). The non-line-based format,
  the only one whose entries carry their own categories, and the only one where
  an incomplete download is rejected rather than parsed as far as it goes.

A `file://` URL works too, for a list you generate yourself:

```yaml
url: "file:///var/lib/dnsdaddy/internal-deny.txt"
```

Built-in feeds can be enabled and disabled but their URL is managed by the
shipped catalog, so an upgrade can correct a source that has moved. Add a
custom feed if you want different content.

**Parsing is deliberately forgiving.** Third-party feeds contain junk, and one
malformed line must not cost you an entire category of protection. Unusable
lines are counted and skipped rather than aborting the load.

**Some entries are rejected on purpose:**

- Single-label entries like `com` or `localhost` — one of those in a feed would
  blackhole an enormous slice of the namespace.
- Bare IP addresses — there is no name to block.
- Hosts-file lines pointing at a real address (`192.168.1.10 fileserver`) —
  that is a name mapping, not a block, and treating it as one would blackhole
  an internal host.

## Memory

Roughly 165–215 bytes per unique domain, measured rather than estimated — about
80–105 MB for a 500,000-domain index. A domain claimed under more than one
category costs about 7 bytes more per claim; domains claimed once, which is
almost all of them, cost exactly what they always did. It is a range because the index stores the
names themselves, so a feed of long third-level names costs about a quarter more
per entry than a feed of short registrable ones. See
[architecture.md](architecture.md#an-exact-match-blocklist-index) for where
that goes and why it is larger than it needs to be.

Enabling the ads and adult feeds roughly doubles the index. On a 1 GB box that
is still fine, but if you are running 512 MB, enable them one at a time and
watch `dnsdaddy_blocklist_domains` and `dnsdaddy_memory_bytes`.

The index is an exact-match map rather than a Bloom filter or a hash-only set.
That costs more memory than the alternatives and buys a guarantee: there is no
possibility of a hash collision silently blocking a legitimate domain. One
unexplained block of a supplier's website costs more trust than the memory costs
money.

## Attribution

DNS Daddy redistributes nothing. It downloads these lists directly to your
server at runtime; they are not vendored into this repository. Each is governed
by its own licence and terms:

- [abuse.ch URLhaus](https://urlhaus.abuse.ch/) — CC0
- [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) — GPL-3.0
- [Phishing Army](https://phishing.army/) — CC BY-NC-SA 4.0
- [The Block List Project](https://blocklistproject.github.io/Lists/) — Unlicense
- [CoinBlockerLists](https://github.com/ZeroDot1/CoinBlockerLists) — GPL-3.0
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) — MIT

The retired first-party connector is not part of the shipped catalogue.

Note the non-commercial clause on Phishing Army. If you are building a
commercial service on DNS Daddy, review each licence and disable anything whose
terms you cannot meet.

These projects are maintained by volunteers doing unglamorous work that a lot
of security tooling quietly depends on. If you rely on them, consider
supporting them.

## Consistent index capacity and refresh outcomes

Feed ingestion uses one deterministic publication envelope at startup, first import
and refresh. With `feeds.import_limits.memory_bytes = M`, 32 MiB remains reserved
for parser/runtime overhead and each published index is limited to
`floor((M - 32 MiB) / 3)` accounting bytes. The other two shares allow the old index,
new candidate and per-feed parsing contribution to coexist. The old-index share
is reserved even on a cold start, so acceptance does not depend on whether an
index is already loaded. If a caller supplies an oversized old index, its actual
charge is retained rather than undercounted.

Each claim costs 512 bytes plus domain/category/feed-ID/feed-name lengths. Existing
byte, record, unique-domain, claim, temporary-storage and timeout limits also apply;
the first bound reached wins. This is conservative application accounting, not a
hard Go heap/RSS quota. GC lag, readers retaining older generations, maps, other
services and kernel I/O still need host headroom. See the Stage 5B security report.

This deliberately tightens cold-start acceptance compared with the earlier code,
which could load a cache too large to refresh safely. Before upgrading, preflight
a representative copy of the complete enabled corpus against these limits on the
intended platform. Do not assume a successfully loaded old cache will pass the new
policy. An over-budget cold load stops startup before listeners open, preserving the
existing fail-closed startup policy. Reduce
claims/feeds or approve an appropriately sized finite budget with measured host
headroom. Splitting one feed does not evade the aggregate published-index cap.
No data, cache or configured limit is silently deleted, increased or rewritten.

A validated download commits its cache and complete index once. It is not rebuilt
again after publication. Failed download/parse/capacity/cancellation/rename work
preserves the last successfully published index. A refresh cannot drop a previously
loaded enabled feed merely because its cache becomes unreadable or corrupt. Cold
cache loading still reports missing/corrupt independent feeds as not loaded; it does
not publish a partially parsed contribution from them.

Full refresh remains a sequence of per-feed commits, not one transaction spanning
all feeds. Some feeds can commit while others fail; the returned/logged outcome
reports failures/warnings and the number committed. `lastRefresh` advances only
when a whole refresh succeeds. Single-feed refresh does not claim a full refresh.
New data is not called rolled back after publication if directory sync or refresh
history fails: a `committed-warning` explicitly distinguishes that result from a
pre-commit error. Review such warnings; disk durability is not guaranteed by an
in-memory publication. SQLite, filesystem rename and the live index do not share
one transaction, and crash-consistent recovery across them is not claimed.

The authenticated feeds response includes `lastFeedOutcome` (or null), the latest
completed feed operation's feed ID, status, `committed` boolean and safe error when
present. It survives a history-write failure in process memory and is not persisted
across restarts. It describes one feed, not a whole batch. `loaded` and
`indexedDomains` describe current protection, while per-feed history describes
attempts. HTTP 202 means work was accepted, not that content has committed.

Cache reloads and refresh ingestion are serialized to bound overlapping builds;
DNS lookups continue reading immutable snapshots without the ingestion lock.
Cancellation is cooperative, including while waiting for another ingestion to
finish; a stalled filesystem can still delay completion or shutdown.
