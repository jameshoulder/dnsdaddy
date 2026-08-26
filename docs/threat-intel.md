# Where the blocking comes from

Every blocking decision DNS Daddy makes traces back to a public, auditable
source. There is no proprietary intelligence, no scoring model you cannot
inspect, and nothing that phones home to us.

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
| DNS Daddy Threat Observatory | multiple | Ours, and the only feed here that is. Off by default so a stock install depends on nothing we operate. See [below](#the-dns-daddy-threat-observatory). |

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

The one exception is our own Threat Observatory, which is why it ships off.

---

## The DNS Daddy Threat Observatory

[threats.dnsdaddy.dev](https://threats.dnsdaddy.dev) is our own threat
intelligence platform. DNS Daddy can consume it as a feed like any other, and
the shipped catalog includes it — **disabled**.

### Why it is off by default

Every other source in this catalog is one you can `curl` yourself and diff
against what we parsed. That property is the whole argument for the way this
project sources its blocking, and a default that quietly reached back to a
DNS Daddy server would cost it for every install that never read this page.

So it is opt-in. A stock install blocks threats using nothing we operate. If
you want our intelligence as well, turn it on deliberately, knowing what it
means:

**Enabling it tells us your resolver exists.** Each refresh is an HTTPS request
from your server to ours, so we see your server's IP address, its User-Agent
(`dnsdaddy/<version>`), and roughly how often it refreshes. We do **not** see
your queries, your clients, or which indicators ever matched — the feed is a
file download, and matching happens entirely on your server. That is the whole
of the exposure, and it is the same exposure you already accept from abuse.ch
and everyone else in the table above.

If that trade is not one you want to make, leave it off. Nothing else changes.

### Turning it on

**Threats → DNS Daddy Threat Observatory → Enable Threat Observatory.** The
same card appears in the Threat intelligence panel on the Dashboard, so you do
not have to find the feeds page first.

One click does four things, in this order:

```text
enable the built-in Observatory feed
        ↓
save that choice           (an ordinary feed row; it survives a restart)
        ↓
refresh it immediately     (rather than waiting up to 12 hours for the scheduler)
        ↓
validate, cache, re-index  (the same path every other feed takes)
        ↓
report what actually happened
```

The card then shows one of three things, and the distinction between them is
the point:

| Card says | Means |
|---|---|
| **Active**, with a domain count and an update time | Its indicators are in the index answering queries. |
| **Attention**, with the age of the last good copy | The refresh failed. The previous copy is still indexed and still blocking. |
| **Not blocking** | It downloaded at some point, but that copy is not in the running blocklist — the cached file is missing or will not parse. |
| Enabled, not downloaded yet | It has never successfully downloaded. Nothing from this feed is being enforced. |

"Active" is decided by whether the feed is in the index right now (`loaded` on
the feed row), never by the download history alone. The two can disagree: a
feed whose cached file goes missing has a perfectly healthy `lastSuccessAt`, no
error, and blocks nothing at all after the next restart. Reporting that as
protection would be the worst thing this card could do, so it does not — and
that is also why enabling the Observatory today lands in the last row, since
the endpoint is not live yet.

Disable puts it back: that feed stops contributing, the index is rebuilt
without it, and every other feed and every policy is untouched. The built-in
row is disabled, never deleted.

The same thing over the API:

```bash
# enable
curl -X PATCH -H "Authorization: Bearer dnsd_…" \
  -H 'Content-Type: application/json' \
  -d '{"enabled":true}' \
  https://dns.example.co.uk/api/v1/feeds/dnsdaddy-observatory

# and download it now rather than at the next scheduled refresh
curl -X POST -H "Authorization: Bearer dnsd_…" \
  https://dns.example.co.uk/api/v1/feeds/dnsdaddy-observatory/refresh

# then read the outcome off the row: lastStatus, lastError, lastSuccessAt
curl -H "Authorization: Bearer dnsd_…" \
  https://dns.example.co.uk/api/v1/feeds
```

`POST /api/v1/feeds/{id}/refresh` is not Observatory-specific: it refreshes any
single feed, using the same download, validation, caching and index rebuild as
a full refresh. It exists so that switching a feed on can be verified in
seconds instead of after a download of every third-party list.

`loaded` says whether the feed is in the index serving traffic; `loadError`
says why not when it is not. `lastRefreshedAt` moves on every attempt;
`lastSuccessAt` moves only when a download produced content this server can
enforce. A feed that has been
failing since Tuesday has a recent `lastRefreshedAt` and a three-day-old
`lastSuccessAt`, and it is the second number that dates the intelligence
actually in the index.

Once enabled it refreshes on the same schedule as everything else, caches to
the same directory, and is disabled again the same way.

### What makes it different from the other feeds

Every other feed is a flat list filed under one category: everything on the
Phishing Army list is phishing. Observatory indicators carry **their own
categories**, so a single feed row contributes to malware, phishing, C2 and
cryptomining at once, and a policy that enables phishing but not cryptomining
gets exactly the indicators it asked for.

The block reason follows the indicator, so the query log reads the same as it
does for any other source:

```json
{
  "domain": "login.example.com",
  "action": "blocked",
  "category": "c2",
  "reason": "Domain is known command-and-control infrastructure",
  "source": "DNS Daddy Threat Observatory"
}
```

Two rules govern how an indicator is filed:

- **An indicator keeps every category it names.** A domain tagged both
  `malware` and `c2` is filed under both, so a malware-only policy blocks it
  *and* a C2-only policy blocks it. Neither operator has to know the other
  category exists. The query log names whichever category their policy actually
  enabled, so the reason always matches the box they ticked.
- **An unrecognised label falls back to the feed's own category**, malware.
  The Observatory lists a domain because it wants it blocked, and losing that
  to a vocabulary mismatch would be the wrong failure. The mapping from
  Observatory labels to DNS Daddy categories is in
  [`internal/catalog/observatory.go`](../internal/catalog/observatory.go) — a
  new label is a one-line change there.

**IP indicators are ignored.** There is no name for a resolver to block. The
same goes for URL and hash indicators; those belong to the richer endpoints
below, not to DNS filtering.

### What the Observatory does not decide

The Observatory decides what belongs in `feed.json`. Your policies decide what
gets blocked. There is no third mechanism and no per-feed filtering knob: an
indicator reaches the index, and from there the ordinary category machinery
applies, exactly as it does for URLhaus.

If you want only part of what the Observatory publishes, that is a question for
the feed URL rather than for DNS Daddy's configuration — add a custom feed
pointing at a filtered endpoint (say
`…/api/v1/feed.json?min_severity=high`, once the Observatory offers it) and
disable the built-in one. The indicator fields DNS Daddy does not act on —
`severity`, `family`, `last_seen` — are parsed past and ignored.

### The endpoint contract

DNS Daddy needs exactly one endpoint. The other two are for humans and
integrations; nothing in the resolver depends on them.

#### `GET /api/v1/feed.json` — required

The blocking feed. Served as `application/json`, and it should honour `ETag` /
`If-None-Match` so an unchanged feed is not re-downloaded.

```json
{
  "generated_at": "2026-08-26T09:15:00Z",
  "source": "dnsdaddy-threat-observatory",
  "indicators": [
    {
      "value": "example.bad",
      "type": "domain",
      "severity": "critical",
      "categories": ["c2", "malware"],
      "family": "qakbot",
      "last_seen": "2026-08-26T09:10:00Z"
    }
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `generated_at` | no | RFC 3339. Logged on each rebuild; nothing depends on it. |
| `source` | no | Logged, not trusted. TLS is what says who served the file. |
| `indicators[].value` | **yes** | The domain. `domain` is accepted as an alias. |
| `indicators[].type` | no | `domain`, `hostname`, `host`, `fqdn`, or absent. Anything else (`ip`, `url`, `hash`) is skipped. |
| `indicators[].severity` | no | Parsed past and ignored: what gets blocked is a policy question, not a feed one. |
| `indicators[].categories` | no | Array of labels. A bare string is accepted, as is a singular `category` field. |
| `indicators[].family` | no | Free text, e.g. a malware family. Ignored for blocking. |
| `indicators[].last_seen` | no | Not used for blocking. |

**Individual indicators are parsed forgivingly; the document is not.**

Unknown top-level fields are skipped, so the Observatory can add metadata
without every deployed resolver rejecting the file, and a malformed indicator
costs that indicator rather than the feed.

A response that is not a complete, well-formed feed document is **refused
before it replaces anything**. This matters more than it sounds: a feed download is
replacing a dataset that is currently blocking traffic, and a body that stops
halfway is not a smaller dataset — it is thousands of malicious domains
silently becoming resolvable again. So a truncated body, an HTML error page
served with status 200, or a JSON document that parses perfectly and simply is
not a feed — `{"error":"rate limited"}`, or an `indicators` field that is not an
array — is rejected; the previously cached copy stays in use; the error is
shown against that one feed in the dashboard; and every other feed carries on.
It is the same behaviour as a provider being unreachable, because it is the
same kind of failure.

The check is the parser run with nothing to emit to, rather than a separate
validator, so the two cannot disagree about what a feed is. A validator that
waved through a document the loader then refused would produce the worst
outcome available: the good cache replaced, the refresh recorded as a success,
and the feed silently contributing nothing.

It is a streaming pass over the downloaded file, made before the atomic
rename that installs it as the cache, and repeated when a cached file is loaded
so a copy damaged on disk cannot half-populate the index either. `file://`
feeds go through exactly the same gate. Feeds are
streamed rather than buffered, and `feeds.max_feed_bytes` caps the download
like any other.

There is one thing this cannot catch: a feed that is complete and valid but
suddenly much smaller than last time is accepted, because there is no way to
tell a shrinking feed from a cleaned-up one. That is true of every feed format,
not just this one.

#### `GET /api/v1/indicators?hours=24&limit=…` — optional

Recent indicators with fuller context, for a dashboard or a hunt. Not consumed
by the resolver.

#### `GET /api/v1/lookup?q=…` — optional

Single-indicator lookup, for investigating a domain that showed up in a query
log. Not consumed by the resolver.

> **Status.** As of this writing the Observatory serves its web UI but not yet
> the JSON API above. The client is implemented and tested against that
> contract; until the endpoint is live, enabling the feed records an HTTP 404
> against it in the dashboard and changes nothing else — a feed that fails to
> download never disturbs the rest of the index. That is exactly why it ships
> disabled.

### Mirroring it yourself

The `observatory` format is not reserved for our URL. If you generate
Observatory-shaped JSON from your own intelligence, point a custom feed at it:

```bash
curl -X POST -H "Authorization: Bearer dnsd_…" \
  -H 'Content-Type: application/json' \
  -d '{"name":"House intel","url":"https://intel.example.co.uk/feed.json","format":"observatory"}' \
  https://dns.example.co.uk/api/v1/feeds
```

A `file://` URL works too, subject to `feeds.local_feed_dir`. The feed's
configured category becomes the fallback for indicators whose labels DNS Daddy
does not recognise.

---

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
disagree, or by one Observatory indicator carrying both. **Every one of those
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
- **observatory** — DNS Daddy Threat Observatory JSON, described
  [above](#the-dns-daddy-threat-observatory). The only non-line-based format,
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

The DNS Daddy Threat Observatory is ours, is off unless you turn it on, and is
itself built on public abuse feeds.

Note the non-commercial clause on Phishing Army. If you are building a
commercial service on DNS Daddy, review each licence and disable anything whose
terms you cannot meet.

These projects are maintained by volunteers doing unglamorous work that a lot
of security tooling quietly depends on. If you rely on them, consider
supporting them.
