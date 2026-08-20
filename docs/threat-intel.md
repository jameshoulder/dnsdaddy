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

When a domain appears on several feeds, the most severe category wins. A domain
on both a malware list and an ad list is reported as malware, so the reason in
your query log is the one that matters.

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

### How many sources agree

`source` names the feed that decided the block. It is not necessarily the only
feed that listed the name, because the first claim wins so that the block
reason is the most severe classification available.

To see all of them:

```bash
curl -H "Authorization: Bearer dnsd_…" \
  'https://dns.example.co.uk/api/v1/intelligence?domain=login.example.com'
```

```json
{
  "domain": "login.example.com",
  "matchedName": "example.com",
  "listed": true,
  "category": "phishing",
  "independentSources": 2,
  "sources": [
    { "feed": "Phishing Army (extended)", "category": "phishing", "deciding": true },
    { "feed": "abuse.ch URLhaus", "category": "malware", "deciding": false }
  ],
  "assessment": "Two independent feeds list this name, which is stronger evidence than any single list…"
}
```

Two things in that response matter when you are deciding whether to trust a
block:

- **`matchedName`** is the name that actually carries the listing. Here the
  listing is on `example.com`, so every name under it is blocked. A block you
  were about to dispute on `login.example.com` may be a listing on the parent.
- **`independentSources`** is corroboration. One feed is a lead; two
  independent feeds agreeing is materially stronger. Independence is the
  catch — several public lists republish each other, so read the feed names
  rather than trusting the count.

An unlisted name comes back `listed: false` with an assessment saying so. That
is an absence of evidence, not a clean bill of health: DNS Daddy knows only
what the feeds you have enabled contain.

## Adding your own feed

**Threat feeds → Add a custom feed.** Any URL serving one of:

- **hosts** — `0.0.0.0 evil.com`
- **domains** — one bare domain per line
- **adblock** — `||evil.com^`
- **auto** — sniffed per line, which handles mixed files

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

Roughly 72–120 bytes per unique domain, measured rather than estimated — about
36–60 MB for a 500,000-domain index. It is a range because the index stores the
names themselves, so a feed of long third-level names costs about two thirds
more per entry than a feed of short registrable ones. See
[architecture.md](architecture.md#an-exact-match-blocklist-index) for where
that goes.

**Size for a refresh, not for the steady state.** The replacement index is
built while the current one is still answering queries, so both exist at once
and peak memory is close to double. A limit that fits the steady state but not
the peak does not degrade gracefully — the container is OOM-killed mid-refresh.

Enabling the ads and adult feeds roughly doubles the index. If you are running
close to a memory limit, enable them one at a time and watch
`dnsdaddy_blocklist_domains` and `dnsdaddy_memory_bytes`.

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

Note the non-commercial clause on Phishing Army. If you are building a
commercial service on DNS Daddy, review each licence and disable anything whose
terms you cannot meet.

These projects are maintained by volunteers doing unglamorous work that a lot
of security tooling quietly depends on. If you rely on them, consider
supporting them.
