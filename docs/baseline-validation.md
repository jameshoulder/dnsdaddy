# Baseline validation

A pre-extension audit of DNS Daddy: does it behave as intended today, and is it
safe to build a detection engine on top of?

**Verdict: AMBER — one blocking defect found and fixed; everything else is
sound.**

The application resolves, filters, logs and explains correctly. Its test suite
passes, its hot path is clean, and its existing behavioural detection works
end-to-end. One defect made the *default Docker deployment* unable to survive
its own first feed refresh. That defect is fixed in this change and the fix is
verified by reproduction. With it applied the baseline is GREEN and safe to
extend.

- Date: 2026-08-20
- Commit audited: `089f43f`
- Method: static review, full test suite, live binary under load, and kernel
  cgroup reproduction of the container memory limit

---

## 1. The blocking defect: OOM-kill loop on the default deployment

### What happens

With the shipped `docker-compose.yml` and the shipped default feed set, the
container is OOM-killed by the kernel during its first blocklist refresh.
Because the service is declared `restart: always`, this is a restart loop: the
resolver comes up, serves DNS for a few seconds, dies mid-refresh, and repeats.
It never completes a refresh, so it never reaches a steady state.

### Why

Three facts combine:

1. **The default feed set is far larger than the documented sizing.** The
   published capacity figures are quoted against a 500,000-domain index. The
   feeds that ship *enabled* produce **2,878,143** domains. One of them,
   `botnet-c2` (The Block List Project — Malware & C2), contributes 2,530,361
   of those on its own — 88% of the index, from a 69 MB list. The parser is
   correct; the list really is that big.

2. **A refresh holds two indexes at once.** `internal/blocklist/manager.go`
   builds the replacement index to completion and only then swaps it into the
   `Holder`. The old index is live and serving queries throughout, so peak live
   heap during a refresh is close to *double* the steady state. This is correct
   for availability — there is no window without a blocklist — but it means
   sizing must be done against the peak, not the steady state.

3. **`Entry` was stored inline against every domain.** The index was
   `map[string]Entry`, and `Entry` is three strings — category, feed ID, feed
   name — so 48 bytes of string headers per domain before a single character of
   anything. Those three fields take as many distinct values as there are feeds
   (about ten), so the index spent most of its memory restating the same
   handful of strings a few million times.

Startup alone fitted. It was the refresh that did not.

### Reproduction

Run under a memory cgroup set to the same limit `docker-compose.yml` applies
(`mem_limit: 640m`), with the same `GOMEMLIMIT: 512MiB` the compose file sets:

```
Memory cgroup out of memory: Killed process 5004 (dnsdaddy)
  anon-rss:653132kB
oom-kill:constraint=CONSTRAINT_MEMCG,oom_memcg=/ddtest,task=dnsdaddy
```

The full matrix, each run taken to a completed feed refresh or to death:

| Build | `GOMEMLIMIT` | Outcome | cgroup peak |
|---|---|---|---|
| original | unset | **OOM-killed**, refresh never completed | — |
| original | 480 MiB | **OOM-killed**, refresh never completed | 640 MB |
| original | **512 MiB (shipped default)** | **OOM-killed**, refresh never completed | 640 MB |
| fixed | unset | survived, refresh completed | 640 MB (at the limit) |
| fixed | 480 MiB | survived, refresh completed | 535 MB |
| fixed | **512 MiB (shipped default)** | **survived, refresh completed** | **550 MB** |

`GOMEMLIMIT` alone does not rescue the original build, and that is the useful
part of the result: the memory is genuinely *live*, and a garbage collector
cannot collect data that is still referenced. Two indexes of 2.88M domains each
simply do not fit in 640 MB at the old cost per domain. The representation had
to change.

### The fix

Intern the `Entry` values. `Index` now holds a small table of distinct `Entry`
values and the map stores a `uint32` index into it, so the per-domain cost
drops from a 48-byte struct to 4 bytes.

This was already identified as the right optimisation in the repository — both
`docs/architecture.md` and the memory test named it as tracked future work. It
is done here because it stopped being an optimisation and became the fix for a
deployment-breaking defect.

Measured effect, same 2,878,143-domain feed set:

| | Before | After |
|---|---|---|
| Bytes/domain, short names | 167 | 72 |
| Bytes/domain, typical names | 183 | 88 |
| Bytes/domain, long names | 215 | 120 |
| RSS, unconstrained | 1,080 MB | **624 MB** |
| Survives default container limits | **No** | **Yes** |

**No protection was removed to achieve this.** All 2,878,143 domains are still
indexed, every default feed stays enabled, and blocking behaviour — including
the parent-suffix walk — is unchanged. Exact matching is preserved: this is not
a Bloom filter, and there is still no possibility of a hash collision silently
blocking a legitimate domain.

Lookup gained one slice index on the hot path. It is not measurable: see the
latency table in §6.

### What was deliberately *not* done

- **Feeds were not removed or disabled.** Cutting `botnet-c2` would have fixed
  the memory arithmetic in one line and quietly removed 88% of the malware
  blocklist. That is a product decision about protection posture, not a
  memory fix, and it is not one to make silently inside an audit.
- **The limits were not raised.** Raising `mem_limit` past 1 GB would abandon
  the constraint the project is designed around.
- **The double-index refresh was left alone.** It is the reason there is never
  a window without a blocklist, and it is worth its cost now that the cost is
  half what it was.

### Residual risk

The default install now peaks at 550 MB inside a 640 MB container — about 90 MB
of headroom, and that headroom shrinks as the upstream feeds grow. The feed set
is 5.7× the size the published figures are quoted against, and `botnet-c2` grows
over time with no bound that DNS Daddy controls. **This should be treated as
unfinished:** either the default feed set is brought back in line with the
documented 500,000-domain reference, or the refresh is changed so it does not
need to hold two full indexes. That is a decision for the maintainer, and it is
the single most important item in §9.

---

## 2. Architecture as actually built

Go 1.25, one static binary, ~23,000 lines including tests. SQLite (pure-Go
driver, so `CGO_ENABLED=0` and a scratch-ish runtime image). No Redis, no
message broker, no second service.

The query path, traced end to end in `internal/dnsserver/handler.go`:

```
UDP/TCP/DoT/DoH listener
  → client ACL              (refused sources never reach the log or an upstream)
  → single-question + class validation, name-length bound
  → policy match            (network → policy, compiled snapshot, atomic swap)
  → policy evaluate         (allow-list → block-list → threat-intel index)
  → [blocked] synthesise    → query log → detection observe → respond
  → [allowed] resolver      (cache → upstream, TCP fallback on truncation)
                            → query log → detection observe → respond
```

Two properties matter for what comes next, and both hold:

- **Nothing in the detection path can block, delay or fail a DNS answer.**
  `Handler.observe` hands a plain value to a buffered channel and returns; a
  full channel drops and counts rather than waiting. The engine runs detectors
  on its own goroutine.
- **No HTTP request sits in the synchronous DNS path.** Feed downloads are a
  background worker writing to a cache file and swapping an in-memory index.

Both are prerequisites for the detection work, and neither had to be created.

## 3. Tests

`go test ./...` — **all packages pass**, 279 test and fuzz functions across 12
packages with tests. `go test -race` on the packages touched by this change
(`blocklist`, `policy`, `dnsserver`) is clean.

No failures, no skips outside the deliberate `-short` guard on the memory test,
no flakes observed across repeated runs.

The suite is meaningful rather than decorative: it includes a fuzz target for
the suffix walk (with a committed corpus entry from a real finding), contract
tests for API responses, invariant tests for the detection engine, and the
memory budget test that gave this audit its starting point.

## 4. Docker validation

**Not fully validated: no Docker daemon is available in the audit
environment.** This is a real gap in coverage and is stated rather than papered
over.

What was validated instead:

- `Dockerfile` reviewed. Multi-stage; lab tooling built in a separate stage so
  the production image carries only the resolver; runs as uid 10001; drops to a
  non-root `WORKDIR` on a declared volume; healthcheck present.
- `docker-compose.yml` reviewed. `cap_drop: ALL`, `no-new-privileges:true`,
  bounded json-file logging, named volume, published-port note explaining the
  unprivileged 5353 binding.
- The **memory limits the compose file applies were reproduced exactly** using
  a kernel memory cgroup, which is the mechanism `mem_limit` uses. That is how
  §1 was found and how the fix was verified. It is the part of the Docker
  configuration most likely to bite, and it is now covered.

Still unverified and worth running before release: `docker compose build`,
container start/restart/persistence across `down`/`up`, and volume permissions.

## 5. DNS correctness

Validated against a live instance with real upstreams.

| Case | Result |
|---|---|
| `example.com` A, `github.com` A, `microsoft.com` A | NOERROR, answers present |
| `cloudflare.com` AAAA | NOERROR |
| `www.github.com` CNAME | NOERROR |
| `google.com` MX | NOERROR |
| `example.com` TXT | NOERROR |
| Nonexistent name | NXDOMAIN |
| Feed-listed domain | NXDOMAIN, blocked |
| Child of a feed-listed domain | NXDOMAIN, blocked (suffix walk) |
| Allow-list entry over a feed block | NOERROR — allow wins |
| Custom block rule | NXDOMAIN |

Two apparent failures were investigated and are **not defects**:

- **Large TXT answers returned SERVFAIL.** The upstream sets TC=1 and the
  correct response is to retry over TCP, which `internal/resolver/upstream.go`
  does. The audit sandbox blocks outbound TCP/53, so the fallback cannot
  complete. Returning SERVFAIL rather than a truncated answer is the right
  behaviour.
- **Default upstreams appeared dead.** They are DNS-over-TLS on port 853,
  which the sandbox also blocks. Re-testing with plain-UDP upstreams resolved
  everything. The secure-by-default choice is correct, and the resolver logs a
  warning when configured with unencrypted upstreams.

Feeds failing to download (two of six 404'd through the sandbox proxy) degraded
gracefully: the resolver logged, used cached copies where present, skipped the
rest, and kept serving. That is the fail-open behaviour the design calls for.

### Query-log accuracy

The stored explanation matches the actual decision, which is the claim the
product rests on:

| Query | action | reason | category | source |
|---|---|---|---|---|
| `0022a601.pphost.net` | blocked | Domain is on a malware distribution list | malware | abuse.ch URLhaus |
| `deep.sub.0022a601.pphost.net` | blocked | Domain is on a malware distribution list | malware | abuse.ch URLhaus |
| same, after allow-listing | allowed | Allowed by policy allow-list | | allow-list |

Policy precedence (allow → custom block → threat intel) behaves as documented,
and edits take effect immediately via the atomic snapshot swap.

### Detection engine

Exercised end-to-end with synthetic tunnelling traffic (400 high-entropy TXT
lookups under one parent). It produced three correlated findings — tunnelling,
TXT anomaly, and NXDOMAIN burst — with quantified, readable evidence:

> `127.0.0.1` queried 400 distinct subdomains of `tunnel-lab.example` across
> 400 lookups in 15s. Mean label entropy 4.60 bits/char, mean name length 124
> characters, 84% encoded-looking labels, 100% payload-capable record types,
> 96% NXDOMAIN.

The existing engine already does what this programme's philosophy asks for:
modular detectors, per-signal floor/ceiling/weight/contribution, confidence
separated from severity, MITRE mappings that carry a rationale and a
`hypothesis` flag, and an explicit `Enforces: false` on every detector.

## 6. Performance baseline

Measured on one shared vCPU against a warmed cache, so the figures are DNS
Daddy's own overhead rather than internet round-trip time. Open-loop generator:
a slow server shows up as latency, not as reduced offered load.

**Before the fix** (2,878,143 domains):

| Rate | Sent | Errors | p50 | p95 | p99 |
|---|---|---|---|---|---|
| 1/s | 10 | 0 | 0.47 ms | 0.54 ms | 0.54 ms |
| 10/s | 100 | 0 | 0.44 ms | 0.63 ms | 0.69 ms |
| 50/s | 500 | 0 | 0.39 ms | 0.56 ms | 0.99 ms |
| 100/s | 1000 | 0 | 0.40 ms | 0.56 ms | 0.69 ms |

**After the fix** (same feed set):

| Rate | Sent | Errors | p50 | p95 | p99 |
|---|---|---|---|---|---|
| 1/s | 10 | 0 | 0.43 ms | 0.80 ms | 0.80 ms |
| 10/s | 100 | 0 | 0.44 ms | 0.56 ms | 1.36 ms |
| 50/s | 500 | 0 | 0.40 ms | 0.54 ms | 0.72 ms |
| 100/s | 1000 | 0 | 0.36 ms | 0.52 ms | 0.68 ms |

No latency regression; the differences are run-to-run noise. CPU was 0.91 s
before and 0.96 s after for ~1,600 queries plus idle — roughly 2% of one core.
Zero errors at every rate. Cold (uncached) lookups were 2–30 ms, dominated by
upstream RTT.

**Resource summary**

| | Before | After |
|---|---|---|
| RSS, 2.88M domains, unconstrained | 1,080 MB | 624 MB |
| RSS, 348k domains | 142 MB | — |
| Peak inside a 640 MB container | OOM | 550 MB |
| Idle RSS before feeds | ~14 MB | ~14 MB |
| Disk, feed cache | 79 MB | 79 MB |

Headroom for the detection work is therefore about 90 MB inside the default
container, and considerably more on a box sized with the corrected figures in
§1.

## 7. Database review

Schema is sound for the workload. `query_log` is indexed on `ts`, on
`(action, ts)`, on `(network_id, ts)` and on `qname`; `findings` on `ts`,
severity, event type and client. Hourly and daily rollups survive query-log
pruning, so charts keep history under short retention. Retention is
configurable (`retention_days`, `rollup_days`) and enforced by a background
sweep, so growth is bounded by configuration rather than by disk.

Findings store their queryable fields as columns and the full document as JSON,
which is the right trade here: adding a signal changes the JSON and needs no
migration.

Two things to watch as detection grows, neither a defect today:

- `query_log.qname` is indexed but unbounded in cardinality; a first-seen or
  per-domain detector should key off its own compact table rather than adding
  more indexes here.
- Schema is applied idempotently at startup with no versioned migration
  history. That is fine while changes are additive and will need revisiting the
  first time a column has to change shape.

## 8. Security review

No Critical or High findings. The hot path is defensive in the places that
matter: the client ACL runs before any work and deliberately writes no log row
(so an unauthorised source cannot fill the disk), multi-question messages are
refused rather than partially evaluated, presentation-form name length is
bounded before the suffix walk, and ANY is answered per RFC 8482 rather than
forwarded.

| Severity | Finding |
|---|---|
| Medium | **Authenticated SSRF via feed URLs.** `validateFeedURL` accepts any `http`/`https` host, and the feed worker fetches it as the server. An authenticated admin can point a feed at `169.254.169.254` or an internal address; fetched content is parsed as a domain list, so response lines can surface in the UI as "blocked domains" — a slow read primitive. The HTTP client uses Go's default redirect policy, so a public URL that 302-redirects to a private address also reaches it. Mitigating: admin-only, and an admin already controls resolution. Recommended: deny link-local, loopback and private ranges by default with an opt-out, and re-validate after redirects. |
| Low | `file://` feeds are confined to `local_feed_dir` lexically *and* after symlink resolution, re-checked at download time rather than trusted from the stored row. Correct as written; noted because it is the kind of check that rots. |
| Info | Feed downloads are size-capped (`max_feed_bytes`, 128 MB default), written to a temp file and atomically renamed, so an interrupted download cannot leave a truncated list to be parsed as authoritative. |
| Info | No SQL injection: every query reviewed uses bound parameters, including the dynamically assembled `UPDATE` in `feeds.go`, which appends `col = ?` fragments and never interpolates values. |
| Info | No shell execution anywhere in the application. Cache filenames are built by mapping feed IDs through an allowlist of characters rather than trusting them. |
| Info | Container runs unprivileged with `cap_drop: ALL` and `no-new-privileges`. First-run password is generated, written 0600 to the data volume, and logged once. |

Dependencies are current and few: `miekg/dns`, `modernc.org/sqlite`,
`golang.org/x/crypto`, `golang.org/x/net`, `yaml.v3`.

## 9. Remaining risks

1. **The default feed set is 5.7× the documented reference size, and growing.**
   §1 bought roughly 90 MB of headroom inside the shipped container; it did not
   make the sizing right. Decide between trimming the defaults and removing the
   double-index refresh peak. **Highest-priority item.**
2. **Docker was not exercised end-to-end.** Build, restart and volume
   persistence remain unverified in this environment.
3. **Authenticated SSRF** (§8) is unfixed.
4. **No versioned migrations.** Additive changes are safe; the first
   destructive one will not be.
5. **Detection windows are wall-clock.** Findings depend on a 5-minute window;
   `window_scale` exists for labs and is explicitly not a production tuning
   knob. Worth keeping in mind when adding detectors — a test that passes only
   under a compressed window has not been tested.

## 10. Is it safe to extend?

**Yes, with the fix in §1 applied.**

The separation the detection work depends on already exists and is enforced by
the code rather than by convention: detection cannot block DNS, enrichment
cannot block DNS, and every detector already declares `Enforces: false`. The
finding model already carries per-signal evidence, confidence and weights. The
API, storage and UI already render findings.

What the audit changes about the plan: the memory budget is real and is the
binding constraint, not CPU. Latency has enormous headroom — sub-millisecond at
100 queries/second, about 2% of one core — while memory has roughly 90 MB of
headroom inside the shipped container limit. Any new detector should therefore
be judged on its *resident footprint per tracked key*, and anything that wants
a per-domain or per-client table needs a bounded size and a sweep from the
outset, not later.
