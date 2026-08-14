# Threat hunting with DNS telemetry

Practical hunts you can run against telemetry DNS Daddy actually produces.

Hunting is not alert triage. An alert says something already crossed a
threshold; a hunt starts from a hypothesis about adversary behaviour and goes
looking, including in the space below every threshold. The detectors in this
project are deliberately conservative — they have volume gates and multi-signal
requirements precisely so they do not cry wolf — and everything they let
through the gates is exactly where hunting lives.

**Every hunt on this page runs against data DNS Daddy stores today.** Where a
hunt needs something not yet available, it is marked and says what is missing.
A playbook you cannot execute is worse than no playbook.

## Before you start

**Query logging must be on** (`log.query_log: true`), and for client-scoped
hunts **device attribution too** (`log.log_client_ip: true`). Both default on.

**Watch your retention.** The default query-log retention is 7 days; findings
are kept 30. A hunt that needs a month of query history needs
`log.retention_days` raised first, and that is a disk and privacy decision, not
a free one.

**Get the data out.** The examples below use the API with `jq`, which needs
nothing installed on the server:

```bash
export DD=https://dns.example.co.uk
export TOKEN=dnsd_…        # Settings → API tokens
alias ddq='curl -sf -H "Authorization: Bearer $TOKEN"'
```

For heavier analysis, query SQLite directly on the server — it is one file, and
the schema is [`internal/store/schema.sql`](../../internal/store/schema.sql):

```bash
sqlite3 /var/lib/dnsdaddy/dnsdaddy.db
```

Read-only, and be aware you are querying a live database on a box sized for
1 GB of RAM. Copy it first if the query is heavy: `sqlite3 dnsdaddy.db ".backup /tmp/h.db"`.

---

## Hunt 1 — DNS tunnelling

**Hypothesis.** A compromised host is moving data over DNS at a rate below the
detector's volume gates, or through a domain on the exclusion list.

**Telemetry required.** Query log with client IPs. *Available.*

**Detection logic.** The `dns_tunnel` detector needs 30 queries and 15 distinct
subdomains in five minutes. A patient tunnel — one message every ten seconds —
never reaches that in a window. Aggregate over a longer period instead.

```sql
-- Clients with high subdomain cardinality under one parent, over 24 hours.
-- The detector's window is 5 minutes; this one is a day.
SELECT client_ip,
       -- crude eTLD+1: good enough for a hunt, wrong for .co.uk
       substr(qname, instr(qname, '.') + 1)      AS parent,
       COUNT(DISTINCT qname)                     AS distinct_names,
       COUNT(*)                                  AS queries,
       AVG(length(qname))                        AS mean_len,
       SUM(qtype IN ('TXT','NULL','CNAME','MX')) AS payload_types
FROM query_log
WHERE ts > (strftime('%s','now') - 86400) * 1000
GROUP BY client_ip, parent
HAVING distinct_names > 100
   AND mean_len > 60
ORDER BY distinct_names DESC
LIMIT 40;
```

**Investigation.**

1. Who owns the parent domain, and does the business have any relationship with
   them? This answers most of these immediately.
2. Are the names encoded, or structured? `img-00042-abcd.cdn.example` is a
   product; `mfzwizltoqyc4ylbmnqxgzjan52g.x.example` is not.
3. Is the parent domain on the exclusion list? If so you have found the
   residual risk in
   [detection/dns-tunnelling.md](../detection/dns-tunnelling.md), and the
   question is whether this is the vendor or somebody hiding behind them.
4. Check the domain's registration date and nameservers. A tunnel needs the
   attacker to run authoritative DNS.
5. Go to the endpoint. A tunnel needs a process holding it open.

**False positives.** Anti-spam and file-reputation lookups. CDN per-request
hostnames. Analytics SDKs encoding a device ID. Anything under `.arpa`.

**Escalation.** One host, one parent domain, encoded names, a recently
registered domain with self-hosted nameservers → treat as an incident. Preserve
the query log before it is pruned.

**Containment.** Block the parent domain by policy — effective on the next
query. Then work the endpoint, which is where it is actually solved.

**ATT&CK.** [T1071.004], [T1048.003] *(hypothesis until direction is
established)*, [T1132.001].

---

## Hunt 2 — NXDOMAIN bursts and DGA activity

**Hypothesis.** A host is working through a generated domain list looking for
its command-and-control rendezvous point.

**Telemetry required.** Query log with client IPs and actions. *Available.*

```sql
-- Clients with a high failure rate spread across many domains.
-- Policy blocks are excluded: DNS Daddy answers those NXDOMAIN itself.
SELECT client_ip,
       COUNT(*)                                                    AS failures,
       COUNT(DISTINCT substr(qname, instr(qname, '.') + 1))        AS domains,
       MIN(datetime(ts/1000,'unixepoch'))                          AS first_seen,
       MAX(datetime(ts/1000,'unixepoch'))                          AS last_seen
FROM query_log
WHERE action = 'error'
  AND ts > (strftime('%s','now') - 86400) * 1000
GROUP BY client_ip
HAVING failures > 200 AND domains > 50
ORDER BY failures DESC;
```

Then look at the names themselves, which is what actually decides it:

```bash
ddq "$DD/api/v1/queries?clientIp=10.0.4.23&action=error&limit=200" \
  | jq -r '.queries[].domain' | sort -u | head -60
```

**Investigation.**

1. **Read the names.** This is the whole hunt. Generated names look nothing
   like typos, and typos look nothing like a stale search suffix.
2. Do they share a length and character-set fingerprint? Generators are
   consistent, and that consistency is often more recognisable than the
   randomness.
3. Did any of them *resolve*? That one is the live rendezvous point. Check its
   registration date — usually days old.
4. Is the pattern periodic? Date-seeded algorithms restart on a schedule.
5. Do other hosts on the same subnet show it? Shared failures point at
   configuration; one host points at that host.

**False positives.** A stale DHCP search suffix (the classic — every short name
gets qualified against a domain that no longer exists). Captive-portal and
connectivity checks. A decommissioned internal service. Vulnerability scanners
and asset discovery, which enumerate by design.

**Escalation.** Random-looking names + high domain spread + almost all failing
+ one host → infected endpoint. The resolver sees the symptom.

**Containment.** Block any candidate that resolved; the ones that failed are
not worth blocking, since tomorrow's list is different by design. Isolate and
examine the host.

**ATT&CK.** [T1568.002] *(hypothesis for the burst alone; established when the
names are demonstrably algorithmic)*.

---

## Hunt 3 — DNS beaconing

**Hypothesis.** An implant is checking in on a fixed schedule.

**Telemetry required.** Query log timestamps with client IPs. *Available.*

**Note on cache.** DNS Daddy sees every query a client sends, including ones it
serves from its own cache, so client-side cadence is visible. But a client with
its *own* cache only re-queries at TTL expiry, which both hides fast beacons and
manufactures fake ones. The TTL comparison below is what separates them.

```sql
-- Names queried repeatedly by one client, with an interval regular enough
-- to be worth a look. Compute the coefficient of variation by hand from the
-- output, or use the detector's finding if it fired.
SELECT client_ip, qname,
       COUNT(*)                       AS hits,
       (MAX(ts) - MIN(ts)) / 1000     AS span_s,
       ((MAX(ts) - MIN(ts)) / 1000.0) / NULLIF(COUNT(*) - 1, 0) AS mean_interval_s
FROM query_log
WHERE ts > (strftime('%s','now') - 86400) * 1000
GROUP BY client_ip, qname
HAVING hits > 40 AND span_s > 7200
ORDER BY hits DESC
LIMIT 50;
```

**Investigation.**

1. What is the name, and who runs it? Most of these end here.
2. Does **every** device of this type show the same cadence? Fleet-wide
   regularity is a product; one host alone is worth explaining.
3. Compare the mean interval with the record's TTL. If they match, this is a
   cache refreshing and there is nothing here — the `dns_beaconing` detector
   suppresses exactly this case automatically.
4. Is the interval a round number? 60s and 300s suggest configuration; 47s and
   173s suggest something trying not to be round.
5. On the endpoint, identify the process.
6. When did the cadence start? A beacon that began the day after a phishing
   email is a different conversation from one that has run for two years.

**False positives.** Update checkers, telemetry agents, monitoring probes, NTP,
certificate status, push and presence services — all periodic by design. This
hunt has the highest false-positive rate on the page and its output is a list
to explain, not a list to act on.

**Escalation.** Unexplained name + one host + regular cadence + no software that
accounts for it → investigate the endpoint.

**Containment.** Do not block on cadence alone. There is a meaningful chance of
blocking your own monitoring.

**ATT&CK.** [T1071.004] *(hypothesis — periodicity alone does not establish
C2)*.

---

## Hunt 4 — Unusual TXT activity

**Hypothesis.** TXT records are being used to carry tasking or payloads.

**Telemetry required.** Query log with query types. *Available.*

```sql
SELECT client_ip,
       COUNT(*)                  AS txt_queries,
       COUNT(DISTINCT qname)     AS distinct_names
FROM query_log
WHERE qtype = 'TXT'
  AND ts > (strftime('%s','now') - 86400) * 1000
  -- Exclude the standard mail, certificate and verification lookups, or the
  -- mail server buries everything else.
  AND qname NOT LIKE '%\_dmarc.%'      ESCAPE '\'
  AND qname NOT LIKE '%\_domainkey.%'  ESCAPE '\'
  AND qname NOT LIKE '%\_acme-challenge.%' ESCAPE '\'
  AND qname NOT LIKE '%\_mta-sts.%'    ESCAPE '\'
GROUP BY client_ip
HAVING txt_queries > 50
ORDER BY txt_queries DESC;
```

**Investigation.**

1. Is the client a mail server or mail gateway? If so the question is which
   selectors to exclude, not whether to alert.
2. Do the names repeat, or is each one new? Policy lookups repeat a handful of
   names; data transfer does not.
3. **Query the names yourself and read the records.** This is a TXT record —
   the contents are right there, and base64 in a TXT record answers the
   question in one command.
4. Did `dns_tunnel` also fire for this client and parent domain?

**False positives.** Mail infrastructure with non-standard selectors. Licence
checks and anti-abuse services that distribute state over TXT. A bulk
domain-verification exercise during a migration.

**ATT&CK.** [T1071.004] *(hypothesis)*.

---

## Hunt 5 — Newly observed domains

**Hypothesis.** Attacker infrastructure is new. A domain nobody on the network
has ever resolved, suddenly resolved by one host, is worth a look — especially
alongside anything else.

**Telemetry required.** Query log over a long enough baseline. *Available, but
read the caveat.*

```sql
-- Domains first seen in the last hour, given a 7-day baseline.
WITH recent AS (
  SELECT DISTINCT substr(qname, instr(qname,'.')+1) AS parent, client_ip
  FROM query_log
  WHERE ts > (strftime('%s','now') - 3600) * 1000
),
baseline AS (
  SELECT DISTINCT substr(qname, instr(qname,'.')+1) AS parent
  FROM query_log
  WHERE ts <= (strftime('%s','now') - 3600) * 1000
)
SELECT r.parent, r.client_ip
FROM recent r
LEFT JOIN baseline b ON b.parent = r.parent
WHERE b.parent IS NULL
ORDER BY r.parent;
```

**Caveat, and it is a real one.** "Never seen before" is only as good as your
retention. At the default 7 days, everything looks new after a week away, and
this hunt is noisy on any network with normal browsing. It works best scoped to
a server VLAN, where the set of domains a machine legitimately talks to is small
and stable — and it is close to useless pointed at a floor of laptops.

A first-seen index maintained independently of query-log retention would fix
this properly. It is not implemented; see [../roadmap.md](../roadmap.md).

**Investigation.** Registration date. Whether one host or many. Whether the
name resembles a brand you use. Whether any detector fired for the same host.

---

## Hunt 6 — Resolution failures and DNSSEC

**Hypothesis.** A domain you depend on has a broken chain of trust, or its
infrastructure is being interfered with.

**Telemetry required.** Query log with the `dnssec` column and the
`resolution_failure` finding. *Available.* Note this reports the **upstream's**
verdict — DNS Daddy does not validate locally. See
[../dns-security/dnssec.md](../dns-security/dnssec.md).

```bash
# Validation status distribution
ddq "$DD/api/v1/queries?limit=500" | jq -r '.queries[].dnssec' | sort | uniq -c

# Domains currently failing
ddq "$DD/api/v1/findings?type=resolution_failure_burst&detail=true" \
  | jq -r '.findings[] | "\(.domain)\t\(.summary)"'
```

**Investigation.**

1. Are *many* domains failing at once? Then it is your upstream or your
   network, not the domain. That is the tell.
2. Confirm externally: `dig +dnssec example.com @9.9.9.9`, then
   `dig +cd example.com @9.9.9.9`. If it fails normally and succeeds with
   `+cd`, DNSSEC is the cause.
3. `delv +rtrace example.com` names the broken link. [DNSViz](https://dnsviz.net/)
   draws it, which is the fastest way to show a domain owner what is wrong with
   theirs.
4. Was the domain `validated` in your own logs yesterday? A transition from
   validated to servfail is more interesting than a domain that never
   validated.

**False positives.** Expired signatures — by a distance the most common cause,
and someone else's operational mistake rather than an attack. Transient upstream
trouble. Your own egress problems.

**Escalation.** A domain that was validating, now fails, and whose NS records
have changed, is worth treating as possible infrastructure hijacking. A domain
whose signature expired at midnight is worth an email to its owner.

**ATT&CK.** None, deliberately. Infrastructure breakage is not an adversary
technique. See [../detection/mitre.md](../detection/mitre.md).

---

## Hunts that need telemetry DNS Daddy does not have

Listed so the gaps are visible rather than implied.

| Hunt | What is missing |
|---|---|
| **Response-content analysis** — payloads in TXT/CNAME answers | Answer records are not stored. Only the question, action and metadata are logged. |
| **Correlating DNS with connections** — a resolved domain never connected to, or a connection with no lookup (the DoH-bypass tell) | Needs flow or endpoint data. DNS Daddy sees DNS only. |
| **Long-baseline rarity scoring** — "this host has never asked for anything like this" | Needs a persistent first-seen index independent of query-log retention. |
| **Fast-flux detection** — one name resolving to constantly changing addresses | Answer addresses are not stored. |
| **Registration-age enrichment** | No WHOIS/RDAP lookup. The newly-registered *category* exists as a feed, which is not the same as per-domain age at query time. |

These are on the [roadmap](../roadmap.md) at varying distances. None of them
is claimed anywhere as a current capability.

## Turning a hunt into a detection

If a hunt keeps finding the same true positive, it should stop being a hunt.
[detection/README.md](../detection/README.md#extending-it) covers writing a
detector, and the house rules matter more than the code — particularly writing
the *benign* corpus first. If you cannot construct traffic that looks like your
new detection but is harmless, you do not yet understand its false positives,
and you are about to ship an alert somebody will mute.

[T1071.004]: https://attack.mitre.org/techniques/T1071/004/
[T1048.003]: https://attack.mitre.org/techniques/T1048/003/
[T1132.001]: https://attack.mitre.org/techniques/T1132/001/
[T1568.002]: https://attack.mitre.org/techniques/T1568/002/
