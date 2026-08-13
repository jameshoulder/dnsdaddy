# Sending findings to a SIEM

DNS Daddy's job here is to produce a clean, stable, documented event stream and
get out of the way. It does not ship a client for each vendor.

That is a deliberate choice. A newline-delimited JSON file is something every
log shipper in existence already understands — Wazuh, Filebeat, Fluent Bit,
Vector, Splunk's forwarder and rsyslog's `imfile` can all tail one with a few
lines of configuration. Six bespoke API clients would be six things to keep
working against other people's release schedules, for no capability the file
does not already provide. Integrations built to raise a feature count are the
ones that quietly break.

## Turning it on

```yaml
detection:
  findings_file: findings.jsonl     # relative paths land in data_dir
  findings_file_max_bytes: 33554432 # rotate at 32 MiB
  findings_file_keep: 3
```

or `DNSDADDY_DETECTION_FINDINGS_FILE=findings.jsonl`.

**Off by default**, because findings contain client IPs and the domains those
clients looked up. That is browsing history, and writing a second copy of it
somewhere a shipper will forward off the box is the operator's decision, not a
default. See [privacy.md](privacy.md).

The file is written 0640 and rotated in place (`findings.jsonl.1`, `.2`, `.3`).

## The event format

One complete finding per line. The full schema is
[`internal/api/openapi.yaml`](../internal/api/openapi.yaml) and the design is
explained in [detection/README.md](detection/README.md#the-finding-schema).

```json
{"schemaVersion":"1.0","id":"9f2c1a4b7e8d3f6a0b5c2e91","time":"2026-03-14T09:05:00Z","eventType":"dns_tunnel_suspected","severity":"high","confidence":0.87,"score":0.84,"client":{"ip":"192.168.1.42","name":"laptop-07","networkId":"n_office"},"domain":"example.com","qtype":"TXT","title":"Possible DNS tunnelling","summary":"laptop-07 (192.168.1.42) queried 187 distinct subdomains…","signals":[…],"evidence":{…},"mitre":[…],"detector":"dns_tunnel","maturity":"experimental"}
```

### Fields worth mapping

| Field | Map to | Note |
|---|---|---|
| `id` | event ID / dedup key | Random per finding. Use it for idempotent ingestion. |
| `time` | timestamp | RFC 3339, UTC. |
| `eventType` | rule name / signature ID | Stable identifiers. Renaming one would be a breaking change. |
| `severity` | severity | `info`, `low`, `medium`, `high`. |
| `confidence` | confidence / risk score | 0–1. **Not** the same as severity — see below. |
| `client.ip` | source IP | Empty when `log_client_ip` is off. |
| `domain` | destination / observable | Registered domain, or the exact name for beaconing. |
| `mitre[].id` | ATT&CK technique | **Filter on `hypothesis` first.** See below. |
| `maturity` | — | `experimental` on everything today. |

### Two things to get right

**Severity and confidence are different questions.** Severity is *how much
should this interrupt someone*; confidence is *how sure are we*. A
high-confidence advertising beacon is still informational. Mapping confidence
onto your severity field collapses the distinction and produces a noisy queue.

**Do not count hypothesised ATT&CK mappings as coverage.** Mappings with
`"hypothesis": true` describe what the behaviour would be *if* the finding is a
true positive — they are the thing to test during triage, not an established
fact. Counting them is how a coverage matrix ends up claiming detection of
exfiltration on the strength of a host resolving a lot of subdomains. Filter:

```
.mitre[] | select(.hypothesis != true) | .id
```

### Compatibility promise

Within schema version **1.x**, fields may be added but never removed or
repurposed. Parse defensively — a finding written by a newer build may carry
signals and evidence keys your rules do not know about, and that must not break
ingestion.

---

## Wazuh

Wazuh reads JSON log files natively. On the agent (or the manager, if DNS Daddy
runs there):

```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/dnsdaddy/findings.jsonl</location>
</localfile>
```

Every field becomes searchable as `data.<field>`. Rules:

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="dnsdaddy,">

  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <field name="schemaVersion">^1\.</field>
    <description>DNS Daddy: behavioural finding</description>
  </rule>

  <rule id="100201" level="10">
    <if_sid>100200</if_sid>
    <field name="severity">^high$</field>
    <description>DNS Daddy: $(eventType) on $(client.ip) — $(summary)</description>
    <mitre>
      <id>T1071.004</id>
    </mitre>
  </rule>

  <rule id="100202" level="7">
    <if_sid>100200</if_sid>
    <field name="severity">^medium$</field>
    <description>DNS Daddy: $(eventType) on $(client.ip)</description>
  </rule>

  <!-- Findings are alert-only. Nothing here reflects a block, and an active
       response that blocks on one is enforcing on an experimental heuristic —
       see docs/detection/README.md before doing that. -->
</group>
```

Note the ATT&CK ID is hard-coded per rule rather than taken from the event,
because Wazuh's `<mitre>` block is static. Only attach the established mapping
for the event type, not the hypothesised ones.

## Elastic

Filebeat:

```yaml
filebeat.inputs:
  - type: filestream
    id: dnsdaddy-findings
    paths: ["/var/lib/dnsdaddy/findings.jsonl"]
    parsers:
      - ndjson:
          target: dnsdaddy
          add_error_key: true
          overwrite_keys: true
```

Mapping onto ECS, if you use it:

```yaml
processors:
  - timestamp:
      field: dnsdaddy.time
      layouts: ["2006-01-02T15:04:05Z07:00"]
      target_field: "@timestamp"
  - rename:
      fields:
        - { from: "dnsdaddy.client.ip", to: "source.ip" }
        - { from: "dnsdaddy.domain",    to: "dns.question.registered_domain" }
        - { from: "dnsdaddy.qtype",     to: "dns.question.type" }
        - { from: "dnsdaddy.summary",   to: "message" }
        - { from: "dnsdaddy.eventType", to: "rule.name" }
        - { from: "dnsdaddy.severity",  to: "event.severity_name" }
      ignore_missing: true
  - add_fields:
      target: event
      fields: { kind: alert, category: network, type: info, module: dnsdaddy }
```

`event.type: info` rather than `denied`, because nothing was blocked.

## Splunk

`inputs.conf`:

```ini
[monitor:///var/lib/dnsdaddy/findings.jsonl]
sourcetype = dnsdaddy:finding
index      = security
```

`props.conf`:

```ini
[dnsdaddy:finding]
SHOULD_LINEMERGE     = false
LINE_BREAKER         = ([\r\n]+)
KV_MODE              = json
TIME_PREFIX          = "time":"
TIME_FORMAT          = %Y-%m-%dT%H:%M:%S.%3QZ
MAX_TIMESTAMP_LOOKAHEAD = 30
TRUNCATE             = 0
```

`TRUNCATE = 0` matters: a finding with many signals and a long evidence block
runs to several kilobytes, and the default truncation would cut the evidence
off — which is the part worth reading.

```
index=security sourcetype=dnsdaddy:finding severity=high
| table _time eventType client.ip domain confidence summary
| sort - _time
```

## Microsoft Sentinel

No supported native path for an arbitrary JSON file. The realistic options:

**Azure Monitor Agent** with a custom text log data collection rule, pointed at
the file, then parse with `parse_json()` in KQL. Straightforward, and the
approach most people already have plumbing for.

**Logs Ingestion API** — a small script POSTing lines to a DCR endpoint. More
work and more to keep running.

Once ingested:

```kusto
DnsDaddyFindings_CL
| extend f = parse_json(RawData)
| where f.severity in ("high", "medium")
| extend
    EventType  = tostring(f.eventType),
    ClientIP   = tostring(f.client.ip),
    Domain     = tostring(f.domain),
    Confidence = todouble(f.confidence),
    // Established mappings only — hypotheses are not coverage.
    Techniques = strcat_array(
        extract_all(@"""id"":""(T[0-9.]+)""",
                    tostring(f.mitre)), ",")
| project TimeGenerated, EventType, ClientIP, Domain, Confidence,
          Techniques, Summary = tostring(f.summary)
```

## Anything else — syslog

DNS Daddy does not speak syslog directly. `rsyslog` reads the file:

```
module(load="imfile")
input(type="imfile"
      File="/var/lib/dnsdaddy/findings.jsonl"
      Tag="dnsdaddy"
      Severity="warning"
      Facility="local4")
```

The same applies to Vector, Fluent Bit, Logstash and Promtail. If it can tail a
file, it can ingest this.

## Pulling instead of tailing

For a system that prefers polling, the API serves the same documents:

```bash
curl -H "Authorization: Bearer dnsd_…" \
  "https://dns.example.co.uk/api/v1/findings/export?hours=1&severity=medium"
```

NDJSON, **oldest first**, so a consumer appending to its own store keeps time
order. Deduplicate on `id`.

The file is better for continuous ingestion: it survives a restart of your
collector, has no request limit, and does not depend on the API being reachable.
The endpoint is better for backfilling and for a system that cannot reach the
filesystem.

## Also worth collecting

**Prometheus metrics** at `/metrics`. The one to alert on is
`dnsdaddy_detection_dropped_total` — observations the engine never saw because
its queue was full. That is a **detection gap**, not an absence of findings, and
it is the difference between "nothing happened" and "we stopped looking".

```
- alert: DNSDaddyDetectionGap
  expr: rate(dnsdaddy_detection_dropped_total[15m]) > 0
  annotations:
    summary: "DNS Daddy is dropping observations — detection coverage is incomplete"
```

**The query log** via `/api/v1/queries` for the raw telemetry behind a finding.
Considerably higher volume, and subject to its own retention.

## What is not implemented

Stated so it is not inferred from the presence of this page:

- **No webhook sink.** On the roadmap.
- **No native syslog output.** The file plus a shipper covers it.
- **No CEF or LEEF formatting.** JSON only.
- **No push to any vendor API.** By design, as above.
- **No mutual TLS or signing on the findings file.** It is a file on disk with
  0640 permissions; transport security is the shipper's job.
