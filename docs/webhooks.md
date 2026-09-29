# Optional signed webhooks

DNS Daddy can deliver new findings and finding reviews to **one receiver you operate or explicitly trust**. Configure it in the External APIs page. Delivery starts disabled, requires your own signing secret and explicit sharing consent, and uses a durable, bounded outbox.

This is a generic signed JSON integration. A destination must accept this event format and verify its HMAC signature. Slack incoming-webhook payloads, Teams cards, OAuth, and vendor-specific webhook formats are not implemented by this receiver contract.

## Setup

1. Supply an HTTPS URL with a certificate trusted by the resolver host. The URL is readable configuration: do not put credentials in its path, user information or query string. URL query strings and user information are rejected.
2. Enter a separate random signing secret, at least 32 characters. Store the same secret in your receiver. It is encrypted by DNS Daddy and never returned through its API.
3. Choose event types, a request timeout, maximum attempts and queue capacity. Save disabled first.
4. Explicitly consent to **Test receiver**. This sends one synthetic `webhook.test` event to the saved endpoint, even when regular delivery is disabled. It contains no real finding or query data.
5. Enable delivery after acknowledging what the selected events disclose.

Destinations are public HTTPS services by default. The explicit internal-service option permits RFC 1918 and IPv6 ULA addresses, while retaining certificate verification. Loopback, link-local, metadata and special/reserved ranges remain blocked. Addresses are checked on every actual resolved connection; redirects and environment proxies are not used. There is no insecure TLS option.

## Event content

| Type | Includes |
|---|---|
| `finding.created` | Finding ID, occurrence time, detector/type, severity, confidence/score, domain, client IP, network ID, title and a bounded summary |
| `finding.reviewed` | Finding ID, review version, previous/new state, occurrence time, bounded review note and authenticated actor label |
| `webhook.test` | A test ID, time, fixed message and `synthetic: true` |

`finding.created` is the default selection. Review events disclose operator notes, so they require a separate selection. Enabling delivery does not backfill earlier events. Event payloads are small summaries, not complete exports of all evidence; the ID links back to the finding/investigation, and complete paginated exports are available separately.

An example finding event is:

```json
{
  "id": "finding.created:find_example",
  "type": "finding.created",
  "occurredAt": "2026-09-29T12:00:00.000Z",
  "data": {
    "findingId": "find_example",
    "eventType": "dns.beaconing",
    "severity": "medium",
    "confidence": 0.7,
    "score": 0.6,
    "domain": "example.test",
    "clientIp": "10.0.0.2",
    "networkId": "n_example",
    "detector": "beaconing",
    "title": "Repeated DNS interval",
    "summary": "Illustrative event, not a production observation."
  }
}
```

## Signature contract

Every POST includes:

```text
Content-Type: application/json
X-DNSDaddy-Event-ID: <same id as the body>
X-DNSDaddy-Timestamp: <Unix seconds when this attempt was signed>
X-DNSDaddy-Signature: sha256=<lowercase hex digest>
```

The digest is HMAC-SHA256 using the signing secret's UTF-8 bytes over:

```text
timestamp + "." + exact raw request-body bytes
```

Verify the **raw bytes before JSON parsing or reformatting**, use a constant-time digest comparison, and enforce a short timestamp tolerance appropriate to your clock synchronisation. Deduplicate accepted event IDs; the outbox offers at-least-once delivery. A retried attempt has the same event ID/body and a newly generated signing timestamp.

This Python function illustrates verification; request-size limits, HTTP handling, event storage and acknowledgements belong to your receiver:

```python
import hashlib
import hmac
import time


def verify_webhook(raw_body: bytes, headers, secret: str) -> bool:
    if len(raw_body) > 32768:
        return False
    timestamp = headers.get("X-DNSDaddy-Timestamp", "")
    supplied = headers.get("X-DNSDaddy-Signature", "")
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except (TypeError, ValueError):
        return False
    signed = timestamp.encode("ascii") + b"." + raw_body
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), signed, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, supplied)
```

After signature verification, confirm that the event-ID header matches the body and atomically deduplicate/store the event before acknowledging it. The five-minute tolerance above is an example receiver choice. Keep server clocks synchronised.

## Delivery, recovery and limits

The same SQLite transaction that inserts a finding or review history entry captures its event in `webhook_outbox` when delivery and that event type are enabled. If capacity is exhausted, the event is dropped and counted without discarding the finding itself. No network request runs on this write path or on the DNS answer path.

A single background worker makes requests. Defaults and accepted bounds are:

| Control | Default | Accepted range |
|---|---:|---:|
| Queue capacity | 500 | 1–1,000 pending events |
| Request timeout | 5,000 ms | 100–15,000 ms |
| Maximum attempts | 5 | 1–8 |
| Event body | Bounded summary | At most 32 KiB sent |
| Response body drain | Ignored | At most 16 KiB read |

HTTP 2xx is accepted as success. HTTP 408, 425, 429, 5xx and transport failures are retried within the configured attempt limit. Other 4xx and redirects are terminal failures. Backoff starts at two seconds and doubles with a five-minute cap. The implementation does not follow a receiver's redirects or treat its response body as instructions.

Each attempt and a 30-second lease are persisted before sending. After a crash, a pending attempt can be retried when its lease expires. A receiver may therefore see a duplicate if it accepted a request just before the sender stopped; deduplication is part of the receiver contract. This is bounded at-least-once delivery, not an exactly-once or lossless stream.

**Every saved webhook configuration change discards pending events and adds them to the dropped count.** This prevents payloads approved for an old destination/key/configuration from being forwarded under new settings. Disabling/removing the secret also stops future capture. An in-flight request is cancelled where possible, but data already accepted by a receiver cannot be recalled.

The API reports durable totals for queued, attempted, delivered, failed, dropped and retried events, current queue depth, and the last outcome/status/times. These totals survive restart. Connection tests remain separate from production event totals. Queue overflow, terminal failures, reconfiguration drops and receiver duplicates are operational limitations visible to the operator.

The signing secret is AES-256-GCM ciphertext in `webhook_config`, bound to the `webhook:default` identity and the same `secrets.key` keyring used for API-provider credentials. Backups need that key to restore delivery. Pending events and counters reside in SQLite; a recovery bundle is sensitive because it contains event data and key material. See [recovery](recovery.md).

## Management routes

All routes require authenticated management access and applicable CSRF protection:

| Method and path | Behaviour |
|---|---|
| `GET /api/v1/integrations/webhook` | Configuration and persisted delivery status, never the secret; no network |
| `PUT /api/v1/integrations/webhook` | Partial update of `enabled`, `url`, `eventTypes`, `allowPrivate`, `timeoutMs`, `maxAttempts`, `maxQueue`, and optional write-only `secret`; enabling/changing enabled delivery requires `consent: true` |
| `POST /api/v1/integrations/webhook/test` | `{ "consent": true }` sends the synthetic test |
| `DELETE /api/v1/integrations/webhook/secret` | Removes the signing secret, disables delivery and discards pending events |

Automated tests use in-process fixture transports only. They verify exact HMAC/body binding, encrypted identity binding, disabled defaults, no backfill, bounded overflow accounting, restart/lease recovery, bounded retries, redirect refusal, configuration-change drops and synthetic tests. They do not claim compatibility with any untested external service or receiver.
