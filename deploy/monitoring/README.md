# Retention monitoring examples

Import `retention.rules.yml` into **your** Prometheus configuration and route its
alerts through your notification system. Shipping this file does not configure a
Prometheus server or send alerts. Run the executable examples before customising:

```sh
cd deploy/monitoring
promtool check rules retention.rules.yml
promtool test rules retention.test.yml
```

The sample job label is `dnsdaddy`. Adapt it to your scrape job and use authenticated
`/metrics` access over a suitably protected connection. Store bearer credentials in
Prometheus's own protected credential-file configuration, not inline in shared
rules. These examples assume `(job, instance)` uniquely identifies a target; add
cluster/tenant identity to the matching keys in federated environments.

## What is checked

- Missing retention metrics are detected for **each up instance**, not only when
  no instance exports them. Ten minutes avoids startup noise.
- No first success after ten minutes of uptime is pending for a further five
  minutes. An absent success timestamp is unknown, not healthy and not 1970.
- A failed latest sweep persists for five minutes before alerting. A succeeding
  sweep clears this state. Failed steps may still have removed some records.
- No completed sweep, or no fully successful sweep, for over two hours is pending
  for five minutes. The default sweep interval is hourly. Adjust these thresholds
  with any future scheduling changes; a delayed timestamp does not itself prove
  that expired rows exist.
- Scrape failure is a separate condition. A removed/misconfigured target which
  has no `up` series at all needs an external expected-target inventory; these
  rules cannot discover targets Prometheus does not know about.

Tests include startup, first-success absence, multiple instances, failed cleanup,
stalled cleanup, recovery, process restart and unavailable scrapes. Timestamps and
counters are process-local and reset on restart. Frequent restarts can continually
restart grace; alert on restart rates separately. Expiry-disabled records are not
promised erased by a successful sweep. Local metrics do not verify exported,
backup, webhook-recipient or remote SIEM copies.

A shared database problem may cause several steps to fail even though each has a
fresh timeout. Retention runs synchronously with context-aware operations; the
20-second per-step budget is cooperative, not a forceful kill or a filesystem
secure-erasure guarantee.

Reference: [Prometheus rule unit tests](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/).
