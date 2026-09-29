# Daddybound local traffic learning

DNS Daddy has a native, incremental statistical model for local DNS behaviour.
It fits parameters from observed traffic, persists those fitted parameters,
and compares later windows with each client's prior baseline. It runs entirely
in Go without an external machine-learning API, model download or cloud
training service.

**The model produces experimental investigation leads. It never blocks a DNS
answer.** Daddybound's native resolution and DNSSEC validation are separate:
DNSSEC establishes cryptographic validity; a statistical change in traffic
does not establish malicious intent. An immature or mistaken baseline must
not become a network outage.

## Default operation and privacy

`learning.enabled` defaults to `true`. Set it to `false` in YAML and restart to
disable this worker. Learning is independent of the six existing behavioural
heuristics, whose switch remains `detection.enabled`.

The DNS handler only forwards a sample when global query logging, client-IP
logging and that policy's query logging permit it. Suppressed samples increment
`observations.privacySkipped` without retaining the domain or identity. The
learner sees the final, attributed result of the query; it has no way to
rewrite that result.

Completed baselines persist in `daddybound-learning.json` within the configured
data directory. They contain attributed client keys, timestamps, counts,
means and variances. They do **not** contain raw queried domain names or client
display names. They are still sensitive behavioural metadata: the file is
restricted to mode `0600`. Runtime domain diversity uses bounded, keyed hashes
which are not saved. Changing a logging policy prevents new model ingestion;
it does not retroactively delete already retained history.

## What is learned

The unit of learning is a completed, fixed five-minute window for one attributed
client. Each accepted window has one vote regardless of its query volume.

| Feature | Measurement | Minimum standard deviation |
|---|---|---:|
| `log_query_rate` | `ln(1 + successful queries / window minutes)` | 0.25 |
| `mean_label_length` | Mean length of the longest label in each queried name | 2 characters |
| `mean_label_entropy` | Mean of the maximum Shannon label entropy in each name | 0.2 bits/character |
| `unique_domain_ratio` | Unique queried-name hashes / successful queries | 0.10 |
| `txt_ratio` | TXT queries / successful queries | 0.08 |
| `mean_label_count` | Mean number of labels per queried name | 0.40 |

“Successful” means unblocked `NOERROR`. Cached answers contribute because they
are still client behaviour. Entropy is length-sensitive and correlated with
label length; these are descriptive features, not independent proofs.

### Cold start

Scoring requires **at least 12 accepted windows**, **at least 20 successful
queries in each accepted window**, and **at least one hour between the first
window's start and latest accepted window's end**. A quiet client can take much
longer. Twelve windows of inadequate or excluded traffic do not make a model
ready. One ready client does not make every other client's model ready.

During warm-up, the model updates the mean and variance using Welford's online
recurrence. For each window feature `x`, previous mean `mu` and new count `n`:

```text
delta = x - mu
mu' = mu + delta / n
M2' = M2 + delta * (x - mu')
variance = M2' / (n - 1)     when n > 1
```

Before readiness, `score`, `z`, and the scoring baseline fields are `null`.
`state: learning` says a sample was accepted for learning; it does not imply
that the traffic was independently verified benign.

### Score before learning

Every later complete window is compared with **previous** fitted parameters
before any update. For each feature:

```text
sd_i = max(feature_floor_i, sqrt(variance_i))
z_i = abs(x_i - mean_i) / sd_i
distance = sum(min(12, z_i)) / 6
```

The anomaly distance ranges from 0 to 12. A finding requires distance at least
**2.5** and at least **two features with `z >= 3`**. The two features may be
correlated; this gate does not imply two independent sources of evidence.

The finding's existing `score` field is `distance / 12` so it remains in 0..1.
Its signal contributions sum to that normalised value. Evidence contains the
raw distance, threshold, measured feature values, prior means, standard
deviations, sample counts and exclusions. Neither score is a maliciousness
probability. `confidenceAvailable: false` and numeric `confidence: 0` explicitly
mark the existing finding field as uncalibrated/unknown, not a measured 0%
maliciousness estimate. UI consumers should show “Uncalibrated anomaly”.

### Adaptation and contamination limits

After warm-up, eligible non-anomalous windows update an exponentially weighted
mean and variance with `alpha = 0.05`. Each feature's update is clipped to twice
the previous standard deviation:

```text
delta = clamp(x - mean, -2 * sd, 2 * sd)
mean' = mean + alpha * delta
variance' = (1 - alpha) * (variance + alpha * delta * delta)
```

The weighting half-life is approximately **13.51 accepted windows**. This is
observation-weighted memory, not a promise that the whole model resets every
67 minutes. Excluded windows do not advance adaptation; there is no automatic
relearning of a repeatedly anomalous service.

Normal-baseline training excludes a whole window when it contains a policy
block, an unsuccessful response, a sample loss, a query/diversity limit, a
reported anomaly, or any feature more than six standard deviations from its
prior baseline. A partial window with queue loss or saturated bounds is not
assigned an anomaly score.

A visible bootstrap guard also quarantines mean label length at least 40 with
mean entropy at least 3.8 and unique ratio at least 0.75, or TXT ratio at least
0.8 with mean label length at least 24. These are conservative engineering
guards against obvious encoded-name bursts establishing “normal” on startup.
They can exclude legitimate traffic. They do not turn cold-start samples into
ground truth.

Unknown malicious traffic can still contaminate initial learning, an attacker
can move gradually, and legitimate deployments can produce large changes.
Clipping and quarantine limit influence; they do not provide adversarial
robustness. The checked-in evaluation includes false alerts and misses.

## Bounds, loss and persistence

| Resource | Default | Behaviour at the boundary |
|---|---:|---|
| Input queue | 2,048 observations | Drop immediately and count; DNS never waits |
| Attributed clients | 1,024 | Evict least recently active client; count eviction and pending-window loss |
| Queries in one window | 8,192 | Cap accumulation; report overflow and exclude the partial window |
| Unique domain hashes per window | 512 | Report saturation; exclude the partial window |
| Recent in-memory results | 100 | Keep the newest completed windows |
| Client idle lifetime | 24 hours | Expire stale baseline; next activity starts a fresh baseline |
| State file | 8 MiB | Reject oversized input/output |
| Checkpoint interval | 1 minute | Atomic replace after file and directory sync |
| Finding repeat cooldown | 30 minutes/client | Suppress repeated emissions and report the count |

The `Observe` seam performs no I/O and has a non-blocking bounded channel send.
Model work, state writes and finding storage happen in its worker. Slow storage
can cause input loss rather than delay DNS. Queue loss quarantines affected
open windows; counts are visible even if no finding is written. Finding write
errors are also reported separately.

State records `schemaVersion`, `algorithm`, `featureVersion` and a fingerprint
of training semantics. Load rejects incompatible versions/configurations,
invalid parameters, duplicate clients, oversized data, symlinks and broadly
readable files. It does not silently invent replacement parameters for corrupt
state. A load failure disables the optional learner while DNS continues. The
saved file is preserved; the API reports `enabled: true`, `available: false`,
`mode: unavailable` and an actionable error. It does not present a failed model
as an empty, freshly learning baseline. Detailed filesystem errors stay in
local logs. Restore a matching backup or deliberately archive/reset the state
while the process is stopped.

Only completed baselines are checkpointed. Open partial windows are discarded
at restart, including a clean restart; `windows.restartDiscarded` reports the
saved pending-window count. A crash can also lose completed updates since the
last successful checkpoint. Backup includes the model state and can request
`Checkpoint()` first. The SQLite snapshot and model file are not one global
transaction.

Runtime observation/window/emission counters reset at process start. Per-client
`baselineWindows`, `baselineQueries` and training timestamps survive a valid
reload. `persistence.loaded` and `lastSavedAt` make that distinction visible.

## API and investigation

All routes use the authenticated management API:

| Route | Purpose |
|---|---|
| `GET /api/v1/learning/status` | Worker state, algorithm, readiness, sample bounds, queue/loss counters, persistence health, recent results and limitations |
| `GET /api/v1/learning/clients?limit=100` | Current bounded model set, newest activity first; maximum returned limit 500 |
| `GET /api/v1/learning/clients?client=192.0.2.10` | One subject's fitted features, sample counts and readiness |

An unknown subject returns `found: false`, not an invented baseline. Client
keys can be an IP address, `network:<id>`, or `unattributed`; deployment privacy
gates determine which observations the daemon actually admits. A client list
reports `total`, `returned` and `truncated`; it is not a complete query export.

When startup failed, the client-list response has `available: false` and an
error instead of a claimed population count. A single-client response has
`found: null` because the saved subject is unknown until the model can load.
Consumers must gate baseline and counter cards on availability. Zero fields
in an unavailable status are not observations that traffic or model history
is absent.

Recent results have `state` equal to `learning`, `typical`, `anomaly`, `excluded`
or `insufficient`. “Typical” means near that client's prior baseline, not safe.
The `score` field is nullable. Every excluded result names its reasons and
publishes successful and total sampled query counts.

Findings use event type `local_behavior_anomaly`, detector `robust-ewma-v1`,
experimental maturity and low maximum severity. They use the existing finding
review/history workflow. Acknowledgement, resolution and false-positive labels
do not allow a domain, alter DNS policy or automatically train the model.

These GET routes do not initiate DNS queries, contact a provider, mutate model
parameters or resolve review labels. Provider API credentials and external
intelligence are a separate optional capability.

## Measured evaluation

See [the evaluation lab](../labs/evaluation/README.md) and its
[checked-in results](../labs/evaluation/RESULTS.md). The reproducible run uses
5,760 training queries and 3,840 chronologically held-out queries, a frozen
test model, a simple fixed lexical comparator, cold-start abstentions and a
separate online drift experiment. The dataset is author-constructed synthetic
traffic, with known limitations and explicit denominators. It is not a
real-world false-positive study or an independent security evaluation.

## Statistical references

- Welford, B. P. (1962), “Note on a Method for Calculating Corrected Sums of
  Squares and Products”, *Technometrics*, 4(3), pp. 419–420.
  [doi:10.1080/00401706.1962.10490022](https://doi.org/10.1080/00401706.1962.10490022).
  Basis for the stable warm-up mean/variance recurrence.
- NIST/SEMATECH, [EWMA Control Charts](https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc324.htm),
  accessed 29 September 2026. Basis for exponentially weighted adaptation and
  the requirement for a representative reference process. Our clipped
  multifeature residual score is an engineering extension; formal Gaussian
  control-chart false-alarm formulas are not claimed for DNS traffic.
