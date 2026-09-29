# Local learning evaluation

This lab exercises the fitted local anomaly model without external providers,
live DNS lookups, or malicious infrastructure. Every query uses a reserved
`.example` name and documentation-only client addresses.

From the repository root:

```sh
go run ./labs/evaluation
```

The command reads the checked-in datasets, trains on `data/training.ndjson`,
freezes that model, and evaluates `data/heldout.ndjson`. It writes `report.json`
and [RESULTS.md](RESULTS.md). Each held-out window gets its own copy of the
prior baseline, so one test window cannot train the model used by another.
Ground-truth labels are used only for metric accounting.

To reproduce the input bytes from their generator:

```sh
go run ./labs/evaluation -generate
```

`data/manifest.json` records SHA-256 checksums, seed conventions, the window
duration and label provenance. To evaluate from another directory, pass
`-dir <directory>`; the directory must contain the same `data` layout.

## What the corpora represent

The normal training profiles are an ordinary workstation, a mail server doing
TXT infrastructure lookups, a CDN-heavy client and an endpoint doing encoded
reputation lookups. These establish different local means and variances.

The held-out set includes ordinary follow-on traffic, a legitimate software
deployment, a legitimate new nonce service, new clients, encoded TXT and
address-query exfiltration hypotheses, failed-resolution DGA hypotheses,
already blocked queries, and activity deliberately shaped like ordinary
traffic. The last group is a limitation test: aggregate DNS shape cannot
establish intent when the observations overlap normal traffic.

The dataset contains **96 training windows / 5,760 queries** and **64 held-out
windows / 3,840 queries**. Train and test periods do not overlap. The generator
uses separate pseudorandom seeds for the two splits.

## Interpretation

The report publishes scored and unscored populations, TP/FP/TN/FN counts,
explicit denominators, and per-scenario outcomes. An unscored malicious window
is an abstention, not a true negative. Cold start scores are absent, not zero.

The comparison is a simple fixed lexical rule, plus the same model before any
learning. It does not benchmark the existing six heuristics against each other.
Those heuristics keep their own benign/malicious unit corpora under
`internal/detect`; this lab adds a held-out workflow for the new learner.

This is author-constructed synthetic evaluation. Labels record scenario
intent, not independently investigated network outcomes. It cannot establish
a real-world false-positive rate, justify autonomous blocking, or estimate a
maliciousness probability. The deliberate false alerts, misses and abstentions
are retained in the checked-in report.

## Subsequent evaluation

Keep thresholds fixed while evaluating a held-out set. If a result motivates
changing thresholds or features, treat that set as development data and create
a new test period before making a comparison. For representative deployment
evaluation, obtain appropriately authorised, privacy-preserving traffic from
different operating environments and investigate outcomes independently.
Keep the original evidence and review history. A review label alone does not
automatically train this model or change DNS policy.
