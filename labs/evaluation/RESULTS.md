# Local learner: measured synthetic evaluation

Generated reproducibly by `go run ./labs/evaluation`. This is an offline engineering evaluation of `robust-ewma-v1`. It does not estimate a production false-positive rate.

## Population and split

- Training: **96 windows / 5760 queries** across four client profiles, ending 2026-09-01T02:00:00Z.
- Held out: **64 windows / 3840 queries**, starting 2026-09-01T03:00:00Z: **38 benign**, **26 malicious-labelled** windows.
- Windows span five minutes. Training labels are benign scenario intent. Held-out labels are used only for metric accounting.
- The held-out model is frozen: each test window sees a copy of the prior baseline; it cannot update the baseline used by another test window.
- Separate seeds are used for training and held-out traffic; the author wrote both the model and the generator, so this is not independent validation.

## Outcomes with denominators

| Model | Scored windows | TP | FP | TN | FN | Benign abstentions | Malicious abstentions |
|---|---:|---:|---:|---:|---:|---:|---:|
| Before any learning | 0 / 64 | 0 | 0 | 0 | 0 | 38 | 26 |
| Frozen fitted baseline | 50 / 64 | 8 | 4 | 30 | 8 | 4 | 10 |
| Fixed lexical reference rule | 56 / 64 | 14 | 16 | 22 | 4 | 0 | 8 |

For the fitted model:

- Recall among scored malicious-labelled windows: **8 / 16 = 0.5000**.
- Detections divided by **all** malicious-labelled windows, including abstentions: **8 / 26 = 0.3077**.
- False alerts divided by scored benign windows: **4 / 34 = 0.1176**.
- Precision among emitted synthetic alerts: **8 / 12 = 0.6667**.

An abstention is not a correct benign classification. Before training, no score is fabricated. Failed resolution, already blocked traffic and new clients are visible coverage limitations.

The reference rule alerts when mean maximum label length is at least 28 characters and mean maximum label entropy is at least 3.5 bits. It has no fitted client history. It is intentionally simple and is **not** a comparison with the application's six existing heuristic detectors.

## Scenario outcomes

| Scenario | Label | Windows | Scores available | Alerts |
|---|---|---:|---:|---:|
| already-policy-blocked | malicious | 4 | 0 | 0 |
| dga-failed-resolution | malicious | 4 | 0 | 0 |
| encoded-address-exfiltration | malicious | 4 | 4 | 0 |
| encoded-txt-exfiltration | malicious | 4 | 4 | 4 |
| low-and-slow-overlap | malicious | 4 | 4 | 0 |
| mail-host-txt-channel | malicious | 4 | 4 | 4 |
| new-client-exfiltration | malicious | 2 | 0 | 0 |
| new-client-routine | benign | 4 | 0 | 0 |
| new-legitimate-nonce-service | benign | 4 | 4 | 4 |
| routine-cdn | benign | 6 | 6 | 0 |
| routine-mail | benign | 6 | 6 | 0 |
| routine-telemetry | benign | 6 | 6 | 0 |
| routine-web | benign | 6 | 6 | 0 |
| software-deployment | benign | 6 | 6 | 0 |

## Does the model actually adapt?

A separate benign software-deployment stream is evaluated before each online update; it is not part of the frozen holdout.

```json
{
  "acceptedWindows": 24,
  "distanceAfter23Updates": 0.2746783622569431,
  "distanceBeforeAdaptation": 1.17733853047142,
  "experiment": "separate temporal benign-shift stream; not the frozen test set",
  "meanLabelLengthAfter": 10.539764909819041,
  "meanLabelLengthBefore": 7.13032688605555
}
```

## Limitations

- Synthetic, author-constructed windows, not independently collected production or malware-capture data.
- Labels express the generator's scenario intent; they are not investigated real-world outcomes.
- Default parameters were fixed before this held-out run, but the same author understands both model and generator: no independence claim.
- Only aggregate window shape is evaluated. Low-and-slow activity deliberately overlaps benign behaviour and may be missed.
- Failed/blocked traffic and clients without a prior baseline can abstain. Denominators include those abstentions explicitly.
- The fixed lexical comparator is a simple reference rule, not a benchmark of DNS Daddy's existing six detectors or another product.
- No real-world false-positive rate, maliciousness probability, block-safety claim or adversarial robustness guarantee follows from these results.

The deliberately overlapping low-and-slow scenario tests a limit of aggregate features. Legitimate new nonce traffic tests a plausible false alert. Review real findings and preserve the original evidence before considering future calibration; review labels do not automatically retrain this model.
