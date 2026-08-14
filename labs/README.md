# DNS Daddy Lab

A self-contained environment for seeing DNS Daddy's behavioural detections
fire — and, just as importantly, for seeing them *not* fire on traffic that
superficially looks the same.

```bash
docker compose --profile lab up --build
# dashboard: http://127.0.0.1:8081   password: dnsdaddy-lab-demo-password
# findings start appearing after about a minute
```

Tear it down with `docker compose --profile lab down -v`. That is safe: the lab
keeps its own volume and never touches a production deployment's data.

---

## What this is, and what it is not

The lab is **entirely synthetic and entirely offline**. Every name it queries
sits under `.example` or `.test`, which [RFC 2606] and [RFC 6761] reserve for
documentation and testing and which are not delegated in the root zone. The
upstream is a small responder that ships with the lab and serves a made-up
zone. No query leaves the machine, and there is no malicious infrastructure
involved because there is none to involve.

That is a design constraint, not a shortcut. A detection lab built on live
malware command-and-control is one that breaks when the infrastructure is
seized, produces different results every time you run it, and asks you to
contact real attackers to prove a heuristic works.

**What the lab proves:** that the detectors fire on the traffic shapes they
were designed for, that they stay quiet on the benign traffic that shares those
shapes, and what the resulting findings actually look like.

**What the lab does not prove:** that the thresholds are right for your
network. Synthetic traffic is generated from the same understanding of the
problem that produced the detectors, so it is a test of internal consistency,
not of real-world accuracy. This is exactly why every detector is marked
*experimental*. See [docs/detection/README.md](../docs/detection/README.md).

## How the lab is put together

```
 lab-normal ─┐
 lab-tunnelling ─┤
 lab-high-entropy ─┤     ┌──────────────┐     ┌───────────┐
 lab-nxdomain ─────┼────▶│ lab-resolver │────▶│ lab-sink  │
 lab-txt ──────────┤     │  DNS Daddy   │     │ synthetic │
 lab-dga ──────────┤     └──────┬───────┘     │   zone    │
 lab-beaconing ────┘            │             └───────────┘
                                ▼
                     dashboard on :8081
                     findings.jsonl
```

Each scenario runs in its own container with its own IP address. That matters:
most of the detectors are client-scoped, so running everything from one address
would blend seven behaviours into one host apparently doing all of them at
once.

`lab-sink` resolves the attacker-controlled domains and answers NXDOMAIN for
everything else. That asymmetry is the realistic part — a tunnel's domain
*must* resolve or the tunnel does not work, while the thousand candidates a
generation algorithm tries mostly must not. Pointing the lab at a public
resolver instead would fail every lookup equally, and each scenario would raise
a spurious NXDOMAIN finding on top of the one it was built to demonstrate.

### Time compression

The lab sets `detection.window_scale: 0.1` and generates traffic at
`-speed 10`. Detection windows shrink from five minutes to thirty seconds and
the traffic arrives ten times faster, so the number of queries per window is
unchanged and a demonstration finishes in about a minute.

**The two must move together.** The detectors' minimum-volume gates do not
scale with the window, so compressing the window without compressing the
traffic puts a tenth as many queries in each window and produces silence.
`window_scale` is a demonstration setting, not a tuning knob — it makes
rate-based signals noisier without making anything more sensitive.

## Running scenarios by hand

Without Docker, on Linux:

```bash
make build-lab                                    # → bin/dnsdaddy-lab

# In one terminal, the synthetic upstream:
bin/dnsdaddy-lab -sink 127.0.0.1:5300

# Point a DNS Daddy instance at it, then in another terminal:
bin/dnsdaddy-lab -server 127.0.0.1:5353 -scenario dns-tunnelling -speed 10
bin/dnsdaddy-lab -scenario all -speed 10          # every scenario in turn
bin/dnsdaddy-lab                                   # list them
bin/dnsdaddy-lab -scenario dga-simulation -dry-run # see the names, send nothing
```

Each scenario binds a different `127.0.0.x` source address so it appears as its
own client. On macOS and Windows only `127.0.0.1` is normally bound; pass
`-client 127.0.0.1` and accept that every scenario will be attributed to the
same device.

Everything is seeded, so `-seed 1` today produces byte-for-byte the same names
as `-seed 1` next year. A screenshot can be regenerated rather than reshot.

## The scenarios

| Scenario | Client | Expected finding |
|---|---|---|
| [normal-dns](normal-dns.md) | 172.30.0.31 | **none** — the baseline |
| [dns-tunnelling](dns-tunnelling.md) | 172.30.0.32 | `dns_tunnel_suspected` (high) |
| [high-entropy-subdomains](high-entropy-subdomains.md) | 172.30.0.33 | **none** — the multi-signal gate |
| [nxdomain-anomaly](nxdomain-anomaly.md) | 172.30.0.34 | `nxdomain_burst` |
| [suspicious-txt](suspicious-txt.md) | 172.30.0.35 | `txt_activity_anomaly` |
| [dga-simulation](dga-simulation.md) | 172.30.0.36 | `dga_like_domains` |
| [beaconing](beaconing.md) | 172.30.0.37 | `dns_beaconing_suspected` |

Two of the seven are supposed to produce nothing. Those are the most useful
ones. A detection demo that only ever shows detections teaches you nothing
about the false positives you will actually spend your time on, and
`high-entropy-subdomains` in particular exists to answer the single most common
bad assumption in DNS detection — that high entropy means malicious.

## Verifying a run

```bash
# What fired, per client
docker compose exec lab-resolver \
  wget -qO- --header="Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8080/api/v1/findings?limit=50' | jq -r \
  '.findings[] | "\(.severity)\t\(.eventType)\t\(.clientIp)\t\(.domain)"'
```

Or just open the dashboard's **Detections** page, which shows the same thing
with the signal breakdown expanded.

Expected outcome of a full run:

```
normal-dns                 172.30.0.31  no findings
dns-tunnelling             172.30.0.32  dns_tunnel_suspected (high)
                                        txt_activity_anomaly (medium)
high-entropy-subdomains    172.30.0.33  no findings
nxdomain-anomaly           172.30.0.34  nxdomain_burst (medium)
                                        dga_like_domains (medium)
suspicious-txt             172.30.0.35  txt_activity_anomaly (medium)
                                        dns_tunnel_suspected (medium)
dga-simulation             172.30.0.36  dga_like_domains (medium)
                                        nxdomain_burst (medium)
beaconing                  172.30.0.37  dns_beaconing_suspected (medium)
```

Several scenarios trip more than one detector, and that is correct rather than
noisy. A tunnel over TXT genuinely is unusual TXT activity. A host walking a
generated domain list genuinely does produce an NXDOMAIN burst. Correlated
findings from independent detectors are stronger evidence than any one of them
alone — which is the argument for building several narrow detectors rather than
one that tries to decide everything.

[RFC 2606]: https://www.rfc-editor.org/rfc/rfc2606
[RFC 6761]: https://www.rfc-editor.org/rfc/rfc6761
