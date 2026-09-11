# Resolver performance: forward against Daddybound Native

What it costs to resolve DNS yourself, measured rather than asserted.

Run it:

```
go test ./internal/resolution/ -run xxx -bench 'BenchmarkForward|BenchmarkNativeWarm|BenchmarkNativeCold' -benchtime 300x -count=3
go test ./internal/resolution/ -run TestBenchmarkProfile -v
```

Both are hermetic. The forwarding backend talks to a stub upstream in the same
process; the native backend talks to the signed reference hierarchy from
`internal/daddybound/lab`, served as one authoritative server per zone on
loopback. Nothing leaves the machine, so the numbers are about the resolver's
own work rather than about whoever's network the benchmark ran on — which makes
them reproducible, comparable, and an underestimate of real latency in both
cases by exactly the round-trip time each would spend on the Internet.

DNSSEC validation is **on** for every native measurement. Measuring native
resolution with it switched off would produce a better number and a meaningless
one: the validation is the reason to run it.

## Results

Measured 2026-09-11 on the development container: 4 vCPU, Go 1.25.13,
`CGO_ENABLED=0`, Linux 6.18. Three runs, 300 iterations each.

| | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Forward (stub upstream, warm cache) | 20,600 – 22,700 | 2,038 | 34 |
| Daddybound Native, warm cache | 382,000 – 390,000 | 24,520 | 322 |
| Daddybound Native, cold cache | 1,925,000 – 2,025,000 | ~141,700 | ~1,680 |

Under a fixed load of 2,000 sequential queries:

| | QPS | p50 | p95 | p99 | cache hit rate |
|---|---:|---:|---:|---:|---:|
| Forward | 207,515 | 1 µs | 6 µs | 104 µs | 96.8% |
| Native, warm | 2,345 | 377 µs | 667 µs | 794 µs | 100% |

The forward figures are dominated by cache hits and should be read as "what a
cache hit costs", not "what forwarding costs" — a real forwarded miss is a
round trip to Quad9 and is measured in milliseconds, none of which is DNS
Daddy's.

## What the numbers say

**Native warm resolution costs about 380 µs per query with a 100% cache hit
rate.** A cache hit should be microseconds. It is not, and the profile says
exactly why:

```
      flat  flat%   sum%        cum   cum%
      40ms 50.00% 50.00%       40ms 50.00%  crypto/.../field.feSquare
      10ms 12.50% 62.50%       10ms 12.50%  crypto/.../field.(*Element).Multiply
      10ms 12.50% 75.00%       10ms 12.50%  crypto/.../field.(*Element).carryPropagate
         0     0%   100%       60ms 75.00%  crypto/ed25519.Verify
```

Three quarters of the CPU on a warm query is Ed25519 signature verification.
Daddybound re-validates the whole chain of trust on every query, including when
every record involved came from cache: the root's DNSKEY, the TLD's DS and
DNSKEY, the zone's DS and DNSKEY, and the answer itself. Nothing is wrong with
the verdict — re-validating is never less safe than not — but the work is
repeated in full for records that have not changed.

This is the single largest finding of the benchmark and the main thing standing
between native mode and being a sensible default. See "Not done" below.

**A cold native resolution costs about 2 ms and 1,680 allocations** against
servers on loopback. On the real Internet the same walk is four round trips in
series — root, TLD, authoritative, plus the DNSKEY and DS fetches at each level
— so expect tens to hundreds of milliseconds depending on where the zone's
servers are. That is inherent to iterative resolution and is what a forwarder
buys by asking somebody who already knows.

**Allocation pressure is the figure to watch on the reference deployment.**
1 vCPU and 1 GB is where garbage collection bites first, and a cold native
resolution allocates 70× what a forwarded one does. The warm path's 24 KB and
322 allocations are dominated by the same re-validation: the canonical wire form
of each RRset is rebuilt to verify against.

## What was not measured

**CPU as a percentage, and resident memory of a running process.** Go's
benchmark framework reports nanoseconds and allocations per operation, which is
the portable equivalent and the one that matters for the reference target. A
figure for `%CPU` under load on a real 1 vCPU VPS needs a real 1 vCPU VPS and a
traffic generator, and is not something this repository's test suite can
produce. It is not reported here rather than estimated.

**A 1 vCPU / 1 GB reference deployment.** The numbers above are from a 4 vCPU
container. Single-core figures will be worse for native mode in particular,
because the per-query cost is CPU-bound on signature verification rather than
waiting on a network. A run on the reference hardware is outstanding.

**Real Internet latency.** Deliberately: it is not reproducible and it is not
DNS Daddy's.

## Not done, and why

**Validated-answer caching.** The obvious fix for the 380 µs is to cache the
validation verdict alongside the records rather than recomputing it, which is
what every production validating resolver does.

It is not in this milestone because doing it wrong ships a false Secure, which
is the worst failure this project has. A cached verdict has to expire on the
earlier of the record TTL *and* the signature's own expiry — a signature that
expires in ten minutes must not have its Secure verdict held for the record's
one-hour TTL — and it has to be invalidated when the trust anchors change, which
they now do at runtime under RFC 5011. That is a slice of its own with its own
adversarial tests, and adding it hastily at the end of a long milestone is
exactly how the mistake gets made.

Until it exists, native mode is a production beta rather than the default.
