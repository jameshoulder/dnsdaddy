# Daddybound adversarial laboratory

Part of the [Verified Trust](../maturity/verified-trust.md) P0 milestone.
This document names the offline suites that exercise hostile or broken DNS
and encrypted-transport behaviour, so an independent reviewer can run them
without reconstructing the project from memory.

It is not an external penetration-test report. It does not claim that every
cache-poisoning or packet-adversary technique is covered.

## What to run

```bash
# Offline: recursive hostility, DNSSEC lab scenarios, encrypted no-downgrade
make test-adversarial

# Daddybound laboratory verdicts (signed hierarchy)
dnsdaddy daddybound validate
make daddybound-report

# Optional: Unbound/delv differential (needs libunbound-dev, bind9-dnsutils, cgo)
make test-daddybound

# Optional: broader fuzz surface (Daddybound + feeds + backup names)
make fuzz-surface
```

`make test-adversarial` needs no network and no CGO.

## Suites covered by `make test-adversarial`

| Suite | Package / pattern | What it proves |
| --- | --- | --- |
| Recursive hostility | `./internal/daddybound/recursive/` (`hostile_test.go`, bailiwick, scrub) | Additional-section poison is not cached as a delegation; wrong QNAME / TXID / QR rejected; out-of-bailiwick glue not followed; referral loops bounded; zero-TTL not pinned |
| DNSSEC signed lab | `./internal/daddybound/lab/` | Tampered, expired, forged, malformed and incorrectly delegated answers reach the required non-Secure verdicts |
| Native CD / AD | `./internal/daddybound/native/` (`client_test`, `forward_test`) | CD=1 skips crypto only; upstream AD never becomes a local Secure claim |
| Encrypted transport | `./internal/resolver/` (`EncryptedFixture*`) | Authenticated DoH/DoQ paths; redirect to plaintext HTTP refused; unauthenticated peer refused; failover stays authenticated |
| Config fallback refusal | `./internal/config/` (`MalformedEncryptedEndpointEnvironmentCannotSilentlyFallBack`) | Broken encrypted endpoint env cannot silently fall back to plaintext |

## Mapping to the shopping-list item

> Build a reproducible malicious-DNS laboratory covering packet tampering,
> replay, malformed responses and cache attacks.

| Threat shape | Evidence today |
| --- | --- |
| Packet tampering (signed data) | Lab scenarios `tampered-answer`, `malformed-signature`, DNAME/CNAME tamper chains |
| Packet tampering (wire identity) | Wrong TXID, wrong question, QR not set (`hostile_test.go`) |
| Replay | Expired signatures; RFC 5011 replay notes in trust-anchor state; zero-TTL cache pin refusal |
| Malformed responses | Lab malformed signatures; DoH/DoQ invalid envelopes; truncated UDP → TCP |
| Cache attacks | Bailiwick/scrub/hostile Additional poison; recursive cache TTL clamps |

Named gaps that remain for later Verified Trust slices:

- A dedicated packet-capture / MITM harness outside the in-process laboratory
- Independent professional adversarial review of the parsers (shopping-list 1.8)
- Broader fuzz of TLS/QUIC framing beyond the encrypted fixtures already present

## Related documents

- [Validation laboratory](validation-lab.md)
- [Conformance report](conformance-report.md)
- [Encrypted DNS](../encrypted-dns.md)
- [Security model](security-model.md)
