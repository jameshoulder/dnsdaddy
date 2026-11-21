# Verified Integrity (Phase 3)

DNS Daddy’s blocking and management claims are only as trustworthy as the
evidence behind them. This pass records **local** supply-chain and journal
integrity evidence. It is not a new branded engine and it is not publisher
attestation or host-compromise protection.

## Feed supply-chain evidence

Each successful feed commit now records:

| Field | Meaning |
| --- | --- |
| `refreshSourceUrl` | URL or `file://` target of the attempt |
| `contentSha256` | SHA-256 of the committed cache body |
| `lastGoodSha256` | Last known-good cache digest (retained on failure) |
| `parserAccepted` / `parserRejected` | Usable vs skipped lines/indicators from that parse |
| `lastSuccessAt` | Age of the intelligence still considered good |

Failed refreshes update `lastRefreshedAt` / `lastStatus` / `lastError` and the
attempted source URL, but **do not** replace `lastGoodSha256` or parser
evidence. The previous `.list` cache file remains the published copy when a
candidate fails validation — rename is still the commit point.

On rebuild, a cache whose bytes no longer match `lastGoodSha256` is skipped and
reported as not loaded. Empty checksums (upgrades before the first sealed
commit) skip that check.

**What this is not:** a signed publisher provenance claim, a transparency log,
or proof that a third-party feed is benign.

## Hash-chained management journal

`config_change_history` rows written after this pass carry `prevHash` /
`entryHash` (SHA-256 over a canonical redacted seal). Verify with:

```http
GET /api/v1/config/history/verify
GET /api/v1/config/history/verify?expectedTip=<hex>
```

| Detection | Without external tip | With trusted tip checkpoint |
| --- | --- | --- |
| Mutated sealed payload | Yes | Yes |
| Broken prev-link / reorder among sealed rows | Yes | Yes |
| Truncation of sealed suffix (when tip is held) | No | Yes |
| Wholesale database replacement | No | Yes, if tip mismatches |
| Compromised host rewriting DB + forging a new tip you accept | No | No |

Pre-upgrade rows may be `legacyUnsealed`. New sealed rows chain from genesis
(`64` zero hex digits) or from the previous sealed tip.

Credentials remain redacted in journal content. Digests used for secret
comparison never enter the durable seal.

## Operator practice

1. After important changes, copy `tipHash` from verify into offline notes or
   backup metadata. `tipHash` is the last **completed** seal (pending rows are
   excluded from the exported tip).
2. After restore or incident review, re-run verify with that checkpoint.
   `expectedTip` must match the exact backup/journal state you saved, or an
   ancestor seal still present in the chain. Later valid management writes
   advance `tipHash` and set `tipMatches: false` while `checkpointFound`
   stays true — that is not a break.
3. Treat feed checksum mismatch / not-loaded as “do not claim this feed is
   protecting anyone” — the same rule as the existing `loaded` field.

See also [recovery.md](recovery.md), [capabilities.md](capabilities.md) and
[roadmap.md](roadmap.md).
