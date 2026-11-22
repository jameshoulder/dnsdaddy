# Website-consumable static artefacts

## Product claims

File: [`product-claims.json`](product-claims.json)

Regenerate from the repository root:

```bash
go run ./cmd/dnsdaddy claims export
make claims-check
```

### Importing into Lovable (or any static site)

1. At **site build time**, copy or fetch this file from a pinned git revision of
   `jameshoulder/dnsdaddy` (for example via CI checkout or a release asset).
2. Parse JSON and render maturity / availability / caveats. Treat
   `availability: "open-pr"` as **not released**.
3. **Do not** call an unauthenticated endpoint on a live DNS Daddy instance for
   marketing content. Resolvers are operator-private; there is no public claims
   API by design.
4. Show `criticalClaimsDigest` and `generatedFromRevision` in a footer so a
   reviewer can match the site to the inventory.

The detailed prose inventory remains [`../capabilities.md`](../capabilities.md).
This JSON is the structured twin, not a replacement for explanatory docs.
