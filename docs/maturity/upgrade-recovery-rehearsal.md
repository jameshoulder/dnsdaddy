# Upgrade and recovery rehearsal

Reuse encrypted backup and offline restore ([recovery.md](../recovery.md)).
Distinguish three operator actions:

| | Action | Goal |
| --- | --- | --- |
| **A** | Restore the **client's** original DNS | Immediate user recovery without touching the resolver host |
| **B** | Upgrade the resolver | Move to a newer revision/artifact while keeping data |
| **C** | Recover an older version with a compatible pre-upgrade snapshot | Offline restore into a **fresh** directory, then deliberate cut-over |

## Schema generation guard

Current binaries record `schema_generation` (see `internal/store/schema_generation.go`).
Opening a database whose generation is **newer** than the binary fails clearly.

**Important:** this guard cannot protect already-published binaries that lack it.
Additive migrations historically allowed swapping back one release; that is not a
promise for every future change. Prefer a pre-upgrade encrypted backup before
any upgrade you might need to reverse.

## Rehearsal procedure (temporary fixtures)

1. Freeze before/after revisions (or commit SHAs) and configuration/key pairing.
2. Create an encrypted backup with `dnsdaddy backup` (or dashboard Recovery).
3. Upgrade the fixture binary/image (B). Confirm migrations apply.
4. Practice (A) on the lab client: restore original DNS settings.
5. Practice (C): `dnsdaddy restore -input … -destination NEW_DIR` into an empty
   directory. Confirm sessions are revoked in the restored DB and the live
   source database is untouched.
6. Attempt wrong passphrase / truncated archive — expect clear failure with the
   original data retained.
7. Document migration boundaries and anything untested on a real host.

## What backup does not cover

Service units, reverse-proxy config, host firewall rules, process memory, DNS
answer cache, and unflushed queues are outside the package. See recovery.md.

## Acceptance for this pass

Temporary-fixture upgrade/restore exercises preserve required state where
automated tests already cover backup authentication, checksums and offline
restore. Real multi-host soak upgrades remain **untested** unless recorded in
the [compatibility evidence ledger](compatibility-evidence.json).
A passing backup unit test is **not** a downgrade guarantee.
