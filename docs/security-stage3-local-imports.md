# Local feed import policy (Stage 3 candidate)

Local feeds remain opt-in through `feeds.local_feed_dir`. Use a dedicated local
regular-filesystem directory, controlled producer accounts and a service-owned
cache directory. Producers must publish complete versions using write-temp plus
atomic rename. Do not grant producers write access to the feed cache.

## Configuration and compatibility

```yaml
feeds:
  local_feed_dir: /var/lib/dnsdaddy/local-feeds
  max_feed_bytes: 134217728
  import_limits:
    local_import_timeout: 90s
    records_per_feed: 1000000
    local_records_per_refresh: 2000000
    index_domains: 2000000
    index_claims: 5000000
    memory_bytes: 268435456
    temporary_bytes: 268435456
```

Zero numeric values select finite defaults; there is no unlimited sentinel.
Negative values fail configuration/manager initialization. Maximum snapshot size
is 1 GiB; timeout at most 10 minutes; records 5 million/feed, local records
10 million/refresh, domains 5 million, claims 10 million. Memory accounting accepts
64 MiB–2 GiB, staging storage 1 byte–2 GiB. Full/single refresh operations also have
a ten-minute parent cap. JSON values/keys/indicators and text lines are bounded at
1 MiB; JSON nesting is bounded at 64. Startup cache loading retains its two-minute
parent deadline. Limits apply to remote/cached/restored feeds as well.

`memory_bytes` is conservative ingestion accounting: a 32 MiB parser reserve,
the old index, staged contribution and candidate index are charged before adding
claims (512 bytes plus domain/category/feed identifier/name lengths per claim).
It is NOT a hard process heap/RSS quota. Go allocation, GC lag, concurrent readers
retaining prior generations and the rest of the daemon require additional RAM.
The memory budget can bind well before the domain/claim caps. Large existing feeds
may need splitting or an explicitly sized finite budget; do not assume the domain
cap is a promised supported capacity. Validate a representative corpus on the
intended host before release. No production corpus was used in the audit.

Absolute `file:///...` and `file://localhost/...` URLs inside the configured root
are supported. Relative in-root symlinks work. Absolute symlinks (including links
to in-root files), escaping symlinks, multiple-link files, special nodes, relative
file URLs, remote authorities, URL credentials, queries and fragments are rejected.
Convert absolute links to relative links or publish regular snapshots; copy hard
links to independent files. No files are automatically rewritten or chmodded.
A missing unused local root does not affect remote-only deployments. Once first
used, the local root is pinned for the manager lifetime: deliberate root replacement
requires a restart. A cache directory must be service-owned and not group/world
writable. Existing directory ownership/permissions are not repaired automatically.

## Publication, errors and recovery

Each candidate is copied to a unique rooted mode-0600 staging file, validated
through its open descriptor and checked against index budgets before cache rename.
A structural/limit/cancellation failure leaves its previous cache intact. Per-feed
parse staging prevents a malformed suffix from partially contributing to an index.
Ordinary missing/invalid caches remain visibly unloaded; a resource/cancellation
failure leaves the old active index unchanged. At boot hard resource/deadline
failures refuse listener startup instead of starting silently without filtering.
Oversized legacy/restored caches are retained for operator remediation, not deleted.

Rename is the per-file commit point. Full refresh is not an all-feed filesystem
transaction. Directory durability failure after rename explicitly reports that
cache content committed; publication matches that content. SQLite status/history,
cache files and the atomic in-memory index do not share a transaction. A shutdown
or database failure can leave history behind committed cache content. On restart,
rebuild from committed caches after addressing any errors.

Normal operation removes its own staging file. Crash orphans are deliberately
left for operator review, counted against the temporary quota and never blindly
swept. Remove only verified inactive service-created `.download-*` files during
controlled downtime. Directory scans refuse more than 16,384 entries. This is a
logical staging-byte bound, not a filesystem-wide quota; persistent caches, other
processes, block allocation and free-space/durability need deployment monitoring.

Cancellation is polled during fixed-buffer copy, parsing and before commit.
Manager shutdown cancels and joins its work before closing rooted handles.
Regular/NFS/FUSE I/O can block inside the kernel; no goroutine or thread timeout
makes that reliably interruptible. Use local regular storage. Strict hostile-storage
wall-clock isolation requires a separately approved worker design.

`os.Root` confines names and safe relative symlinks; it does not prohibit bind
mounts, filesystem crossings, privileged mount changes or prove inode provenance.
Rejecting Nlink != 1 reduces hard-link exposure but is not provenance proof.
Do not point the root at system/proc/device trees or allow untrusted mount control.
Source size/mtime comparisons detect some in-place changes, not a coherent snapshot
against a malicious writer restoring metadata. Atomic producer publication is the
supported consistency contract. Linux ARM64 compilation is not Linux runtime race
validation. No daemon, REA or Ghidra execution was performed for this change.

## Separate pre-release blocker

Pending-authentication backups can retain a `bootstrap_pending` database state
while excluding `initial-password.txt`; archive-only restore can then require
operator recovery. Authentication/backup recovery is unchanged by Stage 3. Resolve
that separate blocker before release. Never add plaintext initial credentials to
an unencrypted backup as a workaround. Independent binary verification and the
outstanding dependency advisory/reachability assessment also remain open.
