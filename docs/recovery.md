# Configuration history and encrypted recovery

DNS Daddy records management changes and can create an encrypted recovery
package containing the database **and the state required to use it**. A copy of
`dnsdaddy.db` alone cannot recover encrypted integration credentials without
`secrets.key`.

## Change history

System Settings displays the journal at `GET /api/v1/config/history`.

An entry records the authenticated principal (`session:admin` or the API token
name), operation, target, time, outcome and the actual persisted before/after
values. Changes cover policies and rules, networks and access, friendly client
names, feed configuration, provider/webhook configuration and credentials, management
tokens, the administrator password, protection settings, local DNSSEC mode,
DNS transport selection and finding reviews. Operational feed refresh timestamps are excluded from
configuration differences.

Passwords, credential ciphertext, management-token hashes, network tokens,
provider configuration values, feed/webhook URLs and free-text notes are compared
privately and shown as `[redacted]` when they change. The comparison digest is
never stored or returned. Request bodies, cookies, authorization headers,
passphrases and query strings are never journal content.

The journal begins when this feature is installed. It does not reconstruct past
changes or pretend to observe direct SQL or YAML edits. It is local operational
history, not an independently protected or tamper-proof audit service: somebody
who can replace the database can replace its history.

### What the outcome means

| Status | Meaning |
| --- | --- |
| `pending` | The intent was persisted before the request ran. Completion has not been recorded; a crash or failed journal update may have occurred. Inspect the current configuration. |
| `complete` | The response and actual stored differences were recorded. An accepted request can have no differences, for example an idempotent update. |
| `failed` | The request returned an error. Check its recorded differences: existing handlers may commit a setting before a later runtime reload fails. |
| `incomplete` | The request ran but its resulting configuration could not be captured. Configuration may have changed; inspect it before retrying. |

Existing management handlers use separate database transactions. The journal
therefore uses a durable intent followed by a recorded outcome. It does **not**
claim one atomic transaction spans the request, runtime reload and history.

Configuration writes are serialized within the running management API so one
operator's before/after comparison cannot absorb another operator's update.
DNS answering and read-only investigation are independent of this lock. If
the initial history write fails, the configuration request is refused before
its handler runs. If completion fails, the API returns HTTP 500 with
`configurationMayHaveChanged: true`, a history ID and
`X-DNSDaddy-Audit-Incomplete: true`; it does not tell the operator a rollback
happened.

History uses descending ID pagination. Request `?limit=50`, then pass
`beforeId=<nextBeforeId>` while `hasMore` is true. The maximum page is 200.
New writes do not shift already traversed pages. This history currently has no
automatic pruning; include its growth in database storage monitoring.

## What the recovery package includes

| Component | Handling |
| --- | --- |
| SQLite database | A consistent `VACUUM INTO` snapshot, including committed WAL data, configuration, retained queries/evidence/findings, review history, provider configuration, encrypted credentials and management API tokens. |
| Credential master key | `data/secrets.key` when present. Every captured provider credential and webhook signing credential must decrypt with the included key or backup fails. |
| Runtime configuration | `config.yaml`, with effective values and loadable duration strings. An implicitly selected native mode is left unpinned; SQLite retains the installation/default and latest dashboard mode choice. Explicit mode pins are preserved. |
| Original YAML | `source-config.yaml` when its source path is available, for reference. It may contain old bootstrap passwords and original host paths. |
| Native DNSSEC state | `data/daddybound-anchors.json` when present, preserving native anchor history and hold-down progress. |
| Local learning | `data/daddybound-learning.json` when present. The in-process API requests a fresh checkpoint if the learner is available. |
| Feed caches | Committed `.list` files under `data/feeds`, so a restart can rebuild the current blocklist without waiting for a provider. |
| Local feeds | Files in the configured local feed directory. The restored YAML and stored `file://` feed paths point into the new restore tree. |
| Referenced files | Configured DNS TLS certificate/key and custom DNSSEC anchor file, relocated into `refs`. |

Active dashboard sessions are revoked **in the restored database only**. The
running source is unchanged. The restored runtime configuration clears
`http.admin_password` as defense in depth. Startup now treats the persisted
password hash as authoritative; retained bootstrap configuration cannot overwrite
it. Credential revision is preserved, and older auth schemas migrate safely on
opening. See [dashboard password migration](security/dashboard-password-persistence.md). Existing management API tokens
are retained; rotate them explicitly if recovery follows credential exposure.

The pending webhook outbox is part of the database. After a recovered service
is deliberately activated, pending events may be delivered again; receivers
must apply the event-ID deduplication described in [webhooks.md](webhooks.md).

The retired `session.key`, `initial-password.txt`, process memory, DNS answer
cache, unflushed queue items, external log files, service units, reverse-proxy
configuration and firewall rules are excluded. A JSONL findings sink is derived
output and is redirected into the recovered data directory for future writes.

Database and auxiliary files are independent committed snapshots, not one
global transaction. Native state can move while the database is copied.
Learning checkpoints preserve completed baselines; partial learning windows
are intentionally discarded on restart. The offline CLI cannot request a
checkpoint from a separate running process and uses its last saved state.
Stop the source service first when an exact cross-file recovery point is
required. Neither live nor stopped recovery can recreate observations that
were never persisted.

## Create a backup in the dashboard

Open **System Settings → Recovery**, provide a new backup passphrase and
download the `.ddbackup` attachment. Store the passphrase separately in a
password manager. DNS Daddy neither stores nor recovers it for you.

The passphrase must be valid UTF-8 and contain 12–1024 bytes. The minimum length
is input validation, not a guarantee of strength; use a long, independently
generated password or passphrase.

The authenticated API accepts:

```http
POST /api/v1/recovery/backup
Content-Type: application/json

{"passphrase":"a long independently generated backup passphrase"}
```

The passphrase goes in the request body, never the URL. Cookie authentication
has the same-origin protection used by other management writes. A complete
encrypted file is prepared before returning an attachment. Failures return
JSON; the endpoint does not return a partial backup with a success status.
Use HTTPS or a local protected management connection as for other credentials.

`GET /api/v1/recovery/status` reports availability, inclusions, exclusions,
limits and the offline-only restore mode. The API serializes backup against
management configuration writes. A simultaneous change/backup can return 409;
try again after it completes. Creation has a five-minute request deadline.

## Create a backup from the command line

```sh
dnsdaddy backup \
  -config /etc/dnsdaddy/config.yaml \
  -output /secure-backups/dnsdaddy-2026-09-29.ddbackup \
  -passphrase-file /secure-secrets/dnsdaddy-backup-passphrase
```

The output file must not exist. It is created with mode `0600`. The passphrase
file must be a regular file with owner-only permissions, such as `0600`;
symbolic links are refused. One final line ending is removed. Leading or
trailing spaces that are part of the phrase are preserved.

Alternatively, use `-passphrase-stdin` with a secret manager or securely supplied
standard input. Do not place the phrase in command arguments or exported
environment variables. Both commands accept `-timeout 5m`.

The source is opened read-only. No migrations, seeding, service start or
provider/DNS lookup is performed by the backup command.

The CLI resolves the configuration, environment variables and relative paths
of its own invocation. Run it with the service's intended configuration and
environment. The dashboard path uses the running process's configuration;
neither command can infer an unsaved external service-unit or firewall change.

## Restore and verify offline

Restore **always** requires a new destination directory. It cannot replace a
running database, merge into a data directory or overwrite existing files.

```sh
dnsdaddy restore \
  -input /secure-backups/dnsdaddy-2026-09-29.ddbackup \
  -destination /srv/dnsdaddy-recovered \
  -passphrase-file /secure-secrets/dnsdaddy-backup-passphrase
```

Restore verifies authenticated encryption, every file checksum and SQLite
integrity. It verifies provider credential/key agreement again, relocates the
runtime paths and local feed references, revokes recovered sessions, and writes
`RESTORE.txt` plus the authenticated manifest. Directories use `0700` and files
use `0600`. A failed restore removes only the newly created restore tree.

The command does not start a process or contact any external service. Review
the generated launch configuration at
`/srv/dnsdaddy-recovered/config.yaml`, including DNS/management bind addresses,
TLS, proxy trust, client access, upstreams and provider settings. If the service
runs under a dedicated account, give that account ownership of the new private
tree before switching the service to the new configuration. Keep the current
deployment until the recovered instance has been deliberately verified in the
intended environment.

Use a normal restore into an isolated, fresh directory as a periodic recovery
drill. A successful download alone is not evidence that an operator can find
the passphrase, recover the files or switch a service to them.

## Format and bounds

Format version 1 is an uncompressed tar file carried in authenticated records.
It uses the standard library's AES-256-GCM and `golang.org/x/crypto/scrypt`
(N=131072, r=8, p=1, 32-byte derived key). Each package has a random 32-byte salt
and a random four-byte nonce prefix. Each nonce appends a monotonically
increasing eight-byte record index. The format header, record index and record
length are authenticated additional data. A final authenticated empty record
is mandatory. Truncation, reordered/changed records and appended data are
rejected. The version fixes KDF costs; an input file cannot request arbitrary
memory or CPU parameters.

Creation/restore uses bounded 1 MiB record buffers rather than loading a whole
database into RAM. The KDF uses approximately 128 MiB. One package supports at
most 1 GiB of plaintext tar data, 4096 files, a 2 MiB manifest, 4 MiB runtime/source
configuration files and 8 MiB per native/learning/referenced-state file. File
count, path lengths, total sizes and manifest membership are checked. Only
regular files are accepted; symlinks, hard links, devices, traversal and unknown
paths are rejected. There is no archive compression to expand into a larger
payload.

These controls and the isolated tests describe implemented behavior. They are
not an independent audit of the recovery format. Changing cryptographic or
archive behavior requires retaining the existing tampering, truncation,
round-trip and path-safety tests and a format-version decision.

## Pending administrator activation recovery (Stage 5A)

New backups require an active administrator with a valid stored bcrypt hash.
The check uses the committed SQLite snapshot. Complete initial activation before
creating a recovery package. The database hash remains authoritative: backup,
restore and recovery never replace it from YAML or environment configuration.
Neither archived YAML copy includes `http.admin_password`; `source-config.yaml`
is a normalized reference, with comments removed. Ambiguous YAML, anchors,
aliases, multiple documents and unknown fields are refused. Keep the original
configuration privately; it is never rewritten by backup creation.

Old format-1 archives can contain a generated hash still awaiting activation.
Restore preserves that hash and reports `pending_password_proof`, writes a
private `ADMIN_RECOVERY_REQUIRED.json` note, and does not start the service.
The note is informational; deleting or creating it cannot authorize recovery.
`recovery_required` means proof-based activation is unavailable (for example,
a missing or damaged hash). Do not edit the database to mark it fresh or use
bootstrap settings to reset it. Retain the verified data and find an earlier
usable backup or seek a separately authorized recovery procedure.

For `pending_password_proof` only:

1. Stop the service and keep it stopped. Work on the restored private data tree
   as its owner, using trusted owner-controlled parent directories. Review the
   restored configuration, API tokens and integration credentials before use.
2. Supply the **existing administrator password** to the offline command through
   stdin. Do not put passwords in command arguments, environment variables,
   shell history or files in the backup tree. For example, in Bash with shell
   tracing disabled, use a silent prompt (the command below is operator guidance):

   ```bash
   set +x
   IFS= read -r -s -p 'Existing administrator password: ' recovery_proof
   printf '\n' >&2
   printf '%s' "$recovery_proof" | dnsdaddy recover-admin \
     -data-dir /private/restored/data -password-stdin -service-stopped
   unset recovery_proof
   ```

3. On success, the identical hash becomes active, revision advances, all dashboard
   sessions are revoked and a non-secret event is committed atomically. No new
   password, session or recovery token is issued. Review and deliberately start
   the service; sign in with that same password. Stale bootstrap settings cannot
   override it. Recovery is offline only; there is no HTTP recovery endpoint.

Missing/incorrect proof, unsupported state or database failures fail closed.
A pre-commit failure rolls back activation, session changes and the recovery event.
Repeat the command with correct proof after an interruption: an already active
account is proof-checked and reported without changing credentials or sessions.
If note cleanup or status output fails after commit, the message explicitly says
credentials are active. The database, not a recovery note, determines authority.

The command requires an existing owner-held regular mode-0600 single-link database,
a directory not writable by group/others, safe existing SQLite sidecars, and an
explicit stopped-service assertion. It never creates a missing database or runs
startup migrations. A nonblocking advisory directory lock serializes cooperating
recovery commands; it does not stop an uncooperative daemon. Same-user/root changes,
untrusted parent-directory replacement and hostile filesystems are outside this
local administrator trust boundary. Bounded input is read before the 30-second DB
operation deadline; a stalled stdin producer or kernel I/O can still block.

Losing the existing pending password cannot be repaired securely from its bcrypt
hash or the archive passphrase alone. Keep any separately escrowed initial delivery
credential in an independent encrypted operator vault, never in this archive.
Older archives may retain bootstrap plaintext in their encrypted reference YAML;
they are not rewritten automatically and must be handled as sensitive material.
Backups restore the password and API tokens valid at snapshot time: restoring an
older backup can restore an older password. Review external credentials and API
tokens deliberately after recovery. This command is not an anti-rollback mechanism.

### Recovery notice location

New restores write the non-secret `ADMIN_RECOVERY_REQUIRED.json` notice inside the
restored **data directory** (`<destination>/data/`), which is the directory supplied
to `recover-admin -data-dir`. After correct existing-password proof, the command
removes that notice through its pinned data root; it never opens a parent root or
traverses `..` to clean up notices. Incorrect proof leaves the notice, credential
state and session rows unchanged. A notice symlink is unlinked as a leaf, without
following its target. The database remains authoritative, not the notice.

Older restores may have written the notice one level above `data/`. Recovery will
not automatically remove that historical parent notice. After verifying successful
activation, an operator may review that informational leftover separately. Neither
a leftover notice nor its removal authorizes a password reset or overrides DB state.
