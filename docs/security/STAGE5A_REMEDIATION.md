# Stage 5A: administrator backup recovery remediation

Scope: R01 (CWE-754, conditional availability/recovery failure). Based on the
approved BACKUP_RECOVERY_REMEDIATION_PLAN and Phase 4 reproductions at parent
commit 6619c5b. This isolated change implements sections A–D only. R03 backup
file-opener hardening, capacity and dependency upgrades are not included.

## Root cause and before/after behavior

Before: generated credentials could be committed in bootstrap_pending state
before initial-password delivery/activation completed. Backup captured that state
but excluded initial-password.txt. Restore preserved the hash while clearing the
configured bootstrap password. Startup correctly refused activation without the
absent delivery file, leaving an archive-only recovery dead end. This was an
availability defect, not established remote account takeover.

After:

- Backup inspects the actual VACUUM snapshot, read-only and without migrations.
  Only valid active credentials (including legacy hashes) are eligible. Pending,
  missing, malformed or recovery-required authority cannot produce a successful
  new backup. The gate precedes encryption/output, and never updates the source.
- Existing format-1 pending archives remain recoverable as verified data. Restore
  returns an explicit administrator status and private non-secret recovery notice;
  it does not claim authentication readiness or start the service. A restored
  pre-hash pending row is made recovery_required, preventing fresh bootstrapping.
- The offline recover-admin command requires existing-password proof on bounded
  stdin and an explicitly selected, owner-controlled private data tree. There is
  no HTTP route, password replacement, new password generation or session issuance.
  Bcrypt proof is followed by CAS against pending/generated/revision-zero and the
  exact expected hash. Activation, revision advancement, session deletion and the
  non-secret recovery event commit together. Rollback preserves existing authority.
- A proof-checked already active account is an idempotent no-op. Wrong passwords,
  including passwords invalidated by rotation, cannot change it. Post-commit note
  cleanup/output errors truthfully report active credentials; retry is safe.
- Both archived YAML copies exclude http.admin_password. Source YAML is normalized,
  bounded and parsed against the schema; comments are removed and ambiguous YAML
  is rejected. No plaintext initial-password file is included. Existing AES-GCM/
  scrypt encryption, archive verification and destination safeguards remain.

## Implementation evidence and modified-file summary

| Files | Change |
|---|---|
| internal/store/admin_snapshot.go | Coherent read-only current/legacy snapshot inspection; mode=rw offline opener with no create, seed or startup migration |
| internal/store/admin_auth.go | Transactional CAS activation, session revocation and recovery audit event; normal generated activation also atomically revokes sessions |
| internal/api/auth.go | Existing-password proof and proof-checked active no-op; offline constructor avoids startup side effects |
| internal/backup/admin.go | Snapshot eligibility/status and bounded bootstrap-password exclusion from source YAML |
| internal/backup/backup.go | Gate committed snapshot; sanitize both archived YAML copies |
| internal/backup/restore.go | Explicit auth status; preserve verified pending data; block pre-hash restored initialization; non-secret notice |
| cmd/dnsdaddy/main.go, recovery.go, recover_admin.go | Offline command dispatch, restore diagnostics, owner/type/mode/link checks, advisory exclusion of cooperating recovery commands |
| internal/store/admin_recovery_test.go | Rollback at state/session/audit/commit boundaries, cancellation, two-handle CAS race and snapshot classification |
| internal/api/p4_recovery_validation_test.go | Replace historical pending-backup characterization with refusal/proof regressions; retain rotated active restore control |
| internal/backup/admin_test.go | Authenticated legacy archive fixtures, repeated/canceled restores, missing-hash refusal, YAML exclusion and source preservation |
| cmd/dnsdaddy/recover_admin_test.go | Direct command-function tests with synthetic stdin; invalid/absent/oversized proof, idempotence, secret-free output, unsafe database refusal |
| internal/backup/backup_test.go, cmd/dnsdaddy/recovery_test.go | Existing successful-backup fixtures explicitly initialize a synthetic active account |
| docs/recovery.md, this report | Operator procedure, compatibility, trust boundaries and remediation evidence |

No new dependency or Go toolchain version is introduced. Production feed/DNS
resolution behavior and authentication HTTP routes are unchanged.

## Regression acceptance and review

Synthetic temporary databases and offline fixtures cover:

- New generated-pending backups refused before/after delivery, without output or
  changed credential authority; fresh/current/legacy/missing/malformed snapshot
  classifications. Source inspection confirms the check follows VACUUM.
- Authenticated legacy pending archives restored twice to distinct new trees,
  with explicit recovery status, unchanged hash and no plaintext delivery file.
  Missing-hash archives cannot automatically initialize; canceled restores clean up.
- Missing/wrong proof cannot log in, bypass activation through bootstrap settings,
  or change state. Correct proof activates the same hash; restart/bootstrap logic
  keeps it authoritative. Rotated credentials and sessions retain existing controls.
- State-update, session-delete, audit-write and deferred commit failures roll back;
  retry succeeds. Pre-canceled operations fail; concurrent DB handles have one CAS
  winner and one audit event. Stale expected state cannot activate again.
- CLI missing/incorrect/oversized proof, explicit invocation flags, symlink/hardlink/
  broad-permission/missing DB refusal, no missing-DB creation, safe output and repeat.
- Both real archive YAML payloads exclude the synthetic configured bootstrap secret;
  sanitizer rejects malformed, anchored, unknown-field and multiple-document input.
  Original synthetic YAML is byte-identical after backup creation.
- Existing active rotated backup/restore/reopen, archive tamper/truncation checks,
  session invalidation, provider-secret recovery and feed regressions remain covered.

Final review traced proof -> bcrypt -> expected credential -> transaction -> CAS ->
session deletion -> audit -> commit, and snapshot -> eligibility -> encrypted archive
-> verified restore -> auth classification. No reset branch, HTTP recovery route or
secret-bearing diagnostic was introduced. Independent binary verification remains
outstanding by prior agreement; compilation is not binary security verification.
Exact executions, totals, artifact hash, final commit and preservation results are
recorded in the external Stage 5A evidence/report alongside the audit workspace.

## Migration and compatibility

Archive format remains 1. No existing hash, source vocabulary or authentication
revision is converted. The new recovery-event table is additive and created within
the activation transaction; no event table is needed for normal startup. Unknown or
incompatible storage causes a safe failure, never a credential reset. Recovery opens
an existing database without startup migrations and is supported for the assessed
pending/generated schema. Legacy active backups retain their existing migration path.

New backups intentionally fail until activation completes. Existing active accounts
continue backing up. YAML anchors, aliases, multiple documents and unsupported fields
now block backup source-reference capture; operators must use supported explicit
configuration. Original files and historical archives are not rewritten. CLI support
is assessed on Darwin ARM64 with Linux ARM64 compilation; Linux runtime filesystem
and disaster-recovery exercise remain prerequisites for deployment approval.

## Residual risks and limitations

- No known pending password means no proof-based recovery. A hash or archive
  passphrase cannot safely authorize a reset. Use an earlier usable backup or a
  separately designed/approved independent recovery factor; retain verified data.
- A backup restores snapshot-time passwords and API tokens, including older ones.
  This is not anti-rollback recovery. Historical encrypted archives may contain
  bootstrap plaintext in YAML references; handle them as sensitive material.
- The local operator controls the host/tree and must stop the service. Directory
  flock only excludes cooperating recovery commands. SQLite reopens pathnames and
  sidecars; same-UID/root attackers, replaced untrusted ancestors and hostile mounts
  are outside this boundary. File checks are not a sandbox for an adversarial owner.
- Stdin reading is bounded by bytes, not time; the DB operation has a 30-second
  context after input. Bcrypt and kernel I/O cannot always be interrupted by context.
  No process-kill, power-loss, hostile-mount or Linux runtime fault experiment was run.
- Filesystem notes and SQLite are not a shared transaction. After commit, DB state is
  authoritative; cleanup failure is explicitly distinguished. A crash during restore
  can leave an incomplete new directory; do not launch it, retry into a new directory.
- Go 1.27.1/dependency findings D01, feed-capacity P4-I01, R03 and V01–V05 remain
  unresolved as documented in the prior register. No production readiness claim.

No daemon, REA or Ghidra was executed; no merge, push or deployment is authorized.
