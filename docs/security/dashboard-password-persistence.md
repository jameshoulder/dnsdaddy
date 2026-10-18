# Dashboard password authority and upgrade behavior

`http.admin_password` and `DNSDADDY_ADMIN_PASSWORD` are bootstrap inputs. After
initialization the database's administrator hash is authoritative. Retaining,
changing or clearing a bootstrap value does not reset that password. The environment
still overrides YAML when loading configuration; neither overrides an existing
credential. An invalid stale bootstrap value is ignored for an active account.

New configured passwords and dashboard replacements require at least 12 Unicode
characters and at most 72 UTF-8 bytes. Whitespace is preserved. Existing valid
bcrypt credentials, including short legacy passwords, continue to authenticate;
upgrade never hashes stale configuration over them. New hashes use bcrypt's
existing DefaultCost (10), random salt and the existing dependency.

## Upgrade and migration

The auth-state/session-revision migration retains the exact existing hash and
signs out legacy dashboard sessions once. Normal later restarts preserve sessions
and the current password. Migration and its sign-out are transactional/idempotent.
No management API tokens are rotated; rotate those separately if needed.

If an earlier vulnerable restart already replaced a changed password with an old
bootstrap value, the lost hash cannot be reconstructed. Upgrade preserves the
currently effective DB credential. Authenticate with it and change the password
after upgrading. Remove obsolete bootstrap values from both YAML and environment
through your normal configuration-management process; this application does not
edit them. Do not run old and new executables against the same database.

A database with an absent, empty or malformed legacy credential is not assumed
fresh. Management initialization fails with a static recovery-needed message;
configuration cannot silently reset it. Review a consistent backup and use a
deliberately approved offline recovery process. No new automatic reset command
or environment reset bypass is provided. Do not delete the database to reset a
password: it also contains policies, networks and other application state.

## First generated password and interruption

Only a genuinely new database may initialize. Generated credentials remain
bootstrap-pending and cannot authenticate until the initial password file has
been safely published and the matching hash activated. The data directory must
be owned by the service user and not writable by group/others. The application
exclusively creates `initial-password.txt` with mode 0600, refuses conflicts and
syncs the file and containing directory before activation. It never prints the
secret; startup logs the file's location as before.

If interrupted after file delivery, startup resumes only when the file is a
service-owned, mode-0600 regular file with a single link and its password matches
the recorded pending hash. Symlinks, hard links, FIFOs, partial/mismatched content
and unsafe permissions are refused. Missing or inconsistent delivery requires
operator recovery; it does not regenerate or consume a different configured
password. Pending state cannot create dashboard sessions.

For an active account the initial file is neither read nor recreated. After
changing a generated password, delete the stale application-generated file as
already instructed by its contents. Unknown files are never automatically
removed. Failure to clean up a stale file cannot reactivate that credential.

## Password changes and sessions

Replacement uses a database compare-and-swap on the credential hash/revision.
Hash replacement, revision increment and deletion of all dashboard sessions
commit together. Failure rolls back the whole change. Two updates based on one
credential snapshot cannot both succeed. Login creates a session only at the
revision used to verify the password, closing a concurrent verification/issuance
window. Session checks enforce revision and expiry; a password change does not
undo work that a previously authenticated request already completed.

Storage failures return static error messages; they do not echo request bodies,
passwords, hashes, tokens or driver errors. Successful change still clears the
browser cookie and requests reauthentication. Existing audit redaction applies.

## Backup, restore and downgrade

Consistent database backups include auth state/revision. Restore preserves the
credential and revokes restored sessions. Backups without auth revision migrate
as legacy databases on opening. Restored launch YAML continues to clear the
bootstrap password; reference `source-config.yaml` is not launch configuration.
Initial-password files remain excluded from backup.

An old executable can ignore these safeguards and overwrite the password from
configuration again. Downgrade is a deliberate recovery/security operation, not
a safe schema reversal: retain a consistent backup, remove stale bootstrap inputs
and assess credential/session revocation before activating older software.
Legacy hashes, backups and environment/YAML secrets remain sensitive; this change
does not encrypt plaintext configuration or remediate the separate login-resource
exhaustion risk. No deployment changes are performed automatically.
