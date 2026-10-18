# Patch review follow-up: REV-01 and REV-02

Both supplied findings were independently reproduced against complete source at
c5a8f0e59716f401b20e2e93ccc61f993220c3d9 before corrections. This is a narrow
follow-up, not another remediation stage or dependency update.

## REV-01: fatal Observatory errors must retain their identity

The indicators-array opener translated every failed read into a new generic
"not an array" error. This lost cancellation, deadline and resource-limit identity.
Candidate construction also skipped wrapped reader/cache cancellation/deadline
errors when the outer context was still live, or returned an unrelated cache error
when its parent context had just canceled. Initial cache loading could consequently
return nil or a generic error; the existing startup guard distinguishes fatal
errors using errors.Is, so a timeout could enter the warning-and-continue path.

The array opener now returns cancellation/deadline/resource errors intact and keeps
its existing safe structural error for ordinary malformed input. Candidate building
returns an expired parent context error and treats wrapped operational errors as
fatal independently of outer context state. No candidate is published on these
failures. The existing main startup guard remains unchanged: these sentinel errors
cause startup to return before listeners open. Credential-safe classifications and
all byte/record/claim/memory/time limits remain intact.

Regressions cover wrapped canceled/deadline/limit errors at the array delimiter,
a counted-reader byte-limit failure at that same boundary, fatal errors through
public initial LoadFromCache, a genuinely expired initial deadline, and parent
cancellation concurrent with an ordinary cache error. Assertions include errors.Is,
no skipped-feed warning and no Holder pointer/generation change. Source inspection
verifies the unchanged startup branch; no daemon startup is executed in these tests.

## REV-02: restore and recovery must share a confined notice location

Restore wrote the notice under the destination root, while recover-admin was
confined to destination/data. Existing CLI tests had manufactured their notice
inside data and therefore missed the real mismatch. End-to-end reproduction using
an authenticated synthetic legacy pending archive showed correct proof activated
the original hash and revoked sessions but left the actual Restore-created notice.
No password reset or authentication bypass was reproduced.

New restores write data/ADMIN_RECOVERY_REQUIRED.json. Restore and recover-admin
share one basename constant. Recovery still removes the notice solely through its
pinned data root: no parent-root open, path traversal or unconfined removal is added.
The data directory passed to -data-dir remains the same. See docs/recovery.md.

The end-to-end regression generates an encrypted format-1 pending archive entirely
from synthetic temporary data, calls real backup.Restore, then calls the offline
command function with data as its root. It checks the actual notice location,
incorrect-proof preservation of hash/state/sessions/notice, successful proof with
unchanged hash/source and advanced revision, all session rows removed and actual
notice cleaned. A parent sentinel remains untouched. A separate notice symlink
case confirms only the leaf is unlinked and its target outside data is unchanged.
No fixture database, archive, secret or generated binary is committed.

Older already-restored trees may retain a historical parent notice. The command
intentionally does not escape its root to remove it. An operator can review that
informational leftover after verifying activation; DB state remains authoritative.
RESTORE.txt is historical provenance, not current credential state or authorization.

## Validation and remaining limits

Before/after evidence and exact final commands/counts are retained separately in
the audit workspace's review-followup report. The relevant blocklist, backup, CLI,
store and selected authentication/restore tests run in offline isolation with race
checks. No dependency version, production system, REA/Ghidra, push, PR, merge or
deployment is included. Prior dependency advisory remediation, Linux runtime/
integration acceptance and independent post-remediation binary verification remain
outstanding. The stricter startup capacity policy and required preflight remain.
