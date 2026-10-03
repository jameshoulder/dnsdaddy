"""Exercise real installer helpers on synthetic files; no service changes."""
from pathlib import Path
import os
import pwd
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(path: str, name: str) -> str:
    script = (ROOT / path).read_text()
    start = script.index(name + "() {")
    return script[start:script.index("\n}\n", start) + 3]


class Permissions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / "config.yaml"
        self.file.write_text("http:\n  admin_password: synthetic-only\n")
        self.file.chmod(0o644)
        self.root.chmod(0o755)
        self.user = pwd.getpwuid(os.geteuid()).pw_name

    def invoke(self, native: bool, prefix: str = ""):
        path = "deploy/install.sh" if native else "deploy/install-docker.sh"
        name = "restrict_config" if native else "restrict_env_file"
        call = 'restrict_config "$1" "$2" "$3"' if native else 'ENV_FILE="$2"; restrict_env_file'
        script = 'set -uo pipefail\ndie() { printf "%s\\n" "$1" >&2; exit 1; }\n' + prefix + '\n' + function(path, name) + '\n' + call
        return subprocess.run(["bash", "-c", script, "test", str(self.root), str(self.file), self.user], text=True, capture_output=True, timeout=10)

    def test_native_restricts_and_preserves_content_owner(self):
        before = self.file.read_bytes(), self.file.stat().st_uid
        out = self.invoke(True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.root.stat().st_mode & 0o7777, 0o750)
        self.assertEqual(self.file.stat().st_mode & 0o7777, 0o640)
        self.assertEqual((self.file.read_bytes(), self.file.stat().st_uid), before)

    def test_native_preserves_service_owner_only_permissions(self):
        self.root.chmod(0o700); self.file.chmod(0o600)
        out = self.invoke(True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.root.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(self.file.stat().st_mode & 0o7777, 0o600)

    def test_native_chmod_failure_and_false_success_fail(self):
        for status in (0, 1):
            out = self.invoke(True, f'chmod() {{ return {status}; }}')
            self.assertNotEqual(out.returncode, 0)
            self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)

    def test_native_chgrp_failure_fails(self):
        self.assertNotEqual(self.invoke(True, 'chgrp() { return 1; }').returncode, 0)

    def test_native_rejects_foreign_owner(self):
        # No root is required: a fake service identity suffices for a user-owned
        # fixture. As root, change only the disposable file's owner.
        prefix = ''
        if os.geteuid() == 0:
            os.chown(self.file, 12345, os.getegid())
        else:
            prefix = f'id() {{ if [[ "$1" == -u ]]; then echo 12345; else echo {os.getegid()}; fi; }}'
        self.assertNotEqual(self.invoke(True, prefix).returncode, 0)
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)

    def test_env_is_owner_only_and_keeps_read_only_mode(self):
        for mode in (0o644, 0o400):
            self.file.chmod(mode)
            out = self.invoke(False)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(self.file.stat().st_mode & 0o777, mode & 0o700)

    def test_env_chmod_failure_and_false_success_fail(self):
        for status in (0, 1):
            out = self.invoke(False, f'chmod() {{ return {status}; }}')
            self.assertNotEqual(out.returncode, 0)
            self.assertNotIn('synthetic-only', out.stdout + out.stderr)
            self.assertEqual(self.file.stat().st_mode & 0o777, 0o644)

    def test_symlinks_and_hardlinks_rejected(self):
        target = self.root / "target"
        target.write_text("fixture")
        self.file.unlink()
        self.file.symlink_to(target)
        for native in (False, True):
            self.assertNotEqual(self.invoke(native).returncode, 0)
        self.file.unlink()
        os.link(target, self.file)
        for native in (False, True):
            self.assertNotEqual(self.invoke(native).returncode, 0)

    def test_env_stat_failure_fails(self):
        self.assertNotEqual(self.invoke(False, 'stat() { return 1; }').returncode, 0)


if __name__ == "__main__":
    unittest.main()
