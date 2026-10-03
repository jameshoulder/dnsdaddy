"""Guard against reporting a successful tee instead of a failed test command."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkflowEvidence(unittest.TestCase):
    def test_failed_command_through_tee_is_not_success(self):
        run = subprocess.run(["bash", "-euo", "pipefail", "-c", "false | tee /dev/null"], capture_output=True)
        self.assertNotEqual(run.returncode, 0)

    def test_privacy_workflow_enforces_pipeline_failure(self):
        workflow = (ROOT / ".github/workflows/privacy-regressions.yml").read_text()
        self.assertIn("defaults:\n  run:\n    shell: bash", workflow)
        for block in workflow.split("run: |\n")[1:]:
            self.assertTrue(block.lstrip().startswith("set -euo pipefail"))
        self.assertNotIn("continue-on-error", workflow)
        self.assertIn("go test -race -count=1 -timeout=1m ./internal/retention", workflow)
        self.assertIn("--tmpfs /tmp:rw,noexec,nosuid,size=128m", workflow)


if __name__ == "__main__":
    unittest.main()
