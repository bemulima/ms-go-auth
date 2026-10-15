"""Exercise the real policy script in an isolated repository-shaped fixture."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check-agent-policy.sh"


class AgentPolicyTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.script = SCRIPT.read_text()
        required = re.search(r'required_files="([^"]+)"', self.script).group(1)
        for name in required.split():
            self.write(name, "fixture\n")
        self.write("README.md", "fixture\n")
        dirs = re.search(r'for architecture_dir in (.*?); do', self.script).group(1)
        for name in dirs.split() + ["internal/domain", "internal/usecase"]:
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def run_policy(self):
        return subprocess.run(
            ["sh", "-c", self.script], cwd=self.root,
            text=True, capture_output=True, check=False,
        )

    def test_generated_bundle_does_not_block_valid_sources(self):
        self.write(".ai/testing/policy/policy-runner.cjs", '"/wiki/historical";\n')
        result = self.run_policy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("agent-policy: ok", result.stdout)

    def test_source_documentation_and_contracts_still_reject_obsolete_paths(self):
        for name in ["AGENTS.md", "README.md", "docs/flow.md",
                     ".ai/contracts/source.yaml", ".ai/contracts/source.json",
                     "docs/policy-runner.cjs"]:
            with self.subTest(path=name):
                self.write(name, "reference: /wiki/obsolete\n")
                result = self.run_policy()
                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stdout)
                self.assertIn("obsolete external knowledge reference found", result.stderr)
                self.write(name, "fixture\n")

    def test_domain_import_guard_remains_active(self):
        self.write("internal/domain/model.go", 'import "gorm.io/gorm"\n')
        result = self.run_policy()
        self.assertEqual(result.returncode, 1)
        self.assertIn("domain/usecase imports an outer implementation", result.stderr)


if __name__ == "__main__":
    unittest.main()
