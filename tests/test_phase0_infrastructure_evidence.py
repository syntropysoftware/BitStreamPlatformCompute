#!/usr/bin/env python3
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "platformcompute" / "phase0_infrastructure_evidence.py"
spec = importlib.util.spec_from_file_location("pc_phase0", MODULE)
pc = importlib.util.module_from_spec(spec)
assert spec.loader is not None
import sys
sys.modules[spec.name] = pc
spec.loader.exec_module(pc)


class Phase0Tests(unittest.TestCase):
    def test_parse_targets(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "targets.tsv"
            p.write_text("T1\thost1\t10.0.0.1\tmariadb,redis\tnote\n", encoding="utf-8")
            rows = pc.parse_targets(p)
            self.assertEqual(rows[0].target_id, "T1")
            self.assertEqual(rows[0].scopes, ["mariadb", "redis"])

    def test_unsafe_target_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "targets.tsv"
            p.write_text("bad id\thost1\t10.0.0.1\tmariadb\tnote\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                pc.parse_targets(p)

    def test_error_classification(self):
        self.assertEqual(pc.classify_ssh_error("Host key verification failed."), "BLOCKED_HOST_KEY_NOT_PREAPPROVED")
        self.assertEqual(pc.classify_ssh_error("Permission denied (publickey)."), "BLOCKED_AUTHORIZATION_OR_IDENTITY")

    def test_remote_probe_contains_no_sudo_or_trust_weakening(self):
        probe = pc.REMOTE_PROBE.lower()
        self.assertNotIn("sudo ", probe)
        self.assertNotIn("stricthostkeychecking=no", probe)
        self.assertNotIn("ssh-keyscan", probe)

    def test_remote_probe_python_syntax(self):
        compile(pc.REMOTE_PROBE, "<remote_probe>", "exec")

    def test_contract_identity(self):
        self.assertEqual(pc.AUTHORITY, "PLATFORM_INFRASTRUCTURE_FACTS_ONLY")
        self.assertEqual(pc.MUTATION_POLICY, "READ_ONLY_NO_MUTATION")


if __name__ == "__main__":
    unittest.main()
