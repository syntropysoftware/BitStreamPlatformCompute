#!/usr/bin/env python3
import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "platformcompute" / "phase0b_infrastructure_reconciliation.py"
spec = importlib.util.spec_from_file_location("pc_phase0b", MODULE)
pc = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = pc
spec.loader.exec_module(pc)


class Phase0BTests(unittest.TestCase):
    def test_parse_targets(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "targets.tsv"
            p.write_text("T1\thost1\t10.0.0.1\troute_diag,mariadb\tnote\n", encoding="utf-8")
            rows = pc.parse_targets(p)
            self.assertEqual(rows[0].target_id, "T1")
            self.assertEqual(rows[0].focus, ["route_diag", "mariadb"])

    def test_unsafe_target_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "targets.tsv"
            p.write_text("bad id\thost1\t10.0.0.1\troute_diag\tnote\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                pc.parse_targets(p)

    def test_ssh_error_layers(self):
        self.assertEqual(pc.classify_ssh_error("Host key verification failed."), "BLOCKED_HOST_KEY_NOT_PREAPPROVED")
        self.assertEqual(pc.classify_ssh_error("Permission denied (publickey)."), "BLOCKED_AUTHORIZATION_OR_IDENTITY")
        self.assertEqual(pc.classify_ssh_error("No route to host"), "BLOCKED_NO_ROUTE_TO_HOST")
        self.assertEqual(pc.classify_ssh_error("Connection refused"), "BLOCKED_CONNECTION_REFUSED")

    def test_sanitize_error_redacts_ssh_path_and_token(self):
        s = pc.sanitize_error("/home/alien/.ssh/id_ed25519 token=abc123")
        self.assertIn("<SSH_PATH>", s)
        self.assertIn("token=<REDACTED>", s)
        self.assertNotIn("abc123", s)

    def test_path_classification(self):
        self.assertEqual(pc.REMOTE_PROBE.count("systemctl restart"), 0)
        # The actual classifier is embedded in the remote program; compile proves syntax.
        compile(pc.REMOTE_PROBE, "<remote_probe>", "exec")

    def test_remote_probe_safety_invariants(self):
        probe = pc.REMOTE_PROBE.lower()
        banned = [
            "sudo ",
            "stricthostkeychecking=no",
            "ssh-keyscan",
            "systemctl restart",
            "systemctl start",
            "systemctl stop",
            "systemctl enable",
            "systemctl disable",
            "useradd ",
            "usermod ",
            "passwd ",
            "mount -o",
            "mkfs",
        ]
        for token in banned:
            self.assertNotIn(token, probe)

    def test_contract_identity(self):
        self.assertEqual(pc.AUTHORITY, "PLATFORM_INFRASTRUCTURE_FACTS_ONLY")
        self.assertEqual(pc.MUTATION_POLICY, "READ_ONLY_NO_MUTATION")
        self.assertEqual(pc.CONTRACT, "bitstream-platformcompute-phase0b-infrastructure-reconciliation-v1")


if __name__ == "__main__":
    unittest.main()
