#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_DIR = ROOT / "src" / "platformcompute"
sys.path.insert(0, str(MODULE_DIR))
MODULE = MODULE_DIR / "phase0c_focused_infrastructure_completion.py"
spec = importlib.util.spec_from_file_location("pc_phase0c", MODULE)
pc = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = pc
spec.loader.exec_module(pc)


class Phase0CTests(unittest.TestCase):
    def test_contract_identity(self):
        self.assertEqual(pc.CONTRACT, "bitstream-platformcompute-phase0c-focused-infrastructure-completion-v1")
        self.assertEqual(pc.AUTHORITY, "PLATFORM_INFRASTRUCTURE_FACTS_ONLY")
        self.assertEqual(pc.MUTATION_POLICY, "READ_ONLY_NO_MUTATION")

    def test_current_config_requires_nexusdb_implementation_false(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "cfg.json"
            cfg = {
                "mariadb18": {}, "redisserver6": {}, "ethservice": {}, "nodeserver": {},
                "clientappdb19": {}, "marketdata_influx": {},
                "nexusdb": {"platform_implementation_authorized": True},
            }
            p.write_text(json.dumps(cfg), encoding="utf-8")
            with self.assertRaises(ValueError):
                pc.load_config(p)

    def test_nexusdb_lane_never_implements_reader(self):
        entry = {"ssh_target": "NexusDB", "expected_ip": "192.168.200.23",
                 "security_decision": "TARGET_SPECIFIC_READER_APPROVED",
                 "allowed_identity": "DEDICATED_NON_ROOT_PURPOSE_BOUND_NEXUSDB_METADATA_READER",
                 "platform_implementation_authorized": False}
        with mock.patch.object(pc, "route_observation", return_value={"ssh_config": {"status": "PASS"}}):
            out = pc.nexusdb_lane(entry)
        self.assertEqual(out["action"], "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED")
        self.assertEqual(out["reader_implemented"], "NO")
        self.assertFalse(out["reader_implementation_attempted"])
        self.assertFalse(out["ssh_connection_attempted"])

    def test_marketdata_influx_default_is_blocked_without_authorized_capability(self):
        entry = {"endpoint": "http://192.168.200.27:8086", "physical_target": "H1:CBAdvMarketDataDB:192.168.200.27",
                 "org": "BitStream", "bucket": "CBAdvMarketData-BTC-USD"}
        env = {k: v for k, v in os.environ.items() if not k.startswith("BITSTREAM_PLATFORMCOMPUTE_MARKETDATA_INFLUX_")}
        with mock.patch.dict(os.environ, env, clear=True):
            out = pc.marketdata_influx_lane(entry, 5)
        self.assertEqual(out["status"], "BLOCKED_NO_AUTHORIZED_ADMIN_READ")
        self.assertFalse(out["credential_search_performed"])
        self.assertFalse(out["token_persisted"])

    def test_owner_scope_does_not_connect_to_guest(self):
        entry = {"ssh_target": "ETHService", "expected_ip": "", "owner": "UNRESOLVED_REQUIRES_OWNER_EVIDENCE"}
        with mock.patch.object(pc, "resolved_host_from_local_evidence", return_value={"exact_host_vm_identity": "UNRESOLVED"}):
            out = pc.owner_scope_lane(entry)
        self.assertFalse(out["guest_connection_attempted"])
        self.assertFalse(out["security_exception_requested"])
        self.assertEqual(out["status"], "BLOCKED_SCOPE_INCOMPLETE_NO_NEW_READER_REQUESTED")

    def test_clientappdb_route_failure_stays_unresolved(self):
        with mock.patch.object(pc, "ssh_remote_probe", return_value=(None, {"ssh_batch_test": {"reason": "BLOCKED_SSH_OR_REMOTE_PROBE_FAILED"}})):
            out = pc.clientappdb19_lane({"ssh_target": "ClientAppDB", "expected_ip": "192.168.200.19"}, 5)
        self.assertEqual(out["classification"], "UNRESOLVED")
        self.assertEqual(out["data_bearing"], "UNRESOLVED")

    def test_remote_probe_compiles_and_has_no_mutating_commands(self):
        compile(pc.REMOTE_PROBE, "<phase0c_remote_probe>", "exec")
        probe = pc.REMOTE_PROBE.lower()
        banned = [
            "sudo ", "ssh-keyscan", "stricthostkeychecking=no", "systemctl restart", "systemctl start",
            "systemctl stop", "systemctl enable", "systemctl disable", "useradd ", "usermod ", "passwd ",
            "known_hosts", "redis-cli --scan", " keys *", "flushall", "flushdb",
            "mysqldump ", "mariabackup --backup", "mount -o", "mkfs",
        ]
        for token in banned:
            self.assertNotIn(token, probe)

    def test_summary_contains_required_safety_fields(self):
        results = {
            "mariadb18": {"status": "BLOCKED", "blocker": "X", "observed": None},
            "redisserver6": {"status": "BLOCKED", "blocker": "Y", "observed": None},
            "ethservice": {"host": "UNRESOLVED", "owner": "UNRESOLVED", "durable_paths": [], "rebuildable_paths": [], "durable_size": "UNRESOLVED", "rebuild_source": "UNRESOLVED", "owner_evidence_path_available": False, "blocker": "Z"},
            "nodeserver": {"host": "UNRESOLVED", "owner": "UNRESOLVED", "durable_paths": [], "rebuildable_paths": [], "durable_size": "UNRESOLVED", "rebuild_source": "UNRESOLVED", "owner_evidence_path_available": False, "blocker": "Z"},
            "clientappdb19": {"classification": "UNRESOLVED", "data_bearing": "UNRESOLVED", "blocker": "X", "next_read_only_action": "NONE"},
            "marketdata_influx": {"status": "BLOCKED_NO_AUTHORIZED_ADMIN_READ", "metadata": None, "blocker": "BLOCKED_NO_AUTHORIZED_ADMIN_READ"},
            "nexusdb": {"action": "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED", "platform_implementation_authorization": "NO", "route_reconciled": "NO", "host_key_attested_out_of_band": "NO", "collector_identity_pinned": "NO", "reader_implemented": "NO", "blocker": "NO_AUTH"},
        }
        s = pc.build_summary(results)
        self.assertEqual(s["PRODUCTION_MUTATION"], "NONE")
        self.assertEqual(s["SSH_TRUST_WEAKENING"], "NONE")
        self.assertEqual(s["BACKUP_RESTORE_EXECUTION"], "NONE")
        self.assertEqual(s["NEXUSDB_READER_IMPLEMENTED"], "NO")


if __name__ == "__main__":
    unittest.main()
