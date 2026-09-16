import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MOD = ROOT / "src/platformcompute/phase0g_existing_alias_route_reconciliation.py"
spec = importlib.util.spec_from_file_location("p0g", MOD)
p0g = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p0g
spec.loader.exec_module(p0g)


def E(rc=0, out="", err=""):
    return p0g.p0f.CommandEvidence([], rc, out, err, 1)


def test_contract_identity_authority_and_blocks():
    c = json.loads((ROOT / "contracts/phase0g_existing_alias_route_reconciliation_v1.json").read_text())
    assert c["contract"] == p0g.CONTRACT_NAME
    assert c["authority"] == "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
    assert c["production_mutation"] == "NONE"
    assert c["ssh_config"]["required_proxyjump_alias"] == "hv"
    assert c["hard_blocks"]["marketdata_influx_retention"] == "BLOCKED_NO_AUTHORIZED_ADMIN_READ"
    assert c["hard_blocks"]["nexusdb"] == "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED"
    assert "direct_route_fallback" in c["forbidden"]


def test_literal_alias_parser_follows_include_without_wildcards(tmp_path):
    inc = tmp_path / "included.conf"
    inc.write_text("Host RedisServer *.wild !blocked\n  HostName 192.168.200.6\n")
    root = tmp_path / "config"
    root.write_text(f"Include {inc.name}\nHost MariaDB\n  HostName 192.168.200.18\n")
    got = p0g.discover_literal_ssh_aliases(root)
    assert got["aliases"] == ["MariaDB", "RedisServer"]
    assert "*.wild" not in got["aliases"]
    assert "!blocked" not in got["aliases"]


def test_effective_config_does_not_capture_identityfile(monkeypatch):
    monkeypatch.setattr(p0g.p0f, "run_cmd", lambda *a, **k: E(0, "hostname 192.168.200.6\nuser root\nidentityfile ~/.ssh/id_ed25519\nproxyjump hv\n"))
    cfg = p0g.effective_ssh_config("RedisServer")
    assert cfg["effective"]["hostname"] == "192.168.200.6"
    assert cfg["effective"]["proxyjump"] == "hv"
    assert "identityfile" not in cfg["effective"]


def test_matching_alias_requires_target_ip_and_marks_hv_proxyjump(monkeypatch):
    configs = {
        "Direct": {"alias": "Direct", "returncode": 0, "stderr": "", "effective": {"hostname": "192.168.200.6", "proxyjump": "none"}},
        "RedisServer": {"alias": "RedisServer", "returncode": 0, "stderr": "", "effective": {"hostname": "192.168.200.6", "proxyjump": "root@hv:69"}},
        "Other": {"alias": "Other", "returncode": 0, "stderr": "", "effective": {"hostname": "192.168.200.8", "proxyjump": "hv"}},
    }
    monkeypatch.setattr(p0g, "effective_ssh_config", lambda alias: configs[alias])
    got = p0g.discover_matching_aliases("192.168.200.6", ["Direct", "RedisServer", "Other"], "hv")
    assert [x["alias"] for x in got] == ["RedisServer", "Direct"]
    assert got[0]["required_proxyjump_present"] is True
    assert got[1]["required_proxyjump_present"] is False


def test_no_matching_alias_fails_closed():
    status, _ = p0g.classify_alias_route([], None, E())
    assert status == "BLOCKED_NO_EXISTING_CONFIGURED_ALIAS"


def test_matching_direct_alias_does_not_fallback():
    matches = [{"alias": "Direct", "required_proxyjump_present": False, "effective": {"hostname": "192.168.200.6"}}]
    status, _ = p0g.classify_alias_route(matches, None, E())
    assert status == "BLOCKED_NO_H1_PROXYJUMP_ALIAS"


def test_successful_configured_alias_route_classifies():
    matches = [{"alias": "RedisServer", "required_proxyjump_present": True, "effective": {"hostname": "192.168.200.6", "proxyjump": "hv"}}]
    status, _ = p0g.classify_alias_route(matches, E(0, "PLATFORM_CONFIGURED_ALIAS_ROUTE_OK\n"), E())
    assert status == "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED"


def test_forwarding_failure_classifies_without_guest_down_claim():
    matches = [{"alias": "ClientAppDB", "required_proxyjump_present": True, "effective": {"hostname": "192.168.200.19", "proxyjump": "hv"}}]
    status, reason = p0g.classify_alias_route(matches, E(255, err="Stdio forwarding request failed: Session open refused by peer"), E())
    assert status == "BLOCKED_PROXYJUMP_FORWARDING"
    assert "forward" in reason.lower()


def test_strict_alias_probe_uses_alias_not_manual_jump(monkeypatch):
    calls = []
    monkeypatch.setattr(p0g.p0f, "run_cmd", lambda argv, timeout=0: calls.append((argv, timeout)) or E())
    p0g.strict_alias_probe("RedisServer")
    argv = calls[0][0]
    assert argv[0] == "ssh"
    assert "RedisServer" in argv
    assert "-J" not in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "PasswordAuthentication=no" in argv


def test_persistence_collection_only_after_confirmed_alias_route():
    status, _ = p0g.persistence_status("BLOCKED_GUEST_AUTHORIZATION", None, "redis_persistence")
    assert status == "BLOCKED_GUEST_AUTHORIZATION"
    status, _ = p0g.persistence_status("STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED", E(0, "SERVICE_valkey=active\nPATH=/var/lib/redis\n"), "redis_persistence")
    assert status == "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED"


def test_source_contains_no_trust_weakening_or_direct_ip_fallback():
    src = MOD.read_text().lower()
    assert "stricthostkeychecking=no" not in src
    assert "userknownhostsfile=/dev/null" not in src
    assert "ssh-keyscan" not in src
    assert '"-j"' not in src
    assert "no direct-ip or manually constructed route fallback is permitted" in src
