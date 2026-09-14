import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOD = ROOT / "src/platformcompute/phase0f_strict_proxyjump_persistence_evidence.py"
spec = importlib.util.spec_from_file_location("p0f", MOD)
p0f = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p0f
spec.loader.exec_module(p0f)


def E(rc=0, out="", err=""):
    return p0f.CommandEvidence([], rc, out, err, 1)


def test_contract_identity_authority_and_hard_blocks():
    c = json.loads((ROOT / "contracts/phase0f_strict_proxyjump_persistence_evidence_v1.json").read_text())
    assert c["contract"] == p0f.CONTRACT_NAME
    assert c["authority"] == "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
    assert c["production_mutation"] == "NONE"
    assert c["accepted_source_ref"] == "origin/main"
    assert c["hard_blocks"]["marketdata_influx_retention"] == "BLOCKED_NO_AUTHORIZED_ADMIN_READ"
    assert c["hard_blocks"]["nexusdb"] == "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED"


def test_strict_proxyjump_is_explicit_and_trust_not_weakened():
    src = MOD.read_text().lower()
    assert '"-j", jump' in src
    assert 'stricthostkeychecking=yes' in src
    assert 'passwordauthentication=no' in src
    assert 'kbdinteractiveauthentication=no' in src
    assert '["ssh-keyscan"' not in src
    assert "['ssh-keyscan'" not in src
    assert '["sudo"' not in src
    assert "['sudo'" not in src


def test_proxyjump_forwarding_classification():
    s, _ = p0f.classify_jump(True, E(255, err="stdio forwarding request failed: Session open refused by peer"), E())
    assert s == "BLOCKED_PROXYJUMP_FORWARDING"


def test_proxyjump_host_key_classification():
    s, _ = p0f.classify_jump(True, E(255, err="Host key verification failed"), E())
    assert s == "BLOCKED_STRICT_HOST_KEY_TRUST"


def test_proxyjump_guest_auth_classification():
    s, _ = p0f.classify_jump(True, E(255, err="Permission denied (publickey)."), E())
    assert s == "BLOCKED_GUEST_AUTHORIZATION"


def test_successful_route_enables_evidence_classification():
    route, _ = p0f.classify_jump(True, E(0, out="PLATFORM_PROXYJUMP_GUEST_OK"), E())
    assert route == "STRICT_PROXYJUMP_GUEST_SSH_CONFIRMED"
    status, _ = p0f.persistence_status(route, E(0, out="SERVICE_mariadb=active\nPATH=/var/lib/mysql\n"), "mariadb_persistence")
    assert status == "ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED"


def test_route_only_lane_does_not_collect_persistence():
    status, reason = p0f.persistence_status("STRICT_PROXYJUMP_GUEST_SSH_CONFIRMED", None, "route_only")
    assert status == "STRICT_PROXYJUMP_GUEST_SSH_CONFIRMED"
    assert "route-only" in reason


def test_mariadb_collector_avoids_database_login_and_config_contents():
    text = p0f.MARIADB_REMOTE.lower()
    assert "mariadb -nbe" not in text
    assert "mysql -nbe" not in text
    assert "show variables" not in text
    assert "cat /etc" not in text
    assert "grep /etc" not in text
    assert "process environment" in text


def test_redis_collector_never_enumerates_keys_or_values():
    text = p0f.REDIS_REMOTE.lower()
    forbidden_commands = [" KEYS", " SCAN", " GET", " MGET", " DUMP"]
    for command in forbidden_commands:
        assert f'\"$cli\" --no-auth-warning{command.lower()}' not in text
    assert "dbsize" in text
    assert "info persistence" in text
    assert "info replication" in text


def test_secret_redaction():
    assert "REDACTED" in p0f.redact("password=hunter2")
    assert "hunter2" not in p0f.redact("password=hunter2")


def test_accepted_source_gate_requires_head_ref_match_and_clean(monkeypatch):
    responses = iter([
        E(0, "abc\n", ""),
        E(0, "abc\n", ""),
        E(0, "", ""),
    ])
    monkeypatch.setattr(p0f, "run_cmd", lambda *args, **kwargs: next(responses))
    result = p0f.verify_accepted_source("origin/main")
    assert result["accepted"] is True
    assert result["status"] == "ACCEPTED_SOURCE_PASS"


def test_accepted_source_gate_blocks_mismatch(monkeypatch):
    responses = iter([
        E(0, "abc\n", ""),
        E(0, "def\n", ""),
        E(0, "", ""),
    ])
    monkeypatch.setattr(p0f, "run_cmd", lambda *args, **kwargs: next(responses))
    result = p0f.verify_accepted_source("origin/main")
    assert result["accepted"] is False
    assert "HEAD_NOT_ACCEPTED_REF" in result["reasons"]
