import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOD = ROOT / "src/platformcompute/phase0e_authorized_route_diagnostics.py"
spec = importlib.util.spec_from_file_location("p0e", MOD)
p0e = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = p0e
spec.loader.exec_module(p0e)


def test_contract_identity_and_hard_blocks():
    c = json.loads((ROOT / "contracts/phase0e_authorized_route_diagnostics_v1.json").read_text())
    assert c["contract"] == p0e.CONTRACT_NAME
    assert c["authority"] == "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
    assert c["hard_blocks"]["marketdata_influx_retention"] == "BLOCKED_NO_AUTHORIZED_ADMIN_READ"
    assert c["hard_blocks"]["nexusdb"] == "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED"


def test_no_forbidden_trust_weakening_in_source():
    src = MOD.read_text().lower()
    assert "stricthostkeychecking=yes" in src
    assert "ssh-keyscan" not in src
    assert "userknownhostsfile=/dev/null" in src  # only as forbidden-pattern guard
    assert "sudo -" not in src
    assert "sudo\t" not in src


def test_route_classification_tcp_block():
    E = p0e.CommandEvidence
    s, _ = p0e.classify(True, E([],7,"","",1), E([],125,"","",0), E([],0,"","",1))
    assert s == "BLOCKED_GATEWAY_TO_GUEST_TCP"


def test_route_classification_host_key_block():
    E = p0e.CommandEvidence
    s, _ = p0e.classify(True, E([],0,"REACHABLE","",1), E([],255,"","Host key verification failed",1), E([],0,"DOMAIN=x","",1))
    assert s == "BLOCKED_STRICT_HOST_KEY_TRUST"


def test_direct_tcp_is_non_authoritative_label_present():
    src = MOD.read_text()
    assert "local_direct_tcp_non_authoritative" in src
    assert "not proof of guest downtime" in src
