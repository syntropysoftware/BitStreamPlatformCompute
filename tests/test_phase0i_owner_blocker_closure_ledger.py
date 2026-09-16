import csv
import hashlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MOD = ROOT / "src/platformcompute/phase0i_owner_blocker_closure_ledger.py"
spec = importlib.util.spec_from_file_location("p0i", MOD)
p0i = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p0i
spec.loader.exec_module(p0i)


def _rows(redis_status="BLOCKED_GUEST_AUTHORIZATION", redis_owner="SECURITY"):
    return [
        {"lane": "MariaDB18", "ip": "192.168.200.18", "status": "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED", "reason": "captured", "next_owner": "DISASTER_RECOVERY_REVIEW", "next_action": "review immutable Platform observations"},
        {"lane": "RedisServer6", "ip": "192.168.200.6", "status": redis_status, "reason": "auth", "next_owner": redis_owner, "next_action": "review existing authorization"},
        {"lane": "ClientAppDB19", "ip": "192.168.200.19", "status": "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED", "reason": "route", "next_owner": "DISASTER_RECOVERY_REVIEW", "next_action": "review route observation"},
        {"lane": "ETHService", "ip": "192.168.200.33", "status": "UNRESOLVED_REQUIRES_OWNER_EVIDENCE", "reason": "owner semantics", "next_owner": "APPLICATION_OWNER", "next_action": "provide durable-state evidence"},
        {"lane": "NodeServer", "ip": "192.168.200.8", "status": "UNRESOLVED_REQUIRES_OWNER_EVIDENCE", "reason": "owner semantics", "next_owner": "APPLICATION_OWNER", "next_action": "provide durable-state evidence"},
        {"lane": "MarketDataInfluxRetention", "ip": "", "status": "BLOCKED_NO_AUTHORIZED_ADMIN_READ", "reason": "no auth", "next_owner": "SECURITY_OR_MARKETDATA_OWNER", "next_action": "provide explicit authorization if required"},
        {"lane": "NexusDB", "ip": "192.168.200.23", "status": "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED", "reason": "not authorized", "next_owner": "SECURITY", "next_action": "provide separate implementation authorization"},
    ]


def _make_phase0h_zip(path: Path, rows=None, admitted=True, tamper=False):
    rows = rows or _rows()
    members = {}
    out = io.StringIO()
    fields = ["lane", "ip", "status", "reason", "next_owner", "next_action"]
    w = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
    w.writeheader(); w.writerows(rows)
    members["summary.csv"] = out.getvalue().encode()
    members["summary.env"] = b"AUTHORITY=PLATFORM_INFRASTRUCTURE_FACTS_ONLY\n"
    source_gate = {"status": "ACCEPTED_SOURCE_PASS", "accepted": True, "head": "a"*40, "accepted_ref": "origin/main", "accepted_ref_sha": "a"*40}
    members["source_gate.json"] = (json.dumps(source_gate, sort_keys=True)+"\n").encode()
    receipt = {"run_id": "platformcompute-phase0h-readonly-TEST", "contract": p0i.p0h.CONTRACT_NAME, "authority": "PLATFORM_INFRASTRUCTURE_FACTS_ONLY", "production_mutation": "NONE", "source_gate": source_gate, "dr_acceptance_claimed": False}
    members["receipt.json"] = (json.dumps(receipt, sort_keys=True)+"\n").encode()
    members["REPORT.md"] = b"# report\n"
    members["HANDOFF_TO_DISASTER_RECOVERY.md"] = b"# handoff\n"
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(members.items()))
    self_check = {"manifest_verification": {"status": "PASS"}, "admission": {"status": "PLATFORM_OBSERVATION_PACKET_READY_FOR_DR_REVIEW" if admitted else "PLATFORM_PACKET_INTEGRITY_FAILED"}, "dr_acceptance_claimed": False}
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            if tamper and name == "summary.env":
                data = b"tampered\n"
            zf.writestr(name, data)
        zf.writestr("MANIFEST.sha256", manifest)
        zf.writestr("SELF_CHECK.json", json.dumps(self_check, sort_keys=True)+"\n")
    return path


def test_contract_identity_and_hard_boundaries():
    c = p0i.load_contract(ROOT / "contracts/phase0i_owner_blocker_closure_ledger_v1.json")
    assert c["contract"] == p0i.CONTRACT_NAME
    assert c["authority"] == "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
    assert c["production_mutation"] == "NONE"
    assert c["required_input_admission"] == "PLATFORM_OBSERVATION_PACKET_READY_FOR_DR_REVIEW"
    assert "external message send" in c["forbidden"]
    assert "owner_authority_claim" in c["forbidden"]


def test_phase0h_packet_verification_accepts_self_verified_packet(tmp_path):
    zp = _make_phase0h_zip(tmp_path / "h.zip")
    c = p0i.load_contract(ROOT / "contracts/phase0i_owner_blocker_closure_ledger_v1.json")
    got = p0i.verify_phase0h_packet(zp, c)
    assert got["status"] == "PASS"
    assert got["source_run_id"] == "platformcompute-phase0h-readonly-TEST"
    assert len(got["rows"]) == 7


def test_phase0h_packet_verification_rejects_not_admitted_or_tampered(tmp_path):
    c = p0i.load_contract(ROOT / "contracts/phase0i_owner_blocker_closure_ledger_v1.json")
    not_ready = p0i.verify_phase0h_packet(_make_phase0h_zip(tmp_path / "notready.zip", admitted=False), c)
    assert not_ready["status"] == "FAIL"
    assert "INPUT_ADMISSION_NOT_READY" in not_ready["failures"]
    tampered = p0i.verify_phase0h_packet(_make_phase0h_zip(tmp_path / "tampered.zip", tamper=True), c)
    assert tampered["status"] == "FAIL"
    assert any("SHA256_MISMATCH" in item for item in tampered["failures"])


def test_ledger_preserves_source_status_and_builds_stable_ids():
    rows = _rows()
    a = p0i.build_current_ledger(rows, "run-a", "1"*64)
    b = p0i.build_current_ledger(rows, "run-b", "2"*64)
    by_a = {r["lane"]: r for r in a}; by_b = {r["lane"]: r for r in b}
    assert by_a["RedisServer6"]["status"] == "BLOCKED_GUEST_AUTHORIZATION"
    assert by_a["RedisServer6"]["next_owner"] == "SECURITY"
    assert by_a["RedisServer6"]["work_item_id"] == by_b["RedisServer6"]["work_item_id"]
    assert by_a["RedisServer6"]["lane_id"] == by_b["RedisServer6"]["lane_id"]
    assert by_a["MariaDB18"]["disposition"] == "READY_FOR_DR_REVIEW"
    assert by_a["ETHService"]["disposition"] == "WAITING_FOR_OWNER"


def test_compare_ledgers_deduplicates_unchanged_and_flags_changed():
    previous = p0i.build_current_ledger(_rows(), "old", "1"*64)
    current = p0i.build_current_ledger(_rows(redis_status="CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED", redis_owner="DISASTER_RECOVERY_REVIEW"), "new", "2"*64)
    changes = {r["lane"]: r for r in p0i.compare_ledgers(current, previous)}
    assert changes["MariaDB18"]["change"] == "UNCHANGED"
    assert changes["RedisServer6"]["change"] == "CHANGED"
    assert changes["RedisServer6"]["previous_next_owner"] == "SECURITY"
    assert changes["RedisServer6"]["current_next_owner"] == "DISASTER_RECOVERY_REVIEW"


def test_compare_ledgers_never_silently_closes_missing_lane():
    previous = p0i.build_current_ledger(_rows(), "old", "1"*64)
    current = [r for r in previous if r["lane"] != "NexusDB"]
    changes = {r["lane"]: r for r in p0i.compare_ledgers(current, previous)}
    assert changes["NexusDB"]["change"] == "NO_LONGER_PRESENT_REVIEW_REQUIRED"


def test_owner_handoff_is_proposal_not_authority():
    row = p0i.build_current_ledger(_rows(), "run", "1"*64)[0]
    text = p0i.owner_handoff_text(row["next_owner"], [row], "run", "1"*64)
    assert "routing proposals" in text
    assert "does not grant" in text
    assert "does not infer closure" in text


def test_previous_zip_is_verified_before_reuse(tmp_path):
    ledger = p0i.build_current_ledger(_rows(), "run", "1"*64)
    member = (json.dumps(ledger, sort_keys=True)+"\n").encode()
    manifest = f"{hashlib.sha256(member).hexdigest()}  closure_ledger.json\n"
    zp = tmp_path / "prev.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("closure_ledger.json", member)
        zf.writestr("MANIFEST.sha256", manifest)
        zf.writestr("SELF_CHECK.json", "{}\n")
    got, meta = p0i.load_previous_ledger(zp)
    assert meta["status"] == "VERIFIED_ZIP"
    assert len(got) == 7


def test_source_contains_no_execution_or_network_path():
    src = MOD.read_text().lower()
    assert "subprocess" not in src
    assert "paramiko" not in src
    assert "requests" not in src
    assert "socket" not in src
    assert "systemctl" not in src
    assert "os.system" not in src
    assert "popen(" not in src


def test_main_builds_self_verified_owner_ledger_packet(tmp_path):
    hzip = _make_phase0h_zip(tmp_path / "h.zip")
    out = tmp_path / "evidence"
    rc = p0i.main([
        "--contract", str(ROOT / "contracts/phase0i_owner_blocker_closure_ledger_v1.json"),
        "--phase0h-zip", str(hzip),
        "--output-root", str(out),
    ])
    assert rc == 0
    zips = list(out.glob("platformcompute-phase0i-offline-*.zip"))
    assert len(zips) == 1
    verification = json.loads(Path(str(zips[0]) + ".verification.json").read_text())
    assert verification["zip_verification"]["status"] == "PASS"
    assert verification["dr_acceptance_claimed"] is False
    with zipfile.ZipFile(zips[0]) as zf:
        names = set(zf.namelist())
        assert "closure_ledger.json" in names
        assert "owner_handoffs/SECURITY.md" in names
        assert "owner_handoffs/DISASTER_RECOVERY_REVIEW.md" in names
        assert "SELF_CHECK.json" in names
        summary = json.loads(zf.read("summary.json"))
        assert summary["lane_count"] == 7
        assert summary["external_write_performed"] is False
        changes = json.loads(zf.read("changes_since_previous.json"))
        assert {r["change"] for r in changes} == {"NEW"}
