import importlib.util
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MOD = ROOT / "src/platformcompute/phase0h_deterministic_route_evidence_admission.py"
spec = importlib.util.spec_from_file_location("p0h", MOD)
p0h = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p0h
spec.loader.exec_module(p0h)


def E(rc=0, out="", err="", argv=None):
    return p0h.p0f.CommandEvidence(argv or [], rc, out, err, 1)


def test_contract_identity_and_hard_boundaries():
    c = json.loads((ROOT / "contracts/phase0h_deterministic_route_evidence_admission_v1.json").read_text())
    assert c["contract"] == p0h.CONTRACT_NAME
    assert c["authority"] == "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
    assert c["production_mutation"] == "NONE"
    assert c["ssh_config"]["required_proxyjump_alias"] == "hv"
    assert c["hard_blocks"]["marketdata_influx_retention"] == "BLOCKED_NO_AUTHORIZED_ADMIN_READ"
    assert c["hard_blocks"]["nexusdb"] == "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED"
    assert "dr_acceptance_claim" in c["forbidden"]


def test_selection_scans_all_aliases_before_emission_cap(monkeypatch):
    aliases = [f"Direct{i:02d}" for i in range(10)] + ["RedisServer"]
    def cfg(alias):
        if alias == "RedisServer":
            return {"alias": alias, "returncode": 0, "stderr": "", "effective": {"hostname": "192.168.200.6", "proxyjump": "hv"}}
        return {"alias": alias, "returncode": 0, "stderr": "", "effective": {"hostname": "192.168.200.6", "proxyjump": "none"}}
    monkeypatch.setattr(p0h.p0g, "effective_ssh_config", cfg)
    got = p0h.discover_matching_aliases_deterministic("192.168.200.6", aliases, "hv", max_emitted=8)
    assert got["matching_alias_count"] == 11
    assert got["selected_alias"]["alias"] == "RedisServer"
    assert got["selected_alias"]["required_proxyjump_present"] is True
    assert got["matching_aliases_emitted"][0]["alias"] == "RedisServer"
    assert got["matching_aliases_omitted_count"] == 3


def test_selection_fails_closed_when_only_direct_aliases(monkeypatch):
    monkeypatch.setattr(
        p0h.p0g,
        "effective_ssh_config",
        lambda alias: {"alias": alias, "returncode": 0, "stderr": "", "effective": {"hostname": "192.168.200.18", "proxyjump": "none"}},
    )
    sel = p0h.discover_matching_aliases_deterministic("192.168.200.18", ["MariaDB", "DB"], "hv", max_emitted=1)
    status, _ = p0h.classify_route(sel, None, E())
    assert status == "BLOCKED_NO_H1_PROXYJUMP_ALIAS"


def test_safe_command_evidence_replaces_long_remote_body_with_digest():
    remote = "printf x\\n" * 30
    ev = E(0, "ok\n", "", ["ssh", "-o", "BatchMode=yes", "RedisServer", remote])
    got = p0h.safe_command_evidence(ev)
    assert got["argv"][-1] == "<REMOTE_COMMAND_REDACTED_TO_DIGEST>"
    assert got["remote_command"]["remote_command_bytes"] == len(remote.encode())
    assert len(got["remote_command"]["remote_command_sha256"]) == 64
    assert remote not in json.dumps(got)


def test_safe_command_evidence_preserves_short_probe():
    ev = E(0, "ok\n", "", ["ssh", "RedisServer", "printf ok"])
    got = p0h.safe_command_evidence(ev)
    assert got["argv"][-1] == "printf ok"
    assert got["remote_command"] is None


def test_next_owner_routes_security_boundaries_without_implementation():
    owner, action = p0h.next_owner_for_status("RedisServer6", "BLOCKED_STRICT_HOST_KEY_TRUST")
    assert owner == "SECURITY"
    assert "must not enroll" in action
    owner, action = p0h.next_owner_for_status("NexusDB", "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED")
    assert owner == "SECURITY"
    assert "implementation authorization" in action


def test_admission_is_platform_review_readiness_not_dr_acceptance():
    rows = [
        {"lane": "MariaDB18", "status": "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED"},
        {"lane": "RedisServer6", "status": "BLOCKED_GUEST_AUTHORIZATION"},
        {"lane": "ClientAppDB19", "status": "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED"},
    ]
    got = p0h.admission_classification(rows, True)
    assert got["status"] == "PLATFORM_OBSERVATION_PACKET_READY_FOR_DR_REVIEW"
    assert got["dr_review_ready"] is True
    assert "does not assert" in got["meaning"]


def test_directory_and_zip_integrity_verification(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "a.txt").write_text("a\n")
    (run / "b.txt").write_text("b\n")
    manifest = "".join(f"{p0h.p0f.sha256(run / name)}  {name}\n" for name in ("a.txt", "b.txt"))
    mp = run / "MANIFEST.sha256"
    mp.write_text(manifest)
    assert p0h.verify_run_directory(run, mp)["status"] == "PASS"
    zp = tmp_path / "packet.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.write(run / "a.txt", "a.txt")
        zf.write(run / "b.txt", "b.txt")
        zf.write(mp, "MANIFEST.sha256")
        zf.writestr("SELF_CHECK.json", "{}\n")
    assert p0h.verify_zip(zp, manifest)["status"] == "PASS"


def test_zip_verifier_detects_member_mismatch(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "a.txt").write_text("a\n")
    manifest = f"{p0h.p0f.sha256(run / 'a.txt')}  a.txt\n"
    zp = tmp_path / "packet.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("a.txt", "tampered\n")
        zf.writestr("MANIFEST.sha256", manifest)
    got = p0h.verify_zip(zp, manifest)
    assert got["status"] == "FAIL"
    assert any("SHA256_MISMATCH" in x for x in got["failures"])


def test_source_contains_no_trust_weakening_or_mutation():
    src = MOD.read_text().lower()
    assert "stricthostkeychecking=no" not in src
    assert "userknownhostsfile=/dev/null" not in src
    assert "ssh-keyscan" not in src
    assert "subprocess" not in src
    assert "systemctl restart" not in src
    assert "virsh start" not in src
    assert "virsh destroy" not in src


def test_main_builds_self_verified_immutable_packet(tmp_path, monkeypatch):
    monkeypatch.setattr(
        p0h.p0f,
        "verify_accepted_source",
        lambda ref: {
            "status": "ACCEPTED_SOURCE_PASS",
            "accepted": True,
            "head": "a" * 40,
            "accepted_ref": ref,
            "accepted_ref_sha": "a" * 40,
            "worktree_clean": True,
            "reasons": [],
        },
    )
    aliases = ["MariaDB", "RedisServer", "ClientAppDB"]
    monkeypatch.setattr(
        p0h.p0g,
        "discover_literal_ssh_aliases",
        lambda *a, **k: {"root": "~/.ssh/config", "files_examined_count": 1, "literal_alias_count": 3, "aliases": aliases, "warnings": [], "privacy_rule": "bounded"},
    )
    mapping = {
        "hv": {"hostname": "192.168.200.1", "proxyjump": "none"},
        "MariaDB": {"hostname": "192.168.200.18", "proxyjump": "hv"},
        "RedisServer": {"hostname": "192.168.200.6", "proxyjump": "hv"},
        "ClientAppDB": {"hostname": "192.168.200.19", "proxyjump": "hv"},
    }
    monkeypatch.setattr(
        p0h.p0g,
        "effective_ssh_config",
        lambda alias: {"alias": alias, "returncode": 0, "stderr": "", "effective": mapping[alias]},
    )
    monkeypatch.setattr(p0h.p0g, "hypervisor_metadata_alias", lambda *a, **k: E(0, "DOMAIN=test\n", argv=["ssh", "hv", "virsh"] ))
    monkeypatch.setattr(p0h.p0g, "strict_alias_probe", lambda alias: E(0, "PLATFORM_CONFIGURED_ALIAS_ROUTE_OK\n", argv=["ssh", alias, "printf ok"]))
    def collect(alias, collector):
        if collector == "route_only":
            return None
        text = "SERVICE_test=active\nPATH=/var/lib/test\n"
        return E(0, text, argv=["ssh", alias, "x" * 200])
    monkeypatch.setattr(p0h.p0g, "collect_via_alias", collect)

    out = tmp_path / "evidence"
    rc = p0h.main([
        "--contract", str(ROOT / "contracts/phase0h_deterministic_route_evidence_admission_v1.json"),
        "--output-root", str(out),
    ])
    assert rc == 0
    zips = list(out.glob("platformcompute-phase0h-readonly-*.zip"))
    assert len(zips) == 1
    verification = json.loads(Path(str(zips[0]) + ".verification.json").read_text())
    assert verification["zip_verification"]["status"] == "PASS"
    assert verification["platform_admission"]["status"] == "PLATFORM_OBSERVATION_PACKET_READY_FOR_DR_REVIEW"
    with zipfile.ZipFile(zips[0]) as zf:
        assert "SELF_CHECK.json" in zf.namelist()
        assert "MANIFEST.sha256" in zf.namelist()
        mariadb = json.loads(zf.read("MariaDB18.json"))
        assert mariadb["alias_selection"]["selected_alias"]["alias"] == "MariaDB"
        assert mariadb["persistence_collection"]["argv"][-1] == "<REMOTE_COMMAND_REDACTED_TO_DIGEST>"
