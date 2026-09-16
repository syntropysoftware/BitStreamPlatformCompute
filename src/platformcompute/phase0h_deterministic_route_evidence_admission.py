from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from src.platformcompute import phase0f_strict_proxyjump_persistence_evidence as p0f
from src.platformcompute import phase0g_existing_alias_route_reconciliation as p0g

CONTRACT_NAME = "bitstream-platformcompute-phase0h-deterministic-route-evidence-admission-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
PRODUCTION_MUTATION = "NONE"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def discover_matching_aliases_deterministic(
    ip: str,
    aliases: Iterable[str],
    required_proxyjump_alias: str,
    max_emitted: int = 8,
) -> Dict[str, Any]:
    """Scan every bounded literal alias before limiting emitted evidence.

    Phase-0G stopped collecting matches as soon as max_matches was reached. If many
    direct aliases sorted before a valid H1 ProxyJump alias, a permitted route could
    be missed. Phase-0H evaluates all aliases within the already-bounded discovery
    set, ranks valid H1 routes first, and only then caps what is emitted.
    """
    all_matches: List[Dict[str, Any]] = []
    config_errors = 0
    for alias in sorted(set(aliases), key=str.lower):
        cfg = p0g.effective_ssh_config(alias)
        if cfg.get("returncode") != 0:
            config_errors += 1
        eff = cfg.get("effective", {})
        if eff.get("hostname") != ip:
            continue
        cfg["required_proxyjump_present"] = p0g._proxyjump_contains(eff, required_proxyjump_alias)
        all_matches.append(cfg)

    all_matches.sort(
        key=lambda x: (
            not bool(x.get("required_proxyjump_present")),
            str(x.get("alias", "")).lower(),
        )
    )
    emitted = all_matches[: max(0, int(max_emitted))]
    selected = next((m for m in all_matches if m.get("required_proxyjump_present")), None)
    return {
        "matching_alias_count": len(all_matches),
        "matching_aliases_emitted": emitted,
        "matching_aliases_omitted_count": max(0, len(all_matches) - len(emitted)),
        "effective_config_error_count": config_errors,
        "selected_alias": selected,
        "selection_rule": "Evaluate the complete bounded literal-alias set, prefer aliases whose effective route contains the required hv ProxyJump, then sort deterministically by alias. Evidence emission is capped only after selection.",
    }


def safe_command_evidence(ev: Optional[p0f.CommandEvidence]) -> Optional[Dict[str, Any]]:
    """Keep transport evidence while replacing any remote command body with a digest.

    The collectors contain only allow-listed commands, but embedding the entire remote
    program repeatedly in evidence adds noise and increases the chance that future
    changes accidentally expose sensitive command text. Local SSH options and target
    alias remain visible; the final remote command is represented by length + SHA-256.
    """
    if ev is None:
        return None
    argv = list(ev.argv)
    remote_meta: Optional[Dict[str, Any]] = None
    if argv and argv[0] == "ssh" and len(argv) >= 2:
        remote = argv[-1]
        if isinstance(remote, str) and ("\n" in remote or len(remote) > 120):
            raw = remote.encode("utf-8", errors="replace")
            remote_meta = {
                "remote_command_sha256": _sha256_bytes(raw),
                "remote_command_bytes": len(raw),
            }
            argv[-1] = "<REMOTE_COMMAND_REDACTED_TO_DIGEST>"
    return {
        "argv": argv,
        "returncode": ev.returncode,
        "stdout": ev.stdout,
        "stderr": ev.stderr,
        "elapsed_ms": ev.elapsed_ms,
        "remote_command": remote_meta,
    }


def classify_route(selection: Dict[str, Any], probe: Optional[p0f.CommandEvidence], vm_meta: p0f.CommandEvidence) -> Tuple[str, str]:
    matches = selection["matching_aliases_emitted"]
    selected = selection.get("selected_alias")
    if selection["matching_alias_count"] == 0:
        return "BLOCKED_NO_EXISTING_CONFIGURED_ALIAS", "no literal workstation SSH alias resolves to the scoped target IP"
    if selected is None:
        return "BLOCKED_NO_H1_PROXYJUMP_ALIAS", "matching aliases exist but none resolves through the required existing hv ProxyJump"
    # p0g's classifier needs the selected route first; emitted evidence can be capped.
    selected_first = [selected] + [m for m in matches if m.get("alias") != selected.get("alias")]
    return p0g.classify_alias_route(selected_first, probe, vm_meta)


def persistence_status(route_status: str, collector: Optional[p0f.CommandEvidence], collector_name: str) -> Tuple[str, str]:
    return p0g.persistence_status(route_status, collector, collector_name)


def next_owner_for_status(lane: str, status: str) -> Tuple[str, str]:
    if lane in {"ETHService", "NodeServer"}:
        return "APPLICATION_OWNER", "provide authoritative durable-versus-rebuildable state and rebuild-source evidence"
    if lane == "MarketDataInfluxRetention":
        return "SECURITY_OR_MARKETDATA_OWNER", "provide explicit administrative-read authorization if this evidence is required"
    if lane == "NexusDB":
        return "SECURITY", "separate Platform implementation authorization is required before any reader implementation"
    if status in {"BLOCKED_PROXYJUMP_FORWARDING", "BLOCKED_CONFIGURED_ROUTE_TIMEOUT", "BLOCKED_CONFIGURED_ROUTE_REFUSED"}:
        return "NETWORK_PLATFORM_REVIEW", "review the existing authorized route/forwarding layer without changing trust or access"
    if status == "BLOCKED_STRICT_HOST_KEY_TRUST":
        return "SECURITY", "review the existing trust path; Platform must not enroll or weaken host-key verification"
    if status == "BLOCKED_GUEST_AUTHORIZATION":
        return "SECURITY", "review whether the existing identity is authorized; Platform must not create or discover credentials"
    if status in {"BLOCKED_NO_EXISTING_CONFIGURED_ALIAS", "BLOCKED_NO_H1_PROXYJUMP_ALIAS"}:
        return "PLATFORM_SECURITY_REVIEW", "confirm whether an already-approved route/alias exists; do not construct a fallback route"
    if status in {
        "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED",
        "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED",
    }:
        return "DISASTER_RECOVERY_REVIEW", "review immutable Platform observations; this is not DR protection or restore acceptance"
    if "PERSISTENCE_COLLECTION_PARTIAL" in status or "PERSISTENCE_EVIDENCE_EMPTY" in status:
        return "PLATFORM_OWNER_REVIEW", "review bounded collector coverage and owner semantics before requesting broader access"
    return "PLATFORM_OWNER_REVIEW", "review the observation and retain unresolved status until owner evidence supports refinement"


def admission_classification(rows: List[Dict[str, str]], packet_ok: bool) -> Dict[str, Any]:
    if not packet_ok:
        return {
            "status": "PLATFORM_PACKET_INTEGRITY_FAILED",
            "dr_review_ready": False,
            "meaning": "Platform self-verification failed; do not submit this packet as immutable evidence.",
        }
    route_lanes = [r for r in rows if r["lane"] in {"MariaDB18", "RedisServer6", "ClientAppDB19"}]
    material = sum(
        1
        for r in route_lanes
        if r["status"] in {
            "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED",
            "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED",
        }
    )
    blockers = sum(1 for r in rows if r["status"].startswith("BLOCKED_") or r["status"].startswith("UNRESOLVED"))
    return {
        "status": "PLATFORM_OBSERVATION_PACKET_READY_FOR_DR_REVIEW",
        "dr_review_ready": True,
        "material_route_lanes": material,
        "open_blocker_or_unresolved_rows": blockers,
        "meaning": "Packet integrity and Platform provenance passed. DR may review the observations, but Platform does not assert protection coverage, retention acceptance, restore proof, recovery readiness, or closure.",
    }


def verify_run_directory(run_dir: Path, manifest_path: Path) -> Dict[str, Any]:
    expected: Dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        expected[rel] = digest
    failures: List[str] = []
    for rel, digest in expected.items():
        p = run_dir / rel
        if not p.is_file():
            failures.append(f"MISSING:{rel}")
        elif p0f.sha256(p) != digest:
            failures.append(f"SHA256_MISMATCH:{rel}")
    actual = sorted(p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file() and p != manifest_path)
    expected_names = sorted(expected)
    if actual != expected_names:
        failures.append("MEMBER_SET_MISMATCH")
    return {
        "status": "PASS" if not failures else "FAIL",
        "expected_member_count": len(expected),
        "failures": failures,
    }


def verify_zip(zip_path: Path, manifest_text: str) -> Dict[str, Any]:
    expected: Dict[str, str] = {}
    for line in manifest_text.splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        expected[rel] = digest
    failures: List[str] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = sorted(n for n in zf.namelist() if n not in {"MANIFEST.sha256", "SELF_CHECK.json"})
        if names != sorted(expected):
            failures.append("ZIP_MEMBER_SET_MISMATCH")
        for rel, digest in expected.items():
            try:
                data = zf.read(rel)
            except KeyError:
                failures.append(f"ZIP_MISSING:{rel}")
                continue
            if _sha256_bytes(data) != digest:
                failures.append(f"ZIP_SHA256_MISMATCH:{rel}")
        try:
            embedded_manifest = zf.read("MANIFEST.sha256").decode("utf-8")
            if embedded_manifest != manifest_text:
                failures.append("ZIP_MANIFEST_CONTENT_MISMATCH")
        except KeyError:
            failures.append("ZIP_MISSING:MANIFEST.sha256")
    return {"status": "PASS" if not failures else "FAIL", "failures": failures}


def load_contract(path: Path) -> Dict[str, Any]:
    c = json.loads(path.read_text(encoding="utf-8"))
    if c.get("contract") != CONTRACT_NAME:
        raise RuntimeError("contract identity mismatch")
    if c.get("authority") != AUTHORITY or c.get("production_mutation") != PRODUCTION_MUTATION:
        raise RuntimeError("authority or mutation boundary mismatch")
    forbidden = " ".join(c.get("forbidden", [])).lower()
    for required in (
        "host_key_enrollment", "direct_route_fallback", "manual_jump_fallback", "credential discovery",
        "root fallback", "sudo escalation", "backup_or_restore_execution", "key enumeration",
        "value retrieval", "dr_acceptance_claim",
    ):
        if required not in forbidden:
            raise RuntimeError("contract missing hard safety block: " + required)
    return c


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", default="contracts/phase0h_deterministic_route_evidence_admission_v1.json")
    ap.add_argument("--output-root", default="evidence")
    args = ap.parse_args(argv)

    contract_path = Path(args.contract)
    contract = load_contract(contract_path)
    source_gate = p0f.verify_accepted_source(contract.get("accepted_source_ref", "origin/main"))
    if not source_gate["accepted"]:
        print("BLOCKED: accepted-source validation failed", flush=True)
        print(json.dumps(source_gate, indent=2, sort_keys=True), flush=True)
        return 3

    cfg = contract["ssh_config"]
    discovery = p0g.discover_literal_ssh_aliases(
        Path(cfg["root"]),
        max_depth=int(cfg.get("max_include_depth", 5)),
        max_files=int(cfg.get("max_config_files", 32)),
        max_aliases=int(cfg.get("max_literal_aliases", 512)),
    )
    required_jump = cfg["required_proxyjump_alias"]
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0h-readonly-{run_stamp}"
    out_root = Path(args.output_root)
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    _write_json(run_dir / "source_gate.json", source_gate)
    _write_json(run_dir / "ssh_alias_discovery.json", discovery)
    _write_json(run_dir / "gateway_effective_config.json", p0g.effective_ssh_config(required_jump))

    rows: List[Dict[str, str]] = []
    for target in contract["targets"]:
        lane = target["lane"]
        ip = target["ip"]
        collector_name = target["collector"]
        selection = discover_matching_aliases_deterministic(
            ip,
            discovery["aliases"],
            required_jump,
            max_emitted=int(cfg.get("max_emitted_matching_aliases_per_target", 8)),
        )
        selected = selection.get("selected_alias")
        alias = str(selected.get("alias")) if selected else ""
        vm_meta = p0g.hypervisor_metadata_alias(required_jump, ip)
        probe = p0g.strict_alias_probe(alias) if alias else None
        route_status, route_reason = classify_route(selection, probe, vm_meta)
        collector = p0g.collect_via_alias(alias, collector_name) if alias and route_status == "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED" else None
        status, reason = persistence_status(route_status, collector, collector_name)
        next_owner, next_action = next_owner_for_status(lane, status)

        evidence = {
            "lane": lane,
            "ip": ip,
            "collector": collector_name,
            "status": status,
            "reason": reason,
            "route_status": route_status,
            "route_reason": route_reason,
            "alias_selection": selection,
            "strict_alias_probe": safe_command_evidence(probe),
            "hypervisor_vm_metadata": safe_command_evidence(vm_meta),
            "persistence_collection": safe_command_evidence(collector),
            "next_owner": next_owner,
            "next_action": next_action,
            "interpretation_rule": "Only an already-configured literal alias resolving to the target and using the required hv ProxyJump may be exercised. No direct-IP or manually constructed route fallback is permitted. Platform observations do not establish DR acceptance.",
        }
        _write_json(run_dir / f"{_safe_name(lane)}.json", evidence)
        rows.append({
            "lane": lane,
            "ip": ip,
            "status": status,
            "reason": reason,
            "next_owner": next_owner,
            "next_action": next_action,
        })

    for owner in contract.get("owner_evidence_lanes", []):
        status = "UNRESOLVED_REQUIRES_OWNER_EVIDENCE"
        next_owner, next_action = next_owner_for_status(owner["lane"], status)
        rows.append({
            "lane": owner["lane"],
            "ip": owner.get("expected_ip", ""),
            "status": status,
            "reason": "Platform route/persistence evidence does not establish application durable-state semantics or rebuildability",
            "next_owner": next_owner,
            "next_action": next_action,
        })

    hard_rows = [
        ("MarketDataInfluxRetention", "", contract["hard_blocks"]["marketdata_influx_retention"], "no explicitly authorized administrative read supplied"),
        ("NexusDB", "192.168.200.23", contract["hard_blocks"]["nexusdb"], "Security design approval is not Platform implementation authorization"),
    ]
    for lane, ip, status, reason in hard_rows:
        next_owner, next_action = next_owner_for_status(lane, status)
        rows.append({"lane": lane, "ip": ip, "status": status, "reason": reason, "next_owner": next_owner, "next_action": next_action})

    with (run_dir / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["lane", "ip", "status", "reason", "next_owner", "next_action"])
        writer.writeheader()
        writer.writerows(rows)

    with (run_dir / "routing_proposals.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["lane", "status", "next_owner", "next_action"])
        writer.writeheader()
        writer.writerows({k: r[k] for k in ("lane", "status", "next_owner", "next_action")} for r in rows)

    env_lines = [
        f"RUN_ID={run_id}",
        f"CONTRACT={CONTRACT_NAME}",
        f"AUTHORITY={AUTHORITY}",
        f"PRODUCTION_MUTATION={PRODUCTION_MUTATION}",
        f"SOURCE_HEAD={source_gate['head']}",
        f"ACCEPTED_SOURCE_REF={source_gate['accepted_ref']}",
        f"ACCEPTED_SOURCE_SHA={source_gate['accepted_ref_sha']}",
        "ACCEPTED_SOURCE_STATUS=ACCEPTED_SOURCE_PASS",
    ]
    for row in rows:
        key = re.sub(r"[^A-Z0-9]+", "_", row["lane"].upper()).strip("_")
        env_lines.append(f"{key}_STATUS={row['status']}")
        env_lines.append(f"{key}_NEXT_OWNER={row['next_owner']}")
    (run_dir / "summary.env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    receipt = {
        "run_id": run_id,
        "contract": CONTRACT_NAME,
        "authority": AUTHORITY,
        "production_mutation": PRODUCTION_MUTATION,
        "completed_utc": p0f.utc_now(),
        "source_gate": source_gate,
        "required_proxyjump_alias": required_jump,
        "contract_sha256": p0f.sha256(contract_path),
        "dr_acceptance_claimed": False,
    }
    _write_json(run_dir / "receipt.json", receipt)

    report = [
        "# Platform & Compute Phase-0H deterministic route evidence admission",
        "",
        f"Run: `{run_id}`  ",
        f"Contract: `{CONTRACT_NAME}`  ",
        f"Authority: `{AUTHORITY}`  ",
        f"Production mutation: `{PRODUCTION_MUTATION}`  ",
        f"Accepted source: `{source_gate['head']}` == `{source_gate['accepted_ref']}`",
        "",
        "## Results",
        "",
        "| Lane | Status | Next owner | Reason |",
        "|---|---|---|---|",
    ]
    for row in rows:
        report.append(f"| {row['lane']} | `{row['status']}` | `{row['next_owner']}` | {row['reason']} |")
    report.extend([
        "",
        "## Admission boundary",
        "",
        "Phase-0H is a Platform self-admission gate only. It verifies accepted-source provenance, deterministic existing-alias selection, bounded command evidence, manifest integrity, and immutable ZIP contents. A PASS means the Platform observation packet is structurally ready for Disaster Recovery review; it does not establish backup coverage, retention acceptance, restore proof, recovery readiness, or DR closure.",
        "",
        "No host key is enrolled, no trust setting is weakened, no direct/manual jump fallback is created, no credential is discovered, no service is restarted, and no backup/restore action is executed.",
        "",
    ])
    report_text = "\n".join(report)
    (run_dir / "REPORT.md").write_text(report_text, encoding="utf-8")
    (run_dir / "HANDOFF_TO_DISASTER_RECOVERY.md").write_text(report_text, encoding="utf-8")

    # Manifest excludes itself and SELF_CHECK because SELF_CHECK summarizes manifest verification.
    manifest_members = sorted(p for p in run_dir.rglob("*") if p.is_file())
    manifest_text = "".join(f"{p0f.sha256(p)}  {p.relative_to(run_dir).as_posix()}\n" for p in manifest_members)
    manifest_path = run_dir / "MANIFEST.sha256"
    manifest_path.write_text(manifest_text, encoding="utf-8")
    directory_check = verify_run_directory(run_dir, manifest_path)
    admission = admission_classification(rows, directory_check["status"] == "PASS")
    self_check = {
        "manifest_verification": directory_check,
        "admission": admission,
        "dr_acceptance_claimed": False,
    }
    # SELF_CHECK is intentionally outside the manifest to avoid self-reference; it is still included in the ZIP.
    _write_json(run_dir / "SELF_CHECK.json", self_check)

    zip_path = out_root / f"{run_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(run_dir.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(run_dir).as_posix())

    # Verify all manifest-governed members in the immutable ZIP and separately require the self-check artifact.
    zip_check = verify_zip(zip_path, manifest_text)
    with zipfile.ZipFile(zip_path, "r") as zf:
        if "SELF_CHECK.json" not in zf.namelist():
            zip_check["status"] = "FAIL"
            zip_check.setdefault("failures", []).append("ZIP_MISSING:SELF_CHECK.json")
    if zip_check["status"] != "PASS":
        print("FAIL: immutable ZIP self-verification failed", flush=True)
        print(json.dumps(zip_check, indent=2, sort_keys=True), flush=True)
        return 4

    zip_hash = p0f.sha256(zip_path)
    (zip_path.with_suffix(zip_path.suffix + ".sha256")).write_text(f"{zip_hash}  {zip_path.name}\n", encoding="utf-8")
    (zip_path.with_suffix(zip_path.suffix + ".verification.json")).write_text(
        json.dumps({"zip_sha256": zip_hash, "zip_verification": zip_check, "platform_admission": admission}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"PASS: {zip_path}")
    print(f"PLATFORM_ADMISSION={admission['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
