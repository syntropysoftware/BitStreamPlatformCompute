from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from src.platformcompute import phase0h_deterministic_route_evidence_admission as p0h

CONTRACT_NAME = "bitstream-platformcompute-phase0i-owner-blocker-closure-ledger-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
PRODUCTION_MUTATION = "NONE"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "UNKNOWN"


def _stable_id(prefix: str, *parts: str, length: int = 20) -> str:
    raw = "\x1f".join(parts).encode("utf-8", errors="strict")
    return f"{prefix}-{hashlib.sha256(raw).hexdigest()[:length]}"


def load_contract(path: Path) -> Dict[str, Any]:
    contract = json.loads(path.read_text(encoding="utf-8"))
    if contract.get("contract") != CONTRACT_NAME:
        raise RuntimeError("contract identity mismatch")
    if contract.get("authority") != AUTHORITY or contract.get("production_mutation") != PRODUCTION_MUTATION:
        raise RuntimeError("authority or production-mutation boundary mismatch")
    forbidden = " ".join(contract.get("forbidden", [])).lower()
    for phrase in (
        "production connection",
        "ssh execution",
        "network probing",
        "host_key_enrollment",
        "credential discovery",
        "root fallback",
        "sudo escalation",
        "service restart",
        "backup_or_restore_execution",
        "repository mutation",
        "external message send",
        "dr_acceptance_claim",
        "owner_authority_claim",
    ):
        if phrase not in forbidden:
            raise RuntimeError("contract missing hard safety block: " + phrase)
    return contract


def _parse_manifest(text: str) -> Dict[str, str]:
    expected: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            digest, rel = line.split("  ", 1)
        except ValueError as exc:
            raise RuntimeError("malformed manifest line") from exc
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("malformed manifest digest")
        if not rel or rel.startswith("/") or ".." in Path(rel).parts:
            raise RuntimeError("unsafe manifest member")
        if rel in expected:
            raise RuntimeError("duplicate manifest member")
        expected[rel] = digest
    return expected


def verify_phase0h_packet(zip_path: Path, contract: Dict[str, Any]) -> Dict[str, Any]:
    failures: List[str] = []
    required = {
        "MANIFEST.sha256",
        "SELF_CHECK.json",
        "receipt.json",
        "source_gate.json",
        "summary.csv",
        "summary.env",
        "REPORT.md",
        "HANDOFF_TO_DISASTER_RECOVERY.md",
    }
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = set(zf.namelist())
            missing = sorted(required - names)
            failures.extend(f"MISSING:{name}" for name in missing)
            if "MANIFEST.sha256" not in names:
                return {"status": "FAIL", "failures": failures, "rows": []}
            manifest_text = zf.read("MANIFEST.sha256").decode("utf-8")
            zip_check = p0h.verify_zip(zip_path, manifest_text)
            if zip_check.get("status") != "PASS":
                failures.extend("PHASE0H_" + item for item in zip_check.get("failures", []))
            if "SELF_CHECK.json" in names:
                self_check = json.loads(zf.read("SELF_CHECK.json"))
                admission = self_check.get("admission", {})
                if admission.get("status") != contract["required_input_admission"]:
                    failures.append("INPUT_ADMISSION_NOT_READY")
                if self_check.get("dr_acceptance_claimed") is not False:
                    failures.append("INPUT_DR_ACCEPTANCE_BOUNDARY_VIOLATION")
            else:
                self_check = {}
            if "receipt.json" in names:
                receipt = json.loads(zf.read("receipt.json"))
                if receipt.get("contract") != contract["input_contract"]:
                    failures.append("INPUT_CONTRACT_MISMATCH")
                if receipt.get("authority") != contract["input_authority"]:
                    failures.append("INPUT_AUTHORITY_MISMATCH")
                if receipt.get("production_mutation") != "NONE":
                    failures.append("INPUT_MUTATION_BOUNDARY_MISMATCH")
                if receipt.get("dr_acceptance_claimed") is not False:
                    failures.append("INPUT_RECEIPT_DR_ACCEPTANCE_VIOLATION")
            else:
                receipt = {}
            if "source_gate.json" in names:
                source_gate = json.loads(zf.read("source_gate.json"))
                if source_gate.get("accepted") is not True or source_gate.get("status") != "ACCEPTED_SOURCE_PASS":
                    failures.append("INPUT_SOURCE_NOT_ACCEPTED")
                receipt_source = receipt.get("source_gate", {})
                if receipt_source and receipt_source.get("head") != source_gate.get("head"):
                    failures.append("INPUT_SOURCE_RECEIPT_MISMATCH")
            else:
                source_gate = {}
            rows: List[Dict[str, str]] = []
            if "summary.csv" in names:
                text = zf.read("summary.csv").decode("utf-8")
                reader = csv.DictReader(io.StringIO(text))
                required_columns = {"lane", "ip", "status", "reason", "next_owner", "next_action"}
                if not reader.fieldnames or not required_columns.issubset(set(reader.fieldnames)):
                    failures.append("INPUT_SUMMARY_SCHEMA_MISMATCH")
                else:
                    rows = [{k: (row.get(k) or "") for k in required_columns} for row in reader]
            lanes = [row["lane"] for row in rows]
            if len(lanes) != len(set(lanes)):
                failures.append("INPUT_DUPLICATE_LANE")
            required_lanes = set(contract["required_lanes"])
            if set(lanes) != required_lanes:
                failures.append("INPUT_REQUIRED_LANE_SET_MISMATCH")
            allowed_owners = set(contract["allowed_next_owners"])
            for row in rows:
                if row["next_owner"] not in allowed_owners:
                    failures.append("INPUT_UNKNOWN_NEXT_OWNER:" + row["lane"])
            return {
                "status": "PASS" if not failures else "FAIL",
                "failures": failures,
                "zip_sha256": p0h.p0f.sha256(zip_path),
                "zip_name": zip_path.name,
                "source_run_id": receipt.get("run_id", ""),
                "source_head": source_gate.get("head", ""),
                "source_accepted_ref": source_gate.get("accepted_ref", ""),
                "input_admission": self_check.get("admission", {}).get("status", ""),
                "rows": rows,
            }
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
        failures.append("INPUT_PACKET_ERROR:" + type(exc).__name__ + ":" + str(exc))
        return {"status": "FAIL", "failures": failures, "rows": []}


def disposition_for(row: Dict[str, str]) -> str:
    owner = row["next_owner"]
    status = row["status"]
    if owner == "DISASTER_RECOVERY_REVIEW":
        return "READY_FOR_DR_REVIEW"
    if owner in {"SECURITY", "APPLICATION_OWNER", "SECURITY_OR_MARKETDATA_OWNER", "NETWORK_PLATFORM_REVIEW", "PLATFORM_SECURITY_REVIEW"}:
        return "WAITING_FOR_OWNER"
    if status.startswith("BLOCKED_") or status.startswith("UNRESOLVED"):
        return "WAITING_FOR_OWNER"
    return "PLATFORM_REVIEW_REQUIRED"


def build_current_ledger(rows: Iterable[Dict[str, str]], source_run_id: str, source_zip_sha256: str) -> List[Dict[str, str]]:
    ledger: List[Dict[str, str]] = []
    for row in sorted(rows, key=lambda item: item["lane"].lower()):
        lane = row["lane"]
        status = row["status"]
        owner = row["next_owner"]
        ledger.append({
            "lane_id": _stable_id("lane", lane),
            "work_item_id": _stable_id("pc", lane, status, owner),
            "lane": lane,
            "ip": row["ip"],
            "status": status,
            "reason": row["reason"],
            "next_owner": owner,
            "next_action": row["next_action"],
            "disposition": disposition_for(row),
            "source_run_id": source_run_id,
            "source_zip_sha256": source_zip_sha256,
            "authority": AUTHORITY,
            "production_mutation": PRODUCTION_MUTATION,
            "dr_acceptance_claimed": "false",
            "owner_authority_claimed": "false",
        })
    return ledger


def _verify_generic_packet(zf: zipfile.ZipFile) -> List[str]:
    failures: List[str] = []
    names = set(zf.namelist())
    if "MANIFEST.sha256" not in names:
        return ["PREVIOUS_MISSING:MANIFEST.sha256"]
    manifest_text = zf.read("MANIFEST.sha256").decode("utf-8")
    expected = _parse_manifest(manifest_text)
    allowed_unmanifested = {"MANIFEST.sha256", "SELF_CHECK.json"}
    actual_governed = names - allowed_unmanifested
    if actual_governed != set(expected):
        failures.append("PREVIOUS_MEMBER_SET_MISMATCH")
    for rel, digest in expected.items():
        try:
            data = zf.read(rel)
        except KeyError:
            failures.append("PREVIOUS_MISSING:" + rel)
            continue
        if _sha256_bytes(data) != digest:
            failures.append("PREVIOUS_SHA256_MISMATCH:" + rel)
    return failures


def load_previous_ledger(path: Optional[Path]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if path is None:
        return [], {"status": "NOT_SUPPLIED", "source": ""}
    if not path.is_file():
        raise RuntimeError("previous ledger path does not exist")
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path, "r") as zf:
            failures = _verify_generic_packet(zf)
            if failures:
                raise RuntimeError("previous Phase-0I packet failed verification: " + ",".join(failures))
            if "closure_ledger.json" not in zf.namelist():
                raise RuntimeError("previous Phase-0I packet has no closure_ledger.json")
            rows = json.loads(zf.read("closure_ledger.json"))
        return rows, {"status": "VERIFIED_ZIP", "source": str(path), "sha256": p0h.p0f.sha256(path)}
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise RuntimeError("previous ledger JSON must be a list")
    return rows, {"status": "JSON_SUPPLIED", "source": str(path), "sha256": p0h.p0f.sha256(path)}


def compare_ledgers(current: List[Dict[str, str]], previous: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    prev_by_lane = {str(row.get("lane", "")): row for row in previous if row.get("lane")}
    current_by_lane = {row["lane"]: row for row in current}
    changes: List[Dict[str, str]] = []
    for lane in sorted(current_by_lane, key=str.lower):
        cur = current_by_lane[lane]
        prev = prev_by_lane.get(lane)
        if prev is None:
            change = "NEW"
            previous_status = ""
            previous_owner = ""
        elif str(prev.get("status", "")) == cur["status"] and str(prev.get("next_owner", "")) == cur["next_owner"]:
            change = "UNCHANGED"
            previous_status = str(prev.get("status", ""))
            previous_owner = str(prev.get("next_owner", ""))
        else:
            change = "CHANGED"
            previous_status = str(prev.get("status", ""))
            previous_owner = str(prev.get("next_owner", ""))
        changes.append({
            "lane": lane,
            "change": change,
            "previous_status": previous_status,
            "current_status": cur["status"],
            "previous_next_owner": previous_owner,
            "current_next_owner": cur["next_owner"],
            "work_item_id": cur["work_item_id"],
        })
    for lane in sorted(set(prev_by_lane) - set(current_by_lane), key=str.lower):
        prev = prev_by_lane[lane]
        changes.append({
            "lane": lane,
            "change": "NO_LONGER_PRESENT_REVIEW_REQUIRED",
            "previous_status": str(prev.get("status", "")),
            "current_status": "",
            "previous_next_owner": str(prev.get("next_owner", "")),
            "current_next_owner": "",
            "work_item_id": str(prev.get("work_item_id", "")),
        })
    return changes


def owner_handoff_text(owner: str, rows: List[Dict[str, str]], source_run_id: str, input_hash: str) -> str:
    lines = [
        f"# Platform & Compute → {owner} — Phase-0I routed observations",
        "",
        f"Source Phase-0H run: `{source_run_id}`  ",
        f"Source immutable ZIP SHA-256: `{input_hash}`  ",
        f"Authority: `{AUTHORITY}`  ",
        f"Production mutation: `{PRODUCTION_MUTATION}`",
        "",
        "These are deterministic routing proposals derived from the owner fields already present in the verified Phase-0H packet. This document does not grant the recipient authority, request automatic execution, or claim Disaster Recovery acceptance.",
        "",
        "| Lane | Status | Disposition | Requested review/action |",
        "|---|---|---|---|",
    ]
    for row in sorted(rows, key=lambda item: item["lane"].lower()):
        reason = row["next_action"].replace("|", "\\|")
        lines.append(f"| {row['lane']} | `{row['status']}` | `{row['disposition']}` | {reason} |")
    lines.extend(["", "Platform preserves the source observations as-is and does not infer closure from routing or handoff generation.", ""])
    return "\n".join(lines)


def _write_csv(path: Path, rows: List[Dict[str, str]], fields: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def verify_run_directory(run_dir: Path, manifest_path: Path) -> Dict[str, Any]:
    expected = _parse_manifest(manifest_path.read_text(encoding="utf-8"))
    failures: List[str] = []
    for rel, digest in expected.items():
        p = run_dir / rel
        if not p.is_file():
            failures.append("MISSING:" + rel)
        elif p0h.p0f.sha256(p) != digest:
            failures.append("SHA256_MISMATCH:" + rel)
    actual = {
        p.relative_to(run_dir).as_posix()
        for p in run_dir.rglob("*")
        if p.is_file() and p.name not in {"MANIFEST.sha256", "SELF_CHECK.json"}
    }
    if actual != set(expected):
        failures.append("MEMBER_SET_MISMATCH")
    return {"status": "PASS" if not failures else "FAIL", "failures": failures, "member_count": len(expected)}


def verify_output_zip(zip_path: Path, manifest_text: str) -> Dict[str, Any]:
    expected = _parse_manifest(manifest_text)
    failures: List[str] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        governed = names - {"MANIFEST.sha256", "SELF_CHECK.json"}
        if governed != set(expected):
            failures.append("ZIP_MEMBER_SET_MISMATCH")
        for rel, digest in expected.items():
            try:
                data = zf.read(rel)
            except KeyError:
                failures.append("ZIP_MISSING:" + rel)
                continue
            if _sha256_bytes(data) != digest:
                failures.append("ZIP_SHA256_MISMATCH:" + rel)
        if "MANIFEST.sha256" not in names or zf.read("MANIFEST.sha256").decode("utf-8") != manifest_text:
            failures.append("ZIP_MANIFEST_MISSING_OR_MISMATCH")
        if "SELF_CHECK.json" not in names:
            failures.append("ZIP_MISSING:SELF_CHECK.json")
    return {"status": "PASS" if not failures else "FAIL", "failures": failures}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", default="contracts/phase0i_owner_blocker_closure_ledger_v1.json")
    parser.add_argument("--phase0h-zip", required=True)
    parser.add_argument("--previous-ledger")
    parser.add_argument("--output-root", default="evidence")
    args = parser.parse_args(argv)

    contract_path = Path(args.contract)
    contract = load_contract(contract_path)
    input_path = Path(args.phase0h_zip)
    input_verification = verify_phase0h_packet(input_path, contract)
    if input_verification["status"] != "PASS":
        print("BLOCKED: Phase-0H packet verification failed", flush=True)
        print(json.dumps(input_verification, indent=2, sort_keys=True), flush=True)
        return 3

    try:
        previous, previous_meta = load_previous_ledger(Path(args.previous_ledger) if args.previous_ledger else None)
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError, RuntimeError) as exc:
        print("BLOCKED: previous ledger verification failed", flush=True)
        print(str(exc), flush=True)
        return 4

    current = build_current_ledger(
        input_verification["rows"],
        input_verification["source_run_id"],
        input_verification["zip_sha256"],
    )
    changes = compare_ledgers(current, previous)

    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0i-offline-{run_stamp}"
    out_root = Path(args.output_root)
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    handoff_dir = run_dir / "owner_handoffs"
    handoff_dir.mkdir()

    verification_public = {k: v for k, v in input_verification.items() if k != "rows"}
    _write_json(run_dir / "input_verification.json", verification_public)
    _write_json(run_dir / "previous_ledger_source.json", previous_meta)
    _write_json(run_dir / "closure_ledger.json", current)
    ledger_fields = list(current[0].keys()) if current else []
    _write_csv(run_dir / "closure_ledger.csv", current, ledger_fields)
    _write_json(run_dir / "changes_since_previous.json", changes)
    change_fields = [
        "lane", "change", "previous_status", "current_status",
        "previous_next_owner", "current_next_owner", "work_item_id",
    ]
    _write_csv(run_dir / "changes_since_previous.csv", changes, change_fields)

    grouped: Dict[str, List[Dict[str, str]]] = {}
    for row in current:
        grouped.setdefault(row["next_owner"], []).append(row)
    handoff_index: List[Dict[str, str]] = []
    for owner in sorted(grouped):
        filename = _safe_name(owner) + ".md"
        text = owner_handoff_text(owner, grouped[owner], input_verification["source_run_id"], input_verification["zip_sha256"])
        (handoff_dir / filename).write_text(text, encoding="utf-8")
        handoff_index.append({"next_owner": owner, "filename": f"owner_handoffs/{filename}", "lane_count": str(len(grouped[owner]))})
    _write_csv(run_dir / "owner_handoff_index.csv", handoff_index, ["next_owner", "filename", "lane_count"])

    count_by_disposition: Dict[str, int] = {}
    count_by_change: Dict[str, int] = {}
    for row in current:
        count_by_disposition[row["disposition"]] = count_by_disposition.get(row["disposition"], 0) + 1
    for row in changes:
        count_by_change[row["change"]] = count_by_change.get(row["change"], 0) + 1

    summary = {
        "run_id": run_id,
        "contract": CONTRACT_NAME,
        "authority": AUTHORITY,
        "production_mutation": PRODUCTION_MUTATION,
        "source_phase0h_run_id": input_verification["source_run_id"],
        "source_phase0h_zip_sha256": input_verification["zip_sha256"],
        "source_head": input_verification["source_head"],
        "lane_count": len(current),
        "owner_handoff_count": len(grouped),
        "disposition_counts": count_by_disposition,
        "change_counts": count_by_change,
        "previous_ledger": previous_meta,
        "dr_acceptance_claimed": False,
        "owner_authority_claimed": False,
        "external_write_performed": False,
        "production_connection_performed": False,
    }
    _write_json(run_dir / "summary.json", summary)
    env_lines = [
        f"RUN_ID={run_id}",
        f"CONTRACT={CONTRACT_NAME}",
        f"AUTHORITY={AUTHORITY}",
        f"PRODUCTION_MUTATION={PRODUCTION_MUTATION}",
        f"SOURCE_PHASE0H_RUN_ID={input_verification['source_run_id']}",
        f"SOURCE_PHASE0H_ZIP_SHA256={input_verification['zip_sha256']}",
        f"LANE_COUNT={len(current)}",
        f"OWNER_HANDOFF_COUNT={len(grouped)}",
        "DR_ACCEPTANCE_CLAIMED=false",
        "OWNER_AUTHORITY_CLAIMED=false",
        "EXTERNAL_WRITE_PERFORMED=false",
        "PRODUCTION_CONNECTION_PERFORMED=false",
    ]
    for key, value in sorted(count_by_disposition.items()):
        env_lines.append(f"DISPOSITION_{_safe_name(key).upper()}={value}")
    for key, value in sorted(count_by_change.items()):
        env_lines.append(f"CHANGE_{_safe_name(key).upper()}={value}")
    (run_dir / "summary.env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    report = [
        "# Platform & Compute Phase-0I owner-blocker closure ledger",
        "",
        f"Run: `{run_id}`  ",
        f"Source Phase-0H run: `{input_verification['source_run_id']}`  ",
        f"Source Phase-0H immutable ZIP SHA-256: `{input_verification['zip_sha256']}`  ",
        f"Authority: `{AUTHORITY}`  ",
        f"Production mutation: `{PRODUCTION_MUTATION}`",
        "",
        "## Current closure ledger",
        "",
        "| Lane | Status | Disposition | Next owner | Change |",
        "|---|---|---|---|---|",
    ]
    change_by_lane = {row["lane"]: row["change"] for row in changes}
    for row in current:
        report.append(
            f"| {row['lane']} | `{row['status']}` | `{row['disposition']}` | `{row['next_owner']}` | `{change_by_lane.get(row['lane'], 'NEW')}` |"
        )
    report.extend([
        "",
        "## Authority boundary",
        "",
        "Phase-0I is offline correlation only. It preserves Phase-0H observations and routing fields, creates deterministic handoff artifacts, and compares them with an optional prior ledger. It performs no production connection and sends no handoff automatically.",
        "",
        "A routed observation is not closure. `READY_FOR_DR_REVIEW` is not Disaster Recovery acceptance, and `WAITING_FOR_OWNER` does not grant the named owner authority beyond that owner's existing policy boundary.",
        "",
    ])
    report_text = "\n".join(report)
    (run_dir / "REPORT.md").write_text(report_text, encoding="utf-8")

    dr_rows = grouped.get("DISASTER_RECOVERY_REVIEW", [])
    dr_handoff = owner_handoff_text(
        "DISASTER_RECOVERY_REVIEW",
        dr_rows,
        input_verification["source_run_id"],
        input_verification["zip_sha256"],
    )
    dr_handoff += "\nOther lanes remain routed to their recorded owners in the Phase-0I closure ledger and are not represented as DR-accepted or closed.\n"
    (run_dir / "HANDOFF_TO_DISASTER_RECOVERY.md").write_text(dr_handoff, encoding="utf-8")

    receipt = {
        "run_id": run_id,
        "contract": CONTRACT_NAME,
        "authority": AUTHORITY,
        "production_mutation": PRODUCTION_MUTATION,
        "completed_utc": p0h.p0f.utc_now(),
        "input_phase0h_run_id": input_verification["source_run_id"],
        "input_phase0h_zip_sha256": input_verification["zip_sha256"],
        "input_phase0h_source_head": input_verification["source_head"],
        "contract_sha256": p0h.p0f.sha256(contract_path),
        "previous_ledger": previous_meta,
        "dr_acceptance_claimed": False,
        "owner_authority_claimed": False,
        "external_write_performed": False,
        "production_connection_performed": False,
    }
    _write_json(run_dir / "receipt.json", receipt)

    governed_members = sorted(p for p in run_dir.rglob("*") if p.is_file())
    manifest_text = "".join(f"{p0h.p0f.sha256(p)}  {p.relative_to(run_dir).as_posix()}\n" for p in governed_members)
    manifest_path = run_dir / "MANIFEST.sha256"
    manifest_path.write_text(manifest_text, encoding="utf-8")
    directory_check = verify_run_directory(run_dir, manifest_path)
    self_check = {
        "status": "PASS" if directory_check["status"] == "PASS" else "FAIL",
        "manifest_verification": directory_check,
        "input_packet_verification": verification_public,
        "dr_acceptance_claimed": False,
        "owner_authority_claimed": False,
        "external_write_performed": False,
        "production_connection_performed": False,
    }
    _write_json(run_dir / "SELF_CHECK.json", self_check)
    if self_check["status"] != "PASS":
        print("FAIL: Phase-0I run-directory self-verification failed", flush=True)
        print(json.dumps(self_check, indent=2, sort_keys=True), flush=True)
        return 5

    zip_path = out_root / f"{run_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(run_dir.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(run_dir).as_posix())
    zip_check = verify_output_zip(zip_path, manifest_text)
    if zip_check["status"] != "PASS":
        print("FAIL: Phase-0I immutable ZIP verification failed", flush=True)
        print(json.dumps(zip_check, indent=2, sort_keys=True), flush=True)
        return 6

    zip_hash = p0h.p0f.sha256(zip_path)
    Path(str(zip_path) + ".sha256").write_text(f"{zip_hash}  {zip_path.name}\n", encoding="utf-8")
    _write_json(Path(str(zip_path) + ".verification.json"), {
        "zip_sha256": zip_hash,
        "zip_verification": zip_check,
        "input_phase0h_verification": verification_public,
        "dr_acceptance_claimed": False,
        "owner_authority_claimed": False,
    })
    print(f"PASS: {zip_path}")
    print(f"OWNER_HANDOFF_COUNT={len(grouped)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
