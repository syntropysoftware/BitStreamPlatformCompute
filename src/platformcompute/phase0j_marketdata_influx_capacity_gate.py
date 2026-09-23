"""Phase-0J: local-only read-only host snapshot + offline MarketData capacity gate.

No SSH, Influx API, credentials, live host inference, service action or backfill.
An evidence packet is NOT a capacity authorization or Disaster Recovery acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

CONTRACT = "bitstream-platformcompute-phase0j-marketdata-influx-capacity-isolation-gate-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
TRADE_BUCKET = "CBAdvMarketTrades-BTC-USD"
CANDLE_BUCKET = "CBAdvMarketData-BTC-USD"
SEGMENTS = {"C": 73, "A": 303, "B": 130}
SCOPE_KEYS = {"verified_local_hostname", "actual_influx_guest_id", "hypervisor_id", "inventory_evidence_ref", "endpoint_mapping_evidence_ref", "data_path", "wal_path", "backup_path", "backup_path_local", "notes"}
ASSESSMENT_KEYS = {"scope_evidence_ref", "dev_live_isolation", "dev_live_isolation_evidence_ref", "shared_bottleneck_controls_evidence_ref", "bucket_retention_proof", "bucket_inventory_names", "bucket_inventory_complete_evidence_ref", "lifecycle_no_pruning_evidence_ref", "retention_owner_signoff_ref", "retention_safe_for_506_day_research", "attributed_storage_windows", "measured_peak_day_trades", "measured_peak_day_source_ref", "measured_wal_and_compaction_headroom_bytes", "headroom_source_ref", "measured_min_free_bytes_policy", "free_space_policy_source_ref", "measured_live_and_eth_concurrent_write_budget_bytes_per_sec", "throughput_and_latency_source_ref", "max_pilot_days_owner_policy", "max_staged_batch_days_owner_policy", "stop_conditions_owner_evidence_ref", "wal_separate_volume_margin_bytes", "wal_margin_source_ref", "dr_backup_restore_io_and_offhost_dependency_ref", "backup_volume_capacity_evidence_ref", "backup_restore_required_headroom_bytes", "reviewer", "review_utc", "explicit_segment_c_capacity_signoff"}



def verify_accepted_source(ref: str = "origin/main") -> Dict[str, Any]:
    """Local Git identity check only; never fetch, reset, checkout or mutate Git."""
    def git(*args: str) -> str:
        r = subprocess.run(["git", *args], text=True, capture_output=True, timeout=8, check=False)
        if r.returncode:
            raise ValueError("BLOCKED_ACCEPTED_SOURCE_GIT_UNAVAILABLE")
        return r.stdout.strip()
    head = git("rev-parse", "HEAD")
    accepted = git("rev-parse", ref)
    tracked_changes = git("status", "--porcelain", "--untracked-files=no")
    if not re.fullmatch(r"[a-f0-9]{40}", head) or head != accepted or tracked_changes:
        raise ValueError("BLOCKED_ACCEPTED_SOURCE: HEAD must equal accepted origin/main with no tracked modifications")
    return {"status": "ACCEPTED_SOURCE_PASS", "accepted_ref": ref, "head": head, "accepted_ref_sha": accepted, "tracked_worktree_clean": True}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    val = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(val, dict):
        raise ValueError("expected JSON object")
    return val


def check_ref(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 240 and bool(re.fullmatch(r"[A-Za-z0-9_./:@#-]{3,240}", value)) and "REPLACE" not in value and "TOKEN" not in value.upper() and "SECRET" not in value.upper()


def check_identity(scope: Dict[str, Any], local_host: Optional[str] = None) -> None:
    if set(scope) - SCOPE_KEYS:
        raise ValueError("scope contains unknown fields; never include credentials or full configs")
    if scope.get("verified_local_hostname") != (local_host or socket.gethostname()):
        raise ValueError("BLOCKED_WRONG_LOCAL_HOST: endpoint IP alone is not physical-host identity")
    for key in ("actual_influx_guest_id", "hypervisor_id", "inventory_evidence_ref", "endpoint_mapping_evidence_ref"):
        if not check_ref(scope.get(key)):
            raise ValueError("BLOCKED_INVENTORY_IDENTITY_UNVERIFIED: " + key)
    if not isinstance(scope.get("backup_path_local"), bool):
        raise ValueError("backup_path_local must be boolean; no remote backup probes")
    for key in ("data_path", "wal_path") + (("backup_path",) if scope["backup_path_local"] else ()):
        raw = scope.get(key)
        if not isinstance(raw, str) or not raw.startswith("/") or "REPLACE" in raw:
            raise ValueError("BLOCKED_PATH_UNVERIFIED: " + key)
        p = Path(raw)
        if not p.is_dir():
            raise ValueError("BLOCKED_PATH_INACCESSIBLE: " + key)
    if scope.get("backup_path_local") is False and scope.get("backup_path") not in ("", None):
        # Remote backup location must be supplied through separately authorized evidence.
        raise ValueError("BLOCKED_BACKUP_PATH_UNVERIFIED: omit backup_path unless backup_path_local=true")


def _mount_info(path: Path) -> Dict[str, Any]:
    real = os.path.realpath(str(path))
    best: Optional[Tuple[int, Dict[str, Any]]] = None
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"status": "UNVERIFIED_PROC_MOUNTINFO_UNAVAILABLE", "filesystem_mount": None}
    for line in lines:
        parts = line.split(" - ", 1)
        if len(parts) != 2:
            continue
        left, right = parts
        col = left.split()
        tail = right.split()
        if len(col) < 5 or len(tail) < 2:
            continue
        mp = col[4].replace("\\040", " ")
        if not (real == mp or real.startswith(mp.rstrip("/") + "/") or mp == "/"):
            continue
        src = tail[1]
        safe_src = src if (re.fullmatch(r"/dev/[A-Za-z0-9_./:+-]+", src) or src in {"tmpfs", "overlay", "none"}) else "REDACTED_SOURCE_SHA256:" + sha(src.encode())
        entry = {"status": "OBSERVED", "mount_id": col[0], "device_major_minor": col[2], "mountpoint": mp, "fstype": tail[0], "source_redacted": safe_src}
        if best is None or len(mp) > best[0]:
            best = (len(mp), entry)
    return best[1] if best else {"status": "UNVERIFIED_MOUNT_MAPPING", "filesystem_mount": None}


def volume_snapshot(path: Path) -> Dict[str, Any]:
    v = os.statvfs(path)
    fr = v.f_frsize or v.f_bsize
    return {
        "path": os.path.realpath(str(path)), "mount": _mount_info(path),
        "fs_total_bytes": int(v.f_blocks * fr), "fs_used_bytes": int((v.f_blocks - v.f_bfree) * fr),
        "fs_free_bytes": int(v.f_bfree * fr), "fs_available_unprivileged_bytes": int(v.f_bavail * fr),
        "inode_total": int(v.f_files), "inode_free": int(v.f_ffree), "inode_available_unprivileged": int(v.f_favail),
        "st_dev": str(os.stat(path).st_dev),
    }


def _meminfo() -> Dict[str, int]:
    out = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            if k in {"MemTotal", "MemAvailable", "MemFree", "SwapFree"}:
                out[k + "_bytes"] = int(v.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return out


def _diskstats(major_minor: str) -> Optional[Dict[str, int]]:
    try:
        major, minor = map(int, major_minor.split(":"))
        for line in Path("/proc/diskstats").read_text().splitlines():
            words = line.split()
            if len(words) >= 14 and (int(words[0]), int(words[1])) == (major, minor):
                return {"read_ios": int(words[3]), "read_sectors": int(words[5]), "read_ms": int(words[6]),
                        "write_ios": int(words[7]), "write_sectors": int(words[9]), "write_ms": int(words[10]),
                        "inflight_ios": int(words[11]), "io_ms": int(words[12]), "weighted_io_ms": int(words[13])}
    except (OSError, ValueError, IndexError):
        pass
    return None


def collect(scope: Dict[str, Any], local_host: Optional[str] = None, source_gate: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    check_identity(scope, local_host)
    if source_gate is None or source_gate.get("status") != "ACCEPTED_SOURCE_PASS" or source_gate.get("head") != source_gate.get("accepted_ref_sha"):
        raise ValueError("BLOCKED_ACCEPTED_SOURCE_EVIDENCE_REQUIRED")
    volumes = {key: volume_snapshot(Path(scope[key])) for key in ("data_path", "wal_path")}
    volumes["backup_path"] = volume_snapshot(Path(scope["backup_path"])) if scope["backup_path_local"] else {"status": "UNVERIFIED_REMOTE_BACKUP_OWNER_EVIDENCE_REQUIRED"}
    disk = {}
    for vol in volumes.values():
        if vol.get("mount", {}).get("status") == "OBSERVED":
            dev = vol["mount"]["device_major_minor"]
            disk[dev] = _diskstats(dev)
    try:
        loadavg = list(os.getloadavg())
    except OSError:
        loadavg = None
    return {
        "contract": CONTRACT, "authority": AUTHORITY, "production_mutation": "NONE", "capture_utc": utcnow(),
        "capture_mode": "LOCAL_ONLY_NO_NETWORK_NO_INFLUX_API_NO_SSH_NO_CREDENTIAL_READ",
        "source_gate": source_gate,
        "observed_local_hostname": local_host or socket.gethostname(),
        "operator_verified_identity": {k: scope[k] for k in ("actual_influx_guest_id", "hypervisor_id", "inventory_evidence_ref", "endpoint_mapping_evidence_ref")},
        "endpoint_reference_only": "192.168.200.27:8086", "volumes": volumes,
        "host_snapshot": {"meminfo": _meminfo(), "loadavg": loadavg, "diskstats_single_instant_NOT_latency_or_throughput": disk},
        "not_measured": ["actual live-client bucket mapping", "shared hypervisor and backup contention", "bucket-attributed engine/index size", "Influx retention", "write rate", "compaction headroom", "IO latency", "backup restore headroom", "DR restore proof"],
        "capacity_authorization": "NONE",
    }


def _pos_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validated_windows(rows: Any) -> Tuple[Optional[Decimal], Optional[Decimal], List[str]]:
    reasons = []
    if not isinstance(rows, list) or len(rows) < 2:
        return None, None, ["TWO_ATTRIBUTED_STORED_BYTE_WINDOWS_REQUIRED"]
    rates = []
    refs = set()
    for idx, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"source_ref", "attributed_raw_trades", "attributed_persisted_storage_delta_bytes", "exclusive_bucket_attribution", "engine_and_index_included", "steady_state_compaction_checked"}:
            reasons.append("INVALID_WINDOW_SCHEMA:" + str(idx)); continue
        if not (check_ref(row["source_ref"]) and _pos_int(row["attributed_raw_trades"]) and _pos_int(row["attributed_persisted_storage_delta_bytes"]) and row["exclusive_bucket_attribution"] is True and row["engine_and_index_included"] is True and row["steady_state_compaction_checked"] is True):
            reasons.append("UNVERIFIED_WINDOW_ATTRIBUTION:" + str(idx)); continue
        refs.add(row["source_ref"])
        rates.append(Decimal(row["attributed_persisted_storage_delta_bytes"]) / Decimal(row["attributed_raw_trades"]))
    if len(rates) < 2 or len(refs) != len(rates):
        reasons.append("INDEPENDENT_MEASURED_WINDOWS_REQUIRED")
    return (min(rates), max(rates), reasons) if not reasons else (None, None, reasons)


def _safe_assessment(assessment: Dict[str, Any]) -> None:
    extra = set(assessment) - ASSESSMENT_KEYS
    if extra:
        raise ValueError("unrecognized assessment fields (do not supply credentials): " + ",".join(sorted(extra)))
    for field, value in assessment.items():
        if isinstance(value, str) and (len(value) > 500 or any(x in value.lower() for x in ("password=", "token=", "bearer ", "secret="))):
            raise ValueError("assessment contains potentially secret-bearing field: " + field)


def assess(snapshot: Dict[str, Any], assessment: Dict[str, Any], snapshot_hash: str) -> Dict[str, Any]:
    _safe_assessment(assessment)
    if snapshot.get("contract") != CONTRACT or snapshot.get("authority") != AUTHORITY or snapshot.get("production_mutation") != "NONE" or snapshot.get("capacity_authorization") != "NONE":
        raise ValueError("BLOCKED: invalid snapshot provenance or authority")
    if snapshot.get("capture_mode") != "LOCAL_ONLY_NO_NETWORK_NO_INFLUX_API_NO_SSH_NO_CREDENTIAL_READ":
        raise ValueError("BLOCKED: non-local snapshot provenance")
    source = snapshot.get("source_gate", {})
    if source.get("status") != "ACCEPTED_SOURCE_PASS" or source.get("accepted_ref") != "origin/main" or source.get("head") != source.get("accepted_ref_sha") or source.get("tracked_worktree_clean") is not True:
        raise ValueError("BLOCKED: snapshot accepted-source provenance unverified")
    vol = snapshot.get("volumes", {})
    data = vol.get("data_path", {})
    wal = vol.get("wal_path", {})
    identity = snapshot.get("operator_verified_identity", {})
    required_identity = all(check_ref(identity.get(k)) for k in ("actual_influx_guest_id", "hypervisor_id", "inventory_evidence_ref", "endpoint_mapping_evidence_ref"))
    reasons = []
    if not required_identity or not check_ref(assessment.get("scope_evidence_ref")):
        reasons.append("HOST_HYPERVISOR_ENDPOINT_OR_SCOPE_PROOF_MISSING")
    if data.get("mount", {}).get("status") != "OBSERVED" or wal.get("mount", {}).get("status") != "OBSERVED":
        reasons.append("DATA_OR_WAL_VOLUME_MAPPING_UNVERIFIED")
    isolation = assessment.get("dev_live_isolation")
    if isolation not in {"VERIFIED", "SHARED_WITH_CONTROLS"} or not check_ref(assessment.get("dev_live_isolation_evidence_ref")):
        reasons.append("DEV_LIVE_SHARING_OR_ISOLATION_UNVERIFIED")
    if isolation == "SHARED_WITH_CONTROLS" and not check_ref(assessment.get("shared_bottleneck_controls_evidence_ref")):
        reasons.append("SHARED_BOTTLENECK_CONTROLS_UNVERIFIED")
    retention = assessment.get("retention_safe_for_506_day_research", "UNVERIFIED")
    expected = {TRADE_BUCKET, CANDLE_BUCKET}
    all_buckets = assessment.get("bucket_inventory_names")
    if not isinstance(all_buckets, list) or not all(isinstance(b, str) and re.fullmatch(r"[A-Za-z0-9_.-]{3,120}", b) for b in all_buckets) or len(all_buckets) != len(set(all_buckets)) or not expected.issubset(set(all_buckets)):
        all_buckets = []
    proof = assessment.get("bucket_retention_proof") or []
    covered = set()
    if not isinstance(proof, list):
        proof = []
    for row in proof:
        if isinstance(row, dict) and set(row) == {"bucket", "retention_seconds", "source_ref", "owner_confirmed_no_other_pruning"} and check_ref(row["source_ref"]) and isinstance(row["bucket"], str) and (_nonneg_int(row["retention_seconds"])) and row["owner_confirmed_no_other_pruning"] is True:
            if row["retention_seconds"] == 0 or row["retention_seconds"] > 506 * 86400:
                covered.add(row["bucket"])
    if retention != "YES" or not all_buckets or not set(all_buckets).issubset(covered) or not check_ref(assessment.get("bucket_inventory_complete_evidence_ref")) or not check_ref(assessment.get("lifecycle_no_pruning_evidence_ref")) or not check_ref(assessment.get("retention_owner_signoff_ref")):
        reasons.append("RETENTION_OR_COMPLETE_BUCKET_LIFECYCLE_PROOF_MISSING")
    low, high, window_reasons = _validated_windows(assessment.get("attributed_storage_windows"))
    reasons.extend(window_reasons)
    peak = assessment.get("measured_peak_day_trades")
    if not _pos_int(peak) or not check_ref(assessment.get("measured_peak_day_source_ref")):
        reasons.append("MEASURED_PEAK_DAY_WITH_SOURCE_REQUIRED")
    temp = assessment.get("measured_wal_and_compaction_headroom_bytes")
    floor = assessment.get("measured_min_free_bytes_policy")
    if not _nonneg_int(temp) or not check_ref(assessment.get("headroom_source_ref")):
        reasons.append("WAL_INDEX_COMPACTION_HEADROOM_UNVERIFIED")
    if not _nonneg_int(floor) or not check_ref(assessment.get("free_space_policy_source_ref")):
        reasons.append("FREE_SPACE_STOP_POLICY_UNVERIFIED")
    if not _pos_int(assessment.get("measured_live_and_eth_concurrent_write_budget_bytes_per_sec")) or not check_ref(assessment.get("throughput_and_latency_source_ref")):
        reasons.append("BTC_ETH_CONCURRENT_WRITE_LATENCY_BUDGET_UNVERIFIED")
    for key in ("max_pilot_days_owner_policy", "max_staged_batch_days_owner_policy"):
        if not _pos_int(assessment.get(key)) or assessment[key] > 73:
            reasons.append("APPROVED_BATCH_POLICY_REQUIRED:" + key)
    if not check_ref(assessment.get("stop_conditions_owner_evidence_ref")):
        reasons.append("SOURCED_ALERT_AND_STOP_CONDITIONS_REQUIRED")
    if data.get("st_dev") != wal.get("st_dev") and (not _pos_int(assessment.get("wal_separate_volume_margin_bytes")) or not check_ref(assessment.get("wal_margin_source_ref")) or not _nonneg_int(wal.get("fs_available_unprivileged_bytes")) or wal["fs_available_unprivileged_bytes"] < assessment.get("wal_separate_volume_margin_bytes", float("inf"))):
        reasons.append("SEPARATE_WAL_VOLUME_MARGIN_UNVERIFIED")
    backup = vol.get("backup_path", {})
    if not check_ref(assessment.get("backup_volume_capacity_evidence_ref")) or not _pos_int(assessment.get("backup_restore_required_headroom_bytes")):
        reasons.append("BACKUP_VOLUME_AND_RESTORE_HEADROOM_UNVERIFIED")
    elif backup.get("status") != "UNVERIFIED_REMOTE_BACKUP_OWNER_EVIDENCE_REQUIRED" and not _nonneg_int(backup.get("fs_available_unprivileged_bytes")):
        reasons.append("BACKUP_VOLUME_FREE_SPACE_UNVERIFIED")
    elif _nonneg_int(backup.get("fs_available_unprivileged_bytes")) and backup["fs_available_unprivileged_bytes"] < assessment["backup_restore_required_headroom_bytes"]:
        reasons.append("MEASURED_BACKUP_RESTORE_HEADROOM_DEFICIT")
    if not check_ref(assessment.get("dr_backup_restore_io_and_offhost_dependency_ref")):
        reasons.append("DR_BACKUP_RESTORE_IO_AND_OFFHOST_DEPENDENCY_UNVERIFIED")
    reviewer = assessment.get("reviewer")
    try:
        review_utc = datetime.fromisoformat(str(assessment.get("review_utc", "")).replace("Z", "+00:00"))
        valid_date = review_utc.tzinfo is not None
    except ValueError:
        valid_date = False
    if not check_ref(reviewer) or not valid_date:
        reasons.append("EXPLICIT_REVIEWER_AND_REVIEW_UTC_REQUIRED")

    forecast = {name: {"days": days, "status": "UNVERIFIED"} for name, days in SEGMENTS.items()}
    max_pilot = None
    max_stage = None
    stop = None
    observed_free = data.get("fs_available_unprivileged_bytes")
    if (low is not None and high is not None and _pos_int(peak)):
        for name, days in SEGMENTS.items():
            forecast[name] = {"days": days, "status": "BOUNDED_FORECAST_NOT_APPROVAL", "base_stored_bytes_lower": int((low * peak * days).to_integral_value(rounding=ROUND_CEILING)), "base_stored_bytes_upper": int((high * peak * days).to_integral_value(rounding=ROUND_CEILING))}
        if _nonneg_int(temp):
            for entry in forecast.values():
                entry["required_bytes_upper_with_measured_wal_compaction_margin"] = entry["base_stored_bytes_upper"] + temp
        if _nonneg_int(floor) and _nonneg_int(temp) and _nonneg_int(observed_free):
            worst_one_day = int((high * peak).to_integral_value(rounding=ROUND_CEILING))
            safe_day_cap = max(0, (observed_free - temp - floor) // worst_one_day)
            for name, entry in forecast.items():
                entry["data_volume_measured_policy_max_days_only"] = min(entry["days"], safe_day_cap)
            if _pos_int(assessment.get("max_pilot_days_owner_policy")) and _pos_int(assessment.get("max_staged_batch_days_owner_policy")):
                max_pilot = min(assessment["max_pilot_days_owner_policy"], safe_day_cap, 73)
                max_stage = min(assessment["max_staged_batch_days_owner_policy"], safe_day_cap, 73)
            stop = {"data_volume_min_available_bytes": floor, "source_ref": assessment.get("free_space_policy_source_ref")}
            if observed_free < forecast["C"]["required_bytes_upper_with_measured_wal_compaction_margin"] + floor:
                reasons.append("MEASURED_SEGMENT_C_CAPACITY_DEFICIT")
    if not _nonneg_int(observed_free) or not _nonneg_int(data.get("inode_available_unprivileged")) or not _nonneg_int(wal.get("fs_available_unprivileged_bytes")):
        reasons.append("FILESYSTEM_FREE_BYTES_OR_INODES_UNVERIFIED")
    if _nonneg_int(data.get("inode_available_unprivileged")) and data["inode_available_unprivileged"] == 0:
        reasons.append("DATA_VOLUME_INODES_EXHAUSTED")
    explicit = assessment.get("explicit_segment_c_capacity_signoff", "UNVERIFIED")
    if explicit not in {"APPROVED", "NOT_APPROVED", "UNVERIFIED"}:
        raise ValueError("invalid explicit Segment C signoff")
    negative = {"MEASURED_SEGMENT_C_CAPACITY_DEFICIT", "DATA_VOLUME_INODES_EXHAUSTED", "MEASURED_BACKUP_RESTORE_HEADROOM_DEFICIT"}
    if explicit == "NOT_APPROVED" and check_ref(reviewer) and valid_date:
        gate = "NOT_APPROVED"
    elif negative.intersection(reasons):
        gate = "NOT_APPROVED"  # only if the deficiency is directly measured
    elif not reasons and explicit == "APPROVED" and (max_pilot or 0) > 0 and (max_stage or 0) > 0:
        gate = "APPROVED"
    else:
        gate = "UNVERIFIED"
    evidence_index = {
        "bucket_retention": [
            {"bucket": row["bucket"], "retention_seconds": row["retention_seconds"], "source_ref": row["source_ref"], "owner_confirmed_no_other_pruning": True}
            for row in proof if isinstance(row, dict) and set(row) == {"bucket", "retention_seconds", "source_ref", "owner_confirmed_no_other_pruning"}
            and check_ref(row.get("source_ref")) and _nonneg_int(row.get("retention_seconds"))
            and isinstance(row.get("bucket"), str) and re.fullmatch(r"[A-Za-z0-9_.-]{3,120}", row["bucket"])
            and row.get("owner_confirmed_no_other_pruning") is True
        ],
        "attributed_storage_windows": [
            row for row in (assessment.get("attributed_storage_windows") or [])
            if isinstance(row, dict) and set(row) == {"source_ref", "attributed_raw_trades", "attributed_persisted_storage_delta_bytes", "exclusive_bucket_attribution", "engine_and_index_included", "steady_state_compaction_checked"}
            and check_ref(row.get("source_ref")) and _pos_int(row.get("attributed_raw_trades"))
            and _pos_int(row.get("attributed_persisted_storage_delta_bytes"))
            and row.get("exclusive_bucket_attribution") is True and row.get("engine_and_index_included") is True
            and row.get("steady_state_compaction_checked") is True
        ],
        "provenance_refs": {
            key: assessment[key] for key in (
                "scope_evidence_ref", "dev_live_isolation_evidence_ref", "shared_bottleneck_controls_evidence_ref",
                "bucket_inventory_complete_evidence_ref", "lifecycle_no_pruning_evidence_ref",
                "retention_owner_signoff_ref", "measured_peak_day_source_ref", "headroom_source_ref",
                "free_space_policy_source_ref", "throughput_and_latency_source_ref", "stop_conditions_owner_evidence_ref",
                "wal_margin_source_ref", "backup_volume_capacity_evidence_ref", "dr_backup_restore_io_and_offhost_dependency_ref",
            ) if check_ref(assessment.get(key))
        },
        "bucket_inventory_names": all_buckets,
        "measured_peak_day_trades": peak if _pos_int(peak) else None,
    }
    return {
        "contract": CONTRACT, "authority": AUTHORITY, "source_snapshot_sha256": snapshot_hash,
        "measurement_provenance": evidence_index,
        "evidence_utc": utcnow(), "actual_influx_host_and_volume": {"host": identity.get("actual_influx_guest_id"), "hypervisor": identity.get("hypervisor_id"), "data_mount": data.get("mount"), "wal_mount": wal.get("mount"), "inventory_source_ref": identity.get("inventory_evidence_ref"), "endpoint_mapping_source_ref": identity.get("endpoint_mapping_evidence_ref")},
        "dev_live_isolation": isolation if isolation in {"VERIFIED", "SHARED_WITH_CONTROLS"} and "DEV_LIVE_SHARING_OR_ISOLATION_UNVERIFIED" not in reasons and "SHARED_BOTTLENECK_CONTROLS_UNVERIFIED" not in reasons else "UNVERIFIED",
        "retention_safe_for_506_day_research": "YES" if not any("RETENTION" in r for r in reasons) else "UNVERIFIED",
        "segment_c_capacity": gate,
        "max_pilot_days": max_pilot if gate == "APPROVED" else None,
        "max_staged_batch_days": max_stage if gate == "APPROVED" else None,
        "min_free_space_and_stop_threshold": stop if gate == "APPROVED" else None,
        "bytes_per_trade_range": {"lower": str(low), "upper": str(high)} if low is not None else None,
        "segments": forecast,
        "reviewer": reviewer if check_ref(reviewer) else "UNASSIGNED",
        "review_utc": assessment.get("review_utc") if valid_date else "UNVERIFIED",
        "dependencies": sorted(set(reasons + ["DR_RESTORE_ACCEPTANCE_SEPARATE_FROM_PLATFORM_CAPACITY", "NO_BACKFILL_AUTHORIZED_BY_THIS_PACKET"])),
        "production_mutation": "NONE", "backfill_launched": False, "dr_acceptance_claimed": False,
    }


def response_md(gate: Dict[str, Any]) -> str:
    segments = gate["segments"]
    def fmt(name: str) -> str:
        data = segments[name]
        if data["status"] == "UNVERIFIED":
            return "UNVERIFIED (stored-byte attribution / peak-day measurement missing)"
        return (f"{data['base_stored_bytes_lower']:,}–{data['base_stored_bytes_upper']:,} base stored bytes at measured peak-day; "
                f"{data.get('required_bytes_upper_with_measured_wal_compaction_margin', 'unset')} bytes including measured temporary margin, if provided. Forecast only, not a write authorization.")
    host = gate["actual_influx_host_and_volume"]
    def sv(value: Any) -> str:
        return str(value) if value is not None and value != "" else "unset"
    return f"""# Platform & Compute → MarketData — DEV Influx capacity/isolation gate

Evidence UTC: {gate['evidence_utc']}
Authority: `{AUTHORITY}`; collection and analysis only; no production mutation.
Platform reviewer: {gate['reviewer']} ({gate['review_utc']})

```text
ACTUAL_INFLUX_HOST_AND_VOLUME = {sv(host['host'])}; hypervisor={sv(host['hypervisor'])}; data={sv(host['data_mount'])}; wal={sv(host['wal_mount'])}; inventory_ref={sv(host['inventory_source_ref'])}; endpoint_mapping_ref={sv(host['endpoint_mapping_source_ref'])}
DEV_LIVE_ISOLATION = {gate['dev_live_isolation']}
RETENTION_SAFE_FOR_506_DAY_RESEARCH = {gate['retention_safe_for_506_day_research']}
SEGMENT_C_CAPACITY = {gate['segment_c_capacity']}
MAX_PILOT_DAYS = {sv(gate['max_pilot_days'])}
MAX_STAGED_BATCH_DAYS = {sv(gate['max_staged_batch_days'])}
MIN_FREE_SPACE_AND_STOP_THRESHOLD = {sv(gate['min_free_space_and_stop_threshold'])}
REVIEWER / EVIDENCE_UTC = {gate['reviewer']} / {gate['evidence_utc']}
DEPENDENCIES = {', '.join(gate['dependencies'])}
```

Segment C (73 days): {fmt('C')}

Segment A (303 days): {fmt('A')}

Segment B (130 days): {fmt('B')}

Trade storage measurement range (bytes/trade): {sv(gate['bytes_per_trade_range'])}. Estimates are not derived from CSV size or illustrative persisted-trade counts. A/B are forecasts, never approved by this Segment C gate. The September 21 REVIEW day is not a certified export source and must be excluded.

Platform capacity approval, if ever granted, is not Disaster Recovery backup/restore acceptance and does not authorize backfills. The BTC canonical candle bucket remains read-only. No service, storage, retention, access, LIVE workload, or backup policy was modified by this evidence consumer.

Snapshot SHA-256: `{gate['source_snapshot_sha256']}`.
"""


def _verify_members(members: Dict[str, bytes], manifest: str) -> None:
    parsed = {}
    for line in manifest.splitlines():
        digest, sep, name = line.partition("  ")
        if not sep or name in parsed or name not in members or sha(members[name]) != digest:
            raise ValueError("MANIFEST_INTEGRITY_FAILED")
        parsed[name] = digest
    if set(parsed) != set(members):
        raise ValueError("MANIFEST_MEMBER_SET_MISMATCH")


def make_packet(snapshot_bytes: bytes, assessment_bytes: bytes, gate: Dict[str, Any], output_root: Path) -> Tuple[Path, str]:
    run_id = "platformcompute-phase0j-offline-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_root.mkdir(parents=True, exist_ok=True)
    path = output_root / (run_id + ".zip")
    if path.exists():
        raise FileExistsError(path)
    members = {
        "redacted_local_snapshot.json": snapshot_bytes,
        "measurement_provenance.json": dump(gate["measurement_provenance"]),
        "snapshot_sha256.txt": (sha(snapshot_bytes) + "\n").encode(),
        "assessment_sha256.txt": (sha(assessment_bytes) + "\n").encode(),
        "gate.json": dump(gate),
        "HANDOFF_TO_MARKETDATA.md": response_md(gate).encode(),
        "HANDOFF_TO_DISASTER_RECOVERY.md": ("# Platform & Compute → Disaster Recovery — Influx capacity dependency\n\n" +
           "Segment C capacity disposition: `" + gate["segment_c_capacity"] + "`. This packet does not assert backup coverage, off-host copy bandwidth, restore headroom, restore proof or DR acceptance.\n\n" +
           "Review snapshot/backup IO, off-host copy bandwidth, storage sharing and restore headroom independently before scheduling backfill; no backup or restore ran here.\n").encode(),
        "receipt.json": dump({"run_id": run_id, "contract": CONTRACT, "authority": AUTHORITY, "production_mutation": "NONE", "no_production_connection": True, "no_backfill": True, "dr_acceptance_claimed": False, "packet_status": "PLATFORM_PACKET_SELF_VERIFIED_NOT_DR_ACCEPTED"}),
    }
    manifest = "".join(f"{sha(value)}  {name}\n" for name, value in sorted(members.items()))
    _verify_members(members, manifest)
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, value in sorted(members.items()):
            zf.writestr(name, value)
        zf.writestr("MANIFEST.sha256", manifest.encode())
    with zipfile.ZipFile(path) as zf:
        verify = {n: zf.read(n) for n in members}
        embedded_manifest = zf.read("MANIFEST.sha256").decode()
        if embedded_manifest != manifest or set(zf.namelist()) != set(members) | {"MANIFEST.sha256"}:
            raise ValueError("ZIP_MANIFEST_MISMATCH")
        _verify_members(verify, embedded_manifest)
    (output_root / (run_id + ".zip.sha256")).write_text(sha(path.read_bytes()) + "  " + path.name + "\n", encoding="utf-8")
    return path, sha(path.read_bytes())


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sp = ap.add_subparsers(dest="mode", required=True)
    c = sp.add_parser("collect", help="local-only read-only snapshot on previously verified actual Influx host")
    c.add_argument("--scope", required=True)
    c.add_argument("--output", required=True)
    e = sp.add_parser("evaluate", help="offline evidence and manually signed capacity gate")
    e.add_argument("--snapshot", required=True)
    e.add_argument("--assessment", required=True)
    e.add_argument("--output-root", default="evidence")
    args = ap.parse_args(argv)
    try:
        if args.mode == "collect":
            scope = load_json(Path(args.scope))
            out = Path(args.output).resolve()
            for key in ("data_path", "wal_path"):
                raw = scope.get(key)
                if isinstance(raw, str) and raw.startswith("/"):
                    p = Path(raw).resolve()
                    if out == p or p in out.parents:
                        raise ValueError("BLOCKED_EVIDENCE_OUTPUT_INSIDE_INFLUX_STORAGE")
            val = collect(scope, source_gate=verify_accepted_source())
            if not out.parent.is_dir():
                raise ValueError("output parent directory must already exist")
            with out.open("xb") as fh:
                fh.write(dump(val))
            print("PASS: read-only local snapshot written: " + str(out))
            return 0
        snap_path = Path(args.snapshot)
        assess_path = Path(args.assessment)
        raw = snap_path.read_bytes()
        assessment_bytes = assess_path.read_bytes()
        verify_accepted_source()
        result = assess(json.loads(raw), json.loads(assessment_bytes), sha(raw))
        path, digest = make_packet(raw, assessment_bytes, result, Path(args.output_root))
        print("SEGMENT_C_CAPACITY=" + result["segment_c_capacity"])
        print("PLATFORM_PACKET_SHA256=" + digest)
        print("PLATFORM_PACKET=" + str(path))
        return 0
    except (ValueError, KeyError, OSError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
