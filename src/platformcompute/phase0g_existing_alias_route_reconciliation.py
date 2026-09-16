from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import shlex
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from src.platformcompute import phase0f_strict_proxyjump_persistence_evidence as p0f

CONTRACT_NAME = "bitstream-platformcompute-phase0g-existing-alias-route-reconciliation-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
PRODUCTION_MUTATION = "NONE"

SAFE_EFFECTIVE_KEYS = (
    "hostname",
    "user",
    "port",
    "proxyjump",
    "proxycommand",
    "stricthostkeychecking",
    "batchmode",
    "passwordauthentication",
    "kbdinteractiveauthentication",
)

WILDCARD_CHARS = set("*?!")


def _tokens(line: str) -> List[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError:
        return []


def _literal_host(token: str) -> bool:
    return bool(token) and not token.startswith("!") and not any(ch in token for ch in WILDCARD_CHARS)


def _expand_include(pattern: str, parent: Path) -> List[Path]:
    raw = os.path.expanduser(pattern)
    p = Path(raw)
    if not p.is_absolute():
        p = parent / p
    return [Path(x) for x in sorted(glob.glob(str(p)))]


def discover_literal_ssh_aliases(
    root: Path,
    max_depth: int = 5,
    max_files: int = 32,
    max_aliases: int = 512,
) -> Dict[str, Any]:
    """Read only Host/Include directives. Never emit config contents, identities, or credentials."""
    seen: Set[Path] = set()
    aliases: Set[str] = set()
    files: List[str] = []
    warnings: List[str] = []

    def visit(path: Path, depth: int) -> None:
        nonlocal aliases
        try:
            resolved = path.expanduser().resolve(strict=False)
        except OSError:
            resolved = path.expanduser()
        if resolved in seen or len(seen) >= max_files:
            return
        if depth > max_depth:
            warnings.append("INCLUDE_DEPTH_LIMIT")
            return
        seen.add(resolved)
        if not resolved.is_file():
            return
        files.append(str(resolved))
        try:
            with resolved.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    t = _tokens(line)
                    if not t:
                        continue
                    key = t[0].lower()
                    if key == "host":
                        for item in t[1:]:
                            if _literal_host(item) and len(aliases) < max_aliases:
                                aliases.add(item)
                    elif key == "include":
                        for pattern in t[1:]:
                            for inc in _expand_include(pattern, resolved.parent):
                                visit(inc, depth + 1)
        except OSError as exc:
            warnings.append(f"READ_ERROR:{resolved.name}:{type(exc).__name__}")

    visit(root.expanduser(), 0)
    if len(seen) >= max_files:
        warnings.append("CONFIG_FILE_LIMIT")
    if len(aliases) >= max_aliases:
        warnings.append("ALIAS_LIMIT")
    return {
        "root": str(root.expanduser()),
        "files_examined_count": len(files),
        "literal_alias_count": len(aliases),
        "aliases": sorted(aliases),
        "warnings": sorted(set(warnings)),
        "privacy_rule": "Only literal Host aliases and Include topology are used for route resolution; raw SSH configuration contents are not emitted.",
    }


def effective_ssh_config(alias: str) -> Dict[str, Any]:
    ev = p0f.run_cmd(["ssh", "-G", alias], timeout=5)
    parsed = p0f.parse_ssh_g(ev.stdout) if ev.returncode == 0 else {}
    return {
        "alias": alias,
        "returncode": ev.returncode,
        "stderr": ev.stderr,
        "effective": {k: parsed[k] for k in SAFE_EFFECTIVE_KEYS if k in parsed},
    }


def _proxyjump_contains(effective: Dict[str, str], required_alias: str) -> bool:
    pj = effective.get("proxyjump", "").strip().lower()
    required = required_alias.strip().lower()
    if not pj or pj == "none" or not required:
        return False
    hops = [x.strip() for x in pj.split(",") if x.strip()]
    for hop in hops:
        # user@host:port -> host
        hostpart = hop.rsplit("@", 1)[-1]
        hostpart = hostpart.rsplit(":", 1)[0]
        if hostpart.lower() == required:
            return True
    return False


def discover_matching_aliases(
    ip: str,
    aliases: Iterable[str],
    required_proxyjump_alias: str,
    max_matches: int = 8,
) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for alias in aliases:
        cfg = effective_ssh_config(alias)
        eff = cfg.get("effective", {})
        if eff.get("hostname") != ip:
            continue
        cfg["required_proxyjump_present"] = _proxyjump_contains(eff, required_proxyjump_alias)
        matches.append(cfg)
        if len(matches) >= max_matches:
            break
    # Prefer the required H1 jump topology, then deterministic alias order.
    matches.sort(key=lambda x: (not bool(x.get("required_proxyjump_present")), x["alias"].lower()))
    return matches


def ssh_via_alias(alias: str, remote: str, timeout: int = 18) -> p0f.CommandEvidence:
    # Command-line safety options override weaker per-host settings while preserving configured user/port/ProxyJump.
    return p0f.run_cmd(["ssh", *p0f.ssh_common(), alias, remote], timeout=timeout)


def strict_alias_probe(alias: str) -> p0f.CommandEvidence:
    return ssh_via_alias(alias, "printf 'PLATFORM_CONFIGURED_ALIAS_ROUTE_OK\\n'", timeout=18)


def hypervisor_metadata_alias(gateway_alias: str, ip: str) -> p0f.CommandEvidence:
    qip = shlex.quote(ip)
    remote = (
        "set -f; "
        "command -v virsh >/dev/null 2>&1 || { printf 'VIRSH_UNAVAILABLE\\n'; exit 3; }; "
        "for d in $(virsh list --all --name 2>/dev/null); do "
        "[ -n \"$d\" ] || continue; "
        "state=$(virsh domstate \"$d\" 2>/dev/null | tr '\\n' ' '); "
        "ifs=$(virsh domifaddr \"$d\" --source agent 2>/dev/null; virsh domifaddr \"$d\" --source arp 2>/dev/null); "
        f"printf '%s\\n' \"$ifs\" | grep -F -- {qip} >/dev/null 2>&1 || continue; "
        "printf 'DOMAIN=%s\\nSTATE=%s\\n' \"$d\" \"$state\"; "
        "printf '%s\\n' \"$ifs\"; "
        "virsh domblklist \"$d\" --details 2>/dev/null; "
        "done"
    )
    return ssh_via_alias(gateway_alias, remote, timeout=22)


def classify_alias_route(
    matches: List[Dict[str, Any]],
    probe: Optional[p0f.CommandEvidence],
    vm_meta: p0f.CommandEvidence,
) -> Tuple[str, str]:
    if not matches:
        return "BLOCKED_NO_EXISTING_CONFIGURED_ALIAS", "no literal workstation SSH alias resolved to the scoped target IP"
    selected = matches[0]
    if not selected.get("required_proxyjump_present"):
        return "BLOCKED_NO_H1_PROXYJUMP_ALIAS", "matching SSH alias exists but does not resolve through the required existing hv ProxyJump"
    if probe is None:
        return "UNRESOLVED_ALIAS_PROBE_MISSING", "configured alias was selected but no strict route probe result exists"
    combined = (probe.stderr + "\n" + probe.stdout).lower()
    if probe.returncode == 0:
        return "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED", "existing configured SSH alias completed through the required hv ProxyJump under strict command-line trust/auth settings"
    if "host key verification failed" in combined or "no ed25519 host key is known" in combined or "host key is unknown" in combined:
        return "BLOCKED_STRICT_HOST_KEY_TRUST", "configured alias route reached a strict host-key trust boundary; no key was enrolled"
    if "permission denied" in combined:
        return "BLOCKED_GUEST_AUTHORIZATION", "configured alias route reached authentication but the existing identity was not authorized"
    if "stdio forwarding request failed" in combined or "administratively prohibited" in combined or "session open refused" in combined:
        return "BLOCKED_PROXYJUMP_FORWARDING", "configured hv jump route refused or prohibited forwarding to the target"
    if "connection timed out" in combined or "operation timed out" in combined or "timeout" in combined:
        return "BLOCKED_CONFIGURED_ROUTE_TIMEOUT", "configured alias route did not complete before timeout"
    if "connection refused" in combined:
        return "BLOCKED_CONFIGURED_ROUTE_REFUSED", "configured alias route reached an address where target SSH refused the connection"
    if vm_meta.returncode == 0 and vm_meta.stdout.strip() and "VIRSH_UNAVAILABLE" not in vm_meta.stdout:
        return "GUEST_PRESENT_CONFIGURED_ROUTE_UNRESOLVED", "hypervisor metadata identifies the target while the existing configured alias route remains unresolved"
    return "UNRESOLVED_CONFIGURED_ALIAS_ROUTE", "configured alias evidence did not safely identify a more specific failure layer"


def collect_via_alias(alias: str, collector: str) -> Optional[p0f.CommandEvidence]:
    if collector == "mariadb_persistence":
        return ssh_via_alias(alias, p0f.MARIADB_REMOTE, timeout=35)
    if collector == "redis_persistence":
        return ssh_via_alias(alias, p0f.REDIS_REMOTE, timeout=35)
    if collector == "route_only":
        return None
    raise RuntimeError(f"unsupported collector: {collector}")


def persistence_status(
    route_status: str,
    collector: Optional[p0f.CommandEvidence],
    collector_name: str,
) -> Tuple[str, str]:
    if route_status != "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED":
        return route_status, "persistence collection not attempted because the required existing configured alias route was not confirmed"
    if collector_name == "route_only":
        return route_status, "route-only lane; no persistence collection requested"
    if collector is None:
        return "UNRESOLVED_COLLECTOR_STATE", "collector result missing after confirmed configured route"
    if collector.returncode != 0:
        return "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_COLLECTION_PARTIAL", "configured route succeeded but bounded persistence collector returned non-zero"
    material = (
        "SERVICE_", "SERVER_VERSION=", "CLIENT_VERSION=", "LISTENER=", "PATH=",
        "KEYSPACE_COUNT=", "INFO_PERSISTENCE=", "INFO_REPLICATION=", "CONFIG_PERSISTENCE=",
    )
    if any(m in collector.stdout for m in material):
        return "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED", "configured route succeeded and bounded non-secret persistence evidence was captured"
    return "CONFIGURED_ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_EMPTY", "configured route succeeded but allow-listed persistence observations produced no material evidence"


def load_contract(path: Path) -> Dict[str, Any]:
    c = json.loads(path.read_text(encoding="utf-8"))
    if c.get("contract") != CONTRACT_NAME:
        raise RuntimeError("contract identity mismatch")
    if c.get("authority") != AUTHORITY or c.get("production_mutation") != PRODUCTION_MUTATION:
        raise RuntimeError("authority or mutation boundary mismatch")
    forbidden = " ".join(c.get("forbidden", [])).lower()
    for required in (
        "host_key_enrollment", "direct_route_fallback", "credential discovery", "root fallback",
        "sudo escalation", "backup_or_restore_execution", "key enumeration", "value retrieval",
    ):
        if required not in forbidden:
            raise RuntimeError("contract missing hard safety block: " + required)
    return c


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", default="contracts/phase0g_existing_alias_route_reconciliation_v1.json")
    ap.add_argument("--output-root", default="evidence")
    args = ap.parse_args(argv)

    contract_path = Path(args.contract)
    contract = load_contract(contract_path)
    source_gate = p0f.verify_accepted_source(contract.get("accepted_source_ref", "origin/main"))
    if not source_gate["accepted"]:
        print("BLOCKED: accepted-source validation failed", flush=True)
        print(json.dumps(source_gate, indent=2, sort_keys=True), flush=True)
        return 3

    cfg_contract = contract["ssh_config"]
    discovery = discover_literal_ssh_aliases(
        Path(cfg_contract["root"]),
        max_depth=int(cfg_contract.get("max_include_depth", 5)),
        max_files=int(cfg_contract.get("max_config_files", 32)),
        max_aliases=int(cfg_contract.get("max_literal_aliases", 512)),
    )
    required_jump = cfg_contract["required_proxyjump_alias"]

    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0g-readonly-{run_stamp}"
    out_root = Path(args.output_root)
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(run_dir / "source_gate.json", source_gate)
    # Keep only bounded discovery metadata and alias names; no raw SSH config content.
    _write_json(run_dir / "ssh_alias_discovery.json", discovery)

    gateway_cfg = effective_ssh_config(required_jump)
    _write_json(run_dir / "gateway_effective_config.json", gateway_cfg)

    rows: List[Dict[str, str]] = []
    for target in contract["targets"]:
        lane = target["lane"]
        ip = target["ip"]
        collector_name = target["collector"]
        matches = discover_matching_aliases(
            ip,
            discovery["aliases"],
            required_jump,
            max_matches=int(cfg_contract.get("max_matching_aliases_per_target", 8)),
        )
        selected = matches[0] if matches else None
        alias = selected["alias"] if selected and selected.get("required_proxyjump_present") else ""
        vm_meta = hypervisor_metadata_alias(required_jump, ip)
        probe = strict_alias_probe(alias) if alias else None
        route_status, route_reason = classify_alias_route(matches, probe, vm_meta)
        collector = collect_via_alias(alias, collector_name) if alias and route_status == "STRICT_CONFIGURED_ALIAS_ROUTE_CONFIRMED" else None
        status, reason = persistence_status(route_status, collector, collector_name)

        lane_evidence = {
            "lane": lane,
            "ip": ip,
            "collector": collector_name,
            "status": status,
            "reason": reason,
            "route_status": route_status,
            "route_reason": route_reason,
            "matching_existing_aliases": matches,
            "selected_alias": alias or None,
            "strict_alias_probe": asdict(probe) if probe is not None else None,
            "hypervisor_vm_metadata": asdict(vm_meta),
            "persistence_collection": asdict(collector) if collector is not None else None,
            "interpretation_rule": "Only an already-configured literal alias resolving to the target and using the required hv ProxyJump may be exercised. No direct-IP or manually constructed route fallback is permitted.",
        }
        _write_json(run_dir / f"{_safe_name(lane)}.json", lane_evidence)
        rows.append({"lane": lane, "ip": ip, "status": status, "reason": reason})

    for owner in contract.get("owner_evidence_lanes", []):
        rows.append({
            "lane": owner["lane"],
            "ip": owner.get("expected_ip", ""),
            "status": "UNRESOLVED_REQUIRES_OWNER_EVIDENCE",
            "reason": "Platform route/persistence evidence does not establish application durable-state semantics or rebuildability",
        })
    rows.extend([
        {
            "lane": "MarketDataInfluxRetention",
            "ip": "",
            "status": contract["hard_blocks"]["marketdata_influx_retention"],
            "reason": "no explicitly authorized administrative read supplied",
        },
        {
            "lane": "NexusDB",
            "ip": "192.168.200.23",
            "status": contract["hard_blocks"]["nexusdb"],
            "reason": "Security design approval is not Platform implementation authorization",
        },
    ])

    with (run_dir / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["lane", "ip", "status", "reason"])
        writer.writeheader()
        writer.writerows(rows)

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
    }
    _write_json(run_dir / "receipt.json", receipt)

    report = [
        "# Platform & Compute Phase-0G existing-alias route reconciliation",
        "",
        f"Run: `{run_id}`  ",
        f"Contract: `{CONTRACT_NAME}`  ",
        f"Authority: `{AUTHORITY}`  ",
        f"Production mutation: `{PRODUCTION_MUTATION}`  ",
        f"Accepted source: `{source_gate['head']}` == `{source_gate['accepted_ref']}`",
        "",
        "## Results",
        "",
        "| Lane | Status | Reason |",
        "|---|---|---|",
    ]
    for row in rows:
        report.append(f"| {row['lane']} | `{row['status']}` | {row['reason']} |")
    report.extend([
        "",
        "## Interpretation and boundaries",
        "",
        "Phase-0G resolves the scoped target IPs against literal aliases already present in the workstation SSH configuration and exercises only aliases whose effective configuration uses the required existing `hv` ProxyJump. Command-line strict host-key checking and non-interactive authentication override weaker per-host settings. No new alias, host key, credential, trust path, direct-IP fallback, or route is created.",
        "",
        "MariaDB and Redis/Valkey persistence collection remains the bounded Phase-0F allow-list and runs only after the existing configured alias route succeeds. ClientAppDB19 remains route-only. Failures classify the observed config/transport/trust/auth layer and never prove a guest or datastore is down.",
        "",
        "ETHService and NodeServer remain application-owner evidence questions. MarketData administrative retention remains authorization-gated. NexusDB remains design-approved but implementation-not-authorized. Disaster Recovery/Data Protection retains protection, retention, restore, and recovery acceptance authority.",
        "",
    ])
    report_text = "\n".join(report)
    (run_dir / "REPORT.md").write_text(report_text, encoding="utf-8")
    (run_dir / "HANDOFF_TO_DISASTER_RECOVERY.md").write_text(report_text, encoding="utf-8")

    members = sorted(p for p in run_dir.rglob("*") if p.is_file())
    manifest = "".join(f"{p0f.sha256(p)}  {p.relative_to(run_dir).as_posix()}\n" for p in members)
    (run_dir / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")
    zip_path = out_root / f"{run_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(run_dir.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(run_dir).as_posix())
    zip_hash = p0f.sha256(zip_path)
    (zip_path.with_suffix(zip_path.suffix + ".sha256")).write_text(f"{zip_hash}  {zip_path.name}\n", encoding="utf-8")
    print(f"PASS: {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
