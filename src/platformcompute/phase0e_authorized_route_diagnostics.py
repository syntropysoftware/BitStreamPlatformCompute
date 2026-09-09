from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

CONTRACT_NAME = "bitstream-platformcompute-phase0e-authorized-route-diagnostics-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"

FORBIDDEN_SSH_PATTERNS = (
    "stricthostkeychecking=no",
    "userknownhostsfile=/dev/null",
    "-o stricthostkeychecking=no",
)

@dataclass
class CommandEvidence:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed_ms: int


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_cmd(argv: Sequence[str], timeout: int = 15) -> CommandEvidence:
    low = " ".join(argv).lower()
    if any(p in low for p in FORBIDDEN_SSH_PATTERNS):
        raise RuntimeError("forbidden SSH trust weakening requested")
    started = time.monotonic()
    try:
        p = subprocess.run(list(argv), text=True, capture_output=True, timeout=timeout, check=False)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        err = (err + "\nTIMEOUT").strip()
    return CommandEvidence(list(argv), rc, out, err, int((time.monotonic() - started) * 1000))


def ssh_base(target: str, port: Optional[int] = None) -> List[str]:
    argv = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=7",
        "-o", "ConnectionAttempts=1",
    ]
    if port:
        argv += ["-p", str(port)]
    argv.append(target)
    return argv


def parse_ssh_g(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or " " not in line:
            continue
        k, v = line.split(None, 1)
        out[k.strip().lower()] = v.strip()
    return out


def ssh_config(alias: str) -> Dict[str, Any]:
    ev = run_cmd(["ssh", "-G", alias], timeout=5)
    return {"evidence": asdict(ev), "effective": parse_ssh_g(ev.stdout) if ev.returncode == 0 else {}}


def safe_tcp_probe_local(ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            ok, err = True, ""
    except Exception as e:  # evidence only
        ok, err = False, f"{type(e).__name__}: {e}"
    return {"reachable": ok, "error": err, "elapsed_ms": int((time.monotonic()-started)*1000)}


def gateway_probe(gateway: str, gateway_port: int) -> CommandEvidence:
    return run_cmd(ssh_base(gateway, gateway_port) + ["printf", "PLATFORM_ROUTE_GATEWAY_OK\\n"], timeout=12)


def gateway_remote_probe(gateway: str, gateway_port: int, ip: str, port: int) -> CommandEvidence:
    # Read-only connect probe from the already-authorized gateway. No route/trust mutation.
    py = (
        "import socket,sys,time; ip=sys.argv[1]; port=int(sys.argv[2]); "
        "s=socket.socket(); s.settimeout(3); t=time.time(); "
        "\ntry:\n s.connect((ip,port)); print('REACHABLE elapsed_ms=%d'%((time.time()-t)*1000)); s.close(); sys.exit(0)"
        "\nexcept Exception as e:\n print('UNREACHABLE %s: %s'%(type(e).__name__,e)); sys.exit(7)"
    )
    remote = "python3 -c %s %s %s" % (shlex.quote(py), shlex.quote(ip), shlex.quote(str(port)))
    return run_cmd(ssh_base(gateway, gateway_port) + [remote], timeout=15)


def hypervisor_vm_metadata(gateway: str, gateway_port: int, ip: str) -> CommandEvidence:
    # Inventory only. Uses virsh read operations and filters for the exact IP.
    qip = shlex.quote(ip)
    remote = (
        "set -f; "
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
    return run_cmd(ssh_base(gateway, gateway_port) + [remote], timeout=20)


def strict_guest_probe(ip: str, port: int) -> CommandEvidence:
    # Exact target, strict trust. Failure is evidence; never enroll a key.
    return run_cmd(ssh_base(ip, port) + ["printf", "PLATFORM_GUEST_READ_OK\\n"], timeout=12)


def classify(gw_ok: bool, gw_tcp: CommandEvidence, guest_ssh: CommandEvidence, vm_meta: CommandEvidence) -> Tuple[str, str]:
    combined = (guest_ssh.stderr + "\n" + guest_ssh.stdout).lower()
    if not gw_ok:
        return "BLOCKED_GATEWAY_ROUTE", "authorized gateway SSH did not complete"
    if gw_tcp.returncode != 0:
        return "BLOCKED_GATEWAY_TO_GUEST_TCP", "gateway reachable; target SSH port not reachable from gateway"
    if "host key verification failed" in combined or "no ed25519 host key is known" in combined or "host key is unknown" in combined:
        return "BLOCKED_STRICT_HOST_KEY_TRUST", "gateway-to-target TCP works; strict guest host-key trust is not pre-approved"
    if "permission denied" in combined:
        return "BLOCKED_GUEST_AUTHORIZATION", "network/trust path reached guest; configured identity not authorized"
    if guest_ssh.returncode == 0:
        return "ROUTE_AND_GUEST_SSH_CONFIRMED", "strict existing guest SSH path completed"
    if vm_meta.returncode == 0 and vm_meta.stdout.strip():
        return "GUEST_PRESENT_ROUTE_UNRESOLVED", "hypervisor metadata identifies target IP but strict guest SSH did not complete"
    return "UNRESOLVED_ROUTE_LAYER", "evidence did not safely identify a more specific failure layer"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_contract(path: Path) -> Dict[str, Any]:
    c = json.loads(path.read_text(encoding="utf-8"))
    if c.get("contract") != CONTRACT_NAME:
        raise RuntimeError("contract identity mismatch")
    forbidden = " ".join(c.get("forbidden", [])).lower()
    for required in ("host_key_enrollment", "root fallback", "sudo escalation"):
        if required not in forbidden:
            raise RuntimeError("contract missing hard safety block: " + required)
    return c


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", default="contracts/phase0e_authorized_route_diagnostics_v1.json")
    ap.add_argument("--output-root", default="evidence")
    args = ap.parse_args(argv)

    contract_path = Path(args.contract)
    contract = load_contract(contract_path)
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0e-readonly-{run_stamp}"
    out_root = Path(args.output_root)
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    gateway = contract["gateway"]["ssh_target"]
    gateway_port = int(contract["gateway"].get("ssh_port", 69))
    gateway_cfg = ssh_config(gateway)
    gateway_ev = gateway_probe(gateway, gateway_port)
    gateway_ok = gateway_ev.returncode == 0
    write_json(run_dir / "gateway.json", {"ssh_config": gateway_cfg, "probe": asdict(gateway_ev)})

    rows: List[Dict[str, Any]] = []
    for t in contract["targets"]:
        lane, ip, port = t["lane"], t["ip"], int(t.get("expected_ssh_port", 69))
        local_tcp = safe_tcp_probe_local(ip, port)
        gw_tcp = gateway_remote_probe(gateway, gateway_port, ip, port) if gateway_ok else CommandEvidence([], 125, "", "gateway unavailable", 0)
        vm_meta = hypervisor_vm_metadata(gateway, gateway_port, ip) if gateway_ok else CommandEvidence([], 125, "", "gateway unavailable", 0)
        guest = strict_guest_probe(ip, port) if gw_tcp.returncode == 0 else CommandEvidence([], 125, "", "guest SSH not attempted because gateway-to-guest TCP is not confirmed", 0)
        aliases = {a: ssh_config(a) for a in t.get("guest_aliases", [])}
        status, reason = classify(gateway_ok, gw_tcp, guest, vm_meta)
        ev = {
            "lane": lane, "ip": ip, "port": port, "status": status, "reason": reason,
            "local_direct_tcp_non_authoritative": local_tcp,
            "gateway_tcp": asdict(gw_tcp),
            "hypervisor_vm_metadata": asdict(vm_meta),
            "strict_guest_ssh": asdict(guest),
            "configured_aliases": aliases,
            "interpretation_rule": "Direct alien TCP failure is not proof of guest downtime when authorized topology uses H1/ProxyJump.",
        }
        write_json(run_dir / f"{lane}.json", ev)
        rows.append({"lane": lane, "ip": ip, "status": status, "reason": reason})

    for o in contract.get("owner_evidence_lanes", []):
        rows.append({"lane": o["lane"], "ip": o.get("expected_ip", ""), "status": "UNRESOLVED_REQUIRES_OWNER_EVIDENCE", "reason": "Platform route diagnostics do not establish application durable-state semantics"})

    rows += [
        {"lane": "MarketDataInfluxRetention", "ip": "", "status": contract["hard_blocks"]["marketdata_influx_retention"], "reason": "no explicitly authorized administrative read supplied"},
        {"lane": "NexusDB", "ip": "192.168.200.23", "status": contract["hard_blocks"]["nexusdb"], "reason": "Security design approval is not Platform implementation authorization"},
    ]

    with (run_dir / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["lane", "ip", "status", "reason"]); w.writeheader(); w.writerows(rows)

    summary_env = [f"RUN_ID={run_id}", f"CONTRACT={CONTRACT_NAME}", f"AUTHORITY={AUTHORITY}", "PRODUCTION_MUTATION=NONE"]
    summary_env.extend(f"{re.sub('[^A-Z0-9]+','_',r['lane'].upper())}_STATUS={r['status']}" for r in rows)
    (run_dir / "summary.env").write_text("\n".join(summary_env) + "\n", encoding="utf-8")

    receipt = {
        "run_id": run_id, "contract": CONTRACT_NAME, "authority": AUTHORITY,
        "started_or_completed_utc": utc_now(), "production_mutation": "NONE",
        "gateway": gateway, "gateway_port": gateway_port,
        "source_git_head": run_cmd(["git", "rev-parse", "HEAD"], timeout=5).stdout.strip(),
        "contract_sha256": sha256(contract_path),
    }
    write_json(run_dir / "receipt.json", receipt)

    report = [
        f"# Platform & Compute Phase-0E authorized route diagnostics\n",
        f"Run: `{run_id}`  ", f"Contract: `{CONTRACT_NAME}`  ", f"Authority: `{AUTHORITY}`  ", "Production mutation: `NONE`\n",
        "## Results\n",
        "| Lane | Status | Reason |", "|---|---|---|",
    ]
    for r in rows:
        report.append(f"| {r['lane']} | `{r['status']}` | {r['reason']} |")
    report += [
        "\n## Boundaries\n",
        "This product decomposes existing authorized route failures only. It does not create trust, credentials, accounts, routes, mounts, backups, restores, or service changes. A direct workstation TCP failure is not treated as proof that a proxied guest is down. Application durability semantics remain owner evidence; Security retains access authority; DR/Data Protection retains protection and recovery acceptance.\n",
    ]
    (run_dir / "REPORT.md").write_text("\n".join(report), encoding="utf-8")
    (run_dir / "HANDOFF_TO_DISASTER_RECOVERY.md").write_text("\n".join(report), encoding="utf-8")

    # Manifest excludes itself and package hash by design.
    members = sorted(p for p in run_dir.rglob("*") if p.is_file())
    manifest = "".join(f"{sha256(p)}  {p.relative_to(run_dir).as_posix()}\n" for p in members)
    (run_dir / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")

    zip_path = out_root / f"{run_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(run_dir.rglob("*")):
            if p.is_file(): z.write(p, p.relative_to(run_dir).as_posix())
    (zip_path.with_suffix(zip_path.suffix + ".sha256")).write_text(f"{sha256(zip_path)}  {zip_path.name}\n", encoding="utf-8")
    print(f"PASS: {zip_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
