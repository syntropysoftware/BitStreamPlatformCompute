from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shlex
import subprocess
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

CONTRACT_NAME = "bitstream-platformcompute-phase0f-strict-proxyjump-persistence-evidence-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
PRODUCTION_MUTATION = "NONE"

FORBIDDEN_ARG_PATTERNS = (
    "stricthostkeychecking=no",
    "userknownhostsfile=/dev/null",
    "ssh-keyscan",
    "preferredauthentications=password",
    "passwordauthentication=yes",
)

SECRETISH_PATTERNS = (
    re.compile(r"(?i)(password|passwd|token|secret|private[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(redis://|mysql://|mariadb://)[^\s]+"),
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


def redact(text: str) -> str:
    out = text
    for pat in SECRETISH_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def run_cmd(argv: Sequence[str], timeout: int = 15) -> CommandEvidence:
    joined = " ".join(str(x) for x in argv).lower()
    if any(p in joined for p in FORBIDDEN_ARG_PATTERNS):
        raise RuntimeError("forbidden trust/auth weakening requested")
    started = time.monotonic()
    try:
        p = subprocess.run(list(argv), text=True, capture_output=True, timeout=timeout, check=False)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc = 124
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        err = (err + "\nTIMEOUT").strip()
    return CommandEvidence(
        list(argv), rc, redact(out), redact(err), int((time.monotonic() - started) * 1000)
    )


def ssh_common() -> List[str]:
    return [
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=7",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=1",
    ]


def ssh_gateway(gateway: str, gateway_port: int, remote: str, timeout: int = 15) -> CommandEvidence:
    return run_cmd(["ssh", *ssh_common(), "-p", str(gateway_port), gateway, remote], timeout=timeout)


def ssh_via_jump(gateway: str, gateway_port: int, target: str, target_port: int, remote: str, timeout: int = 18) -> CommandEvidence:
    # Explicitly exercise the existing H1 jump topology. Strict host-key verification remains enabled for both hops.
    jump = f"{gateway}:{gateway_port}" if gateway_port != 22 else gateway
    return run_cmd(
        ["ssh", *ssh_common(), "-J", jump, "-p", str(target_port), target, remote],
        timeout=timeout,
    )


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
    effective = parse_ssh_g(ev.stdout) if ev.returncode == 0 else {}
    safe_keys = (
        "hostname", "user", "port", "proxyjump", "proxycommand", "identityfile",
        "stricthostkeychecking", "batchmode", "passwordauthentication",
    )
    # Effective config is reduced to routing/auth mechanism only. No file contents or credential material are captured.
    return {
        "returncode": ev.returncode,
        "stderr": ev.stderr,
        "effective": {k: effective[k] for k in safe_keys if k in effective},
    }


def verify_accepted_source(accepted_ref: str) -> Dict[str, Any]:
    head = run_cmd(["git", "rev-parse", "HEAD"], timeout=5)
    ref = run_cmd(["git", "rev-parse", accepted_ref], timeout=5)
    status = run_cmd(["git", "status", "--porcelain"], timeout=5)
    head_sha = head.stdout.strip() if head.returncode == 0 else ""
    accepted_sha = ref.stdout.strip() if ref.returncode == 0 else ""
    clean = status.returncode == 0 and status.stdout.strip() == ""
    accepted = bool(head_sha and accepted_sha and head_sha == accepted_sha and clean)
    reasons: List[str] = []
    if head.returncode != 0:
        reasons.append("HEAD_UNAVAILABLE")
    if ref.returncode != 0:
        reasons.append("ACCEPTED_REF_UNAVAILABLE")
    if head_sha and accepted_sha and head_sha != accepted_sha:
        reasons.append("HEAD_NOT_ACCEPTED_REF")
    if not clean:
        reasons.append("WORKTREE_NOT_CLEAN")
    return {
        "status": "ACCEPTED_SOURCE_PASS" if accepted else "ACCEPTED_SOURCE_BLOCK",
        "accepted": accepted,
        "head": head_sha,
        "accepted_ref": accepted_ref,
        "accepted_ref_sha": accepted_sha,
        "worktree_clean": clean,
        "reasons": reasons,
    }


def gateway_probe(gateway: str, gateway_port: int) -> CommandEvidence:
    return ssh_gateway(gateway, gateway_port, "printf 'PLATFORM_GATEWAY_OK\\n'", timeout=12)


def strict_jump_probe(gateway: str, gateway_port: int, ip: str, port: int) -> CommandEvidence:
    return ssh_via_jump(
        gateway, gateway_port, ip, port,
        "printf 'PLATFORM_PROXYJUMP_GUEST_OK\\n'",
        timeout=18,
    )


def hypervisor_metadata(gateway: str, gateway_port: int, ip: str) -> CommandEvidence:
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
    return ssh_gateway(gateway, gateway_port, remote, timeout=22)


def classify_jump(gateway_ok: bool, jump: CommandEvidence, vm_meta: CommandEvidence) -> Tuple[str, str]:
    combined = (jump.stderr + "\n" + jump.stdout).lower()
    if not gateway_ok:
        return "BLOCKED_GATEWAY_ROUTE", "authorized gateway SSH did not complete"
    if jump.returncode == 0:
        return "STRICT_PROXYJUMP_GUEST_SSH_CONFIRMED", "strict existing H1 ProxyJump path completed"
    if "host key verification failed" in combined or "no ed25519 host key is known" in combined or "host key is unknown" in combined:
        return "BLOCKED_STRICT_HOST_KEY_TRUST", "ProxyJump transport reached a strict host-key trust boundary; no key was enrolled"
    if "permission denied" in combined:
        return "BLOCKED_GUEST_AUTHORIZATION", "ProxyJump transport reached guest authentication; configured identity was not authorized"
    if "connection timed out" in combined or "operation timed out" in combined:
        return "BLOCKED_PROXYJUMP_TARGET_TIMEOUT", "gateway path was invoked but target SSH did not complete before timeout"
    if "connection refused" in combined:
        return "BLOCKED_PROXYJUMP_TARGET_REFUSED", "gateway path reached target address but SSH port refused the connection"
    if "stdio forwarding request failed" in combined or "administratively prohibited" in combined or "session open refused" in combined:
        return "BLOCKED_PROXYJUMP_FORWARDING", "gateway accepted SSH but refused/prohibited forwarding to the target"
    if vm_meta.returncode == 0 and vm_meta.stdout.strip() and "VIRSH_UNAVAILABLE" not in vm_meta.stdout:
        return "GUEST_PRESENT_PROXYJUMP_UNRESOLVED", "hypervisor metadata identifies the target while strict ProxyJump SSH remains unresolved"
    return "UNRESOLVED_PROXYJUMP_LAYER", "strict ProxyJump evidence did not safely identify a more specific failure layer"


MARIADB_REMOTE = r'''set -f
printf 'COLLECTOR=mariadb_persistence\n'
for s in mariadb mysql mysqld; do
  if command -v systemctl >/dev/null 2>&1; then
    printf 'SERVICE_%s=' "$s"; systemctl is-active "$s" 2>/dev/null || true
  fi
done
if command -v mariadb >/dev/null 2>&1; then mariadb --version 2>/dev/null | head -1 | sed 's/^/CLIENT_VERSION=/' || true; fi
if command -v mariadbd >/dev/null 2>&1; then mariadbd --version 2>/dev/null | head -1 | sed 's/^/SERVER_VERSION=/' || true; fi
if command -v mysqld >/dev/null 2>&1; then mysqld --version 2>/dev/null | head -1 | sed 's/^/SERVER_VERSION=/' || true; fi
if command -v ss >/dev/null 2>&1; then ss -lntH 2>/dev/null | awk '$4 ~ /:3306$/ {print "LISTENER=" $4}'; fi
for p in /var/lib/mysql /var/log/mysql /var/log/mariadb; do
  if [ -e "$p" ]; then
    printf 'PATH=%s\n' "$p"
    stat -c 'PATH_MODE=%A PATH_OWNER=%U:%G PATH_DEVICE=%d' "$p" 2>/dev/null || true
    du -sk "$p" 2>/dev/null | awk '{print "PATH_SIZE_KIB=" $1}' || true
  fi
done
# Deliberately no database login, config-file content, process environment, or credential discovery.
'''


REDIS_REMOTE = r'''set -f
printf 'COLLECTOR=redis_persistence\n'
for s in redis redis-server valkey valkey-server sentinel redis-sentinel; do
  if command -v systemctl >/dev/null 2>&1; then
    printf 'SERVICE_%s=' "$s"; systemctl is-active "$s" 2>/dev/null || true
  fi
done
if command -v redis-server >/dev/null 2>&1; then redis-server --version 2>/dev/null | head -1 | sed 's/^/SERVER_VERSION=/' || true; fi
if command -v valkey-server >/dev/null 2>&1; then valkey-server --version 2>/dev/null | head -1 | sed 's/^/SERVER_VERSION=/' || true; fi
if command -v ss >/dev/null 2>&1; then ss -lntH 2>/dev/null | awk '$4 ~ /:(6379|26379)$/ {print "LISTENER=" $4}'; fi
for p in /var/lib/redis /var/lib/valkey /var/log/redis /var/log/valkey; do
  if [ -e "$p" ]; then
    printf 'PATH=%s\n' "$p"
    stat -c 'PATH_MODE=%A PATH_OWNER=%U:%G PATH_DEVICE=%d' "$p" 2>/dev/null || true
    du -sk "$p" 2>/dev/null | awk '{print "PATH_SIZE_KIB=" $1}' || true
  fi
done
cli=''
if command -v redis-cli >/dev/null 2>&1; then cli=redis-cli; elif command -v valkey-cli >/dev/null 2>&1; then cli=valkey-cli; fi
if [ -n "$cli" ]; then
  # No password/user/token options are supplied. Protected instances fail closed and remain authorization-gated.
  "$cli" --no-auth-warning PING 2>/dev/null | sed 's/^/CLI_PING=/' || true
  "$cli" --no-auth-warning DBSIZE 2>/dev/null | sed 's/^/KEYSPACE_COUNT=/' || true
  "$cli" --no-auth-warning INFO persistence 2>/dev/null | grep -E '^(loading|rdb_|aof_|module_fork_)' | sed 's/^/INFO_PERSISTENCE=/' || true
  "$cli" --no-auth-warning INFO replication 2>/dev/null | grep -E '^(role|connected_slaves|master_host|master_port|master_link_status|slave[0-9]+:)' | sed 's/^/INFO_REPLICATION=/' || true
  "$cli" --no-auth-warning INFO sentinel 2>/dev/null | grep -E '^(sentinel_|master[0-9]+:)' | sed 's/^/INFO_SENTINEL=/' || true
  "$cli" --no-auth-warning CONFIG GET dir dbfilename appendonly appendfilename 2>/dev/null | sed 's/^/CONFIG_PERSISTENCE=/' || true
fi
# Deliberately no KEYS/SCAN/GET/MGET/DUMP, no values, and no credential/config-file discovery.
'''


def collect_lane(gateway: str, gateway_port: int, ip: str, port: int, collector: str) -> Optional[CommandEvidence]:
    if collector == "mariadb_persistence":
        return ssh_via_jump(gateway, gateway_port, ip, port, MARIADB_REMOTE, timeout=35)
    if collector == "redis_persistence":
        return ssh_via_jump(gateway, gateway_port, ip, port, REDIS_REMOTE, timeout=35)
    if collector == "route_only":
        return None
    raise RuntimeError(f"unsupported collector: {collector}")


def persistence_status(route_status: str, collector: Optional[CommandEvidence], collector_name: str) -> Tuple[str, str]:
    if route_status != "STRICT_PROXYJUMP_GUEST_SSH_CONFIRMED":
        return route_status, "persistence collection not attempted because strict ProxyJump guest SSH was not confirmed"
    if collector_name == "route_only":
        return route_status, "route-only lane; no persistence collection requested"
    if collector is None:
        return "UNRESOLVED_COLLECTOR_STATE", "collector result missing after confirmed route"
    if collector.returncode != 0:
        return "ROUTE_CONFIRMED_PERSISTENCE_COLLECTION_PARTIAL", "strict route succeeded but bounded persistence collector returned non-zero"
    text = collector.stdout
    material_markers = ("SERVICE_", "SERVER_VERSION=", "CLIENT_VERSION=", "LISTENER=", "PATH=", "KEYSPACE_COUNT=", "INFO_PERSISTENCE=")
    if any(m in text for m in material_markers):
        return "ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_CAPTURED", "strict route succeeded and bounded non-secret persistence evidence was captured"
    return "ROUTE_CONFIRMED_PERSISTENCE_EVIDENCE_EMPTY", "strict route succeeded but allow-listed persistence observations produced no material evidence"


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
    if c.get("authority") != AUTHORITY or c.get("production_mutation") != PRODUCTION_MUTATION:
        raise RuntimeError("authority or mutation boundary mismatch")
    forbidden = " ".join(c.get("forbidden", [])).lower()
    for required in (
        "host_key_enrollment", "root fallback", "sudo escalation", "credential discovery",
        "backup_or_restore_execution", "key enumeration", "value retrieval",
    ):
        if required not in forbidden:
            raise RuntimeError("contract missing hard safety block: " + required)
    return c


def safe_filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", default="contracts/phase0f_strict_proxyjump_persistence_evidence_v1.json")
    ap.add_argument("--output-root", default="evidence")
    args = ap.parse_args(argv)

    contract_path = Path(args.contract)
    contract = load_contract(contract_path)

    source_gate = verify_accepted_source(contract.get("accepted_source_ref", "origin/main"))
    if not source_gate["accepted"]:
        print("BLOCKED: accepted-source validation failed", flush=True)
        print(json.dumps(source_gate, indent=2, sort_keys=True), flush=True)
        return 3

    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0f-readonly-{run_stamp}"
    out_root = Path(args.output_root)
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    gateway = contract["gateway"]["ssh_target"]
    gateway_port = int(contract["gateway"].get("ssh_port", 69))
    gateway_cfg = ssh_config(gateway)
    gateway_ev = gateway_probe(gateway, gateway_port)
    gateway_ok = gateway_ev.returncode == 0
    write_json(run_dir / "source_gate.json", source_gate)
    write_json(run_dir / "gateway.json", {"ssh_config": gateway_cfg, "probe": asdict(gateway_ev)})

    rows: List[Dict[str, Any]] = []
    for t in contract["targets"]:
        lane = t["lane"]
        ip = t["ip"]
        port = int(t.get("ssh_port", 69))
        collector_name = t["collector"]
        target_cfg = ssh_config(ip)
        vm_meta = hypervisor_metadata(gateway, gateway_port, ip) if gateway_ok else CommandEvidence([], 125, "", "gateway unavailable", 0)
        jump = strict_jump_probe(gateway, gateway_port, ip, port) if gateway_ok else CommandEvidence([], 125, "", "gateway unavailable", 0)
        route_status, route_reason = classify_jump(gateway_ok, jump, vm_meta)
        collector_ev = collect_lane(gateway, gateway_port, ip, port, collector_name) if route_status == "STRICT_PROXYJUMP_GUEST_SSH_CONFIRMED" else None
        status, reason = persistence_status(route_status, collector_ev, collector_name)

        evidence = {
            "lane": lane,
            "ip": ip,
            "port": port,
            "collector": collector_name,
            "status": status,
            "reason": reason,
            "route_status": route_status,
            "route_reason": route_reason,
            "target_effective_ssh_config": target_cfg,
            "strict_proxyjump_probe": asdict(jump),
            "hypervisor_vm_metadata": asdict(vm_meta),
            "persistence_collection": asdict(collector_ev) if collector_ev is not None else None,
            "interpretation_rule": "A failed strict ProxyJump probe classifies only the observed transport/trust/auth layer; it is not proof that the guest or datastore is down.",
        }
        write_json(run_dir / f"{safe_filename(lane)}.json", evidence)
        rows.append({"lane": lane, "ip": ip, "status": status, "reason": reason})

    for o in contract.get("owner_evidence_lanes", []):
        rows.append({
            "lane": o["lane"], "ip": o.get("expected_ip", ""),
            "status": "UNRESOLVED_REQUIRES_OWNER_EVIDENCE",
            "reason": "Platform route/persistence evidence does not establish application durable-state semantics or rebuildability",
        })

    rows.extend([
        {
            "lane": "MarketDataInfluxRetention", "ip": "",
            "status": contract["hard_blocks"]["marketdata_influx_retention"],
            "reason": "no explicitly authorized administrative read supplied",
        },
        {
            "lane": "NexusDB", "ip": "192.168.200.23",
            "status": contract["hard_blocks"]["nexusdb"],
            "reason": "Security design approval is not Platform implementation authorization",
        },
    ])

    with (run_dir / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["lane", "ip", "status", "reason"])
        w.writeheader()
        w.writerows(rows)

    summary_env = [
        f"RUN_ID={run_id}",
        f"CONTRACT={CONTRACT_NAME}",
        f"AUTHORITY={AUTHORITY}",
        f"PRODUCTION_MUTATION={PRODUCTION_MUTATION}",
        f"SOURCE_HEAD={source_gate['head']}",
        f"ACCEPTED_SOURCE_REF={source_gate['accepted_ref']}",
        f"ACCEPTED_SOURCE_SHA={source_gate['accepted_ref_sha']}",
        "ACCEPTED_SOURCE_STATUS=ACCEPTED_SOURCE_PASS",
    ]
    summary_env.extend(
        f"{re.sub('[^A-Z0-9]+', '_', r['lane'].upper())}_STATUS={r['status']}" for r in rows
    )
    (run_dir / "summary.env").write_text("\n".join(summary_env) + "\n", encoding="utf-8")

    receipt = {
        "run_id": run_id,
        "contract": CONTRACT_NAME,
        "authority": AUTHORITY,
        "production_mutation": PRODUCTION_MUTATION,
        "completed_utc": utc_now(),
        "source_gate": source_gate,
        "gateway": gateway,
        "gateway_port": gateway_port,
        "contract_sha256": sha256(contract_path),
    }
    write_json(run_dir / "receipt.json", receipt)

    report = [
        "# Platform & Compute Phase-0F strict ProxyJump + persistence evidence",
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
    for r in rows:
        report.append(f"| {r['lane']} | `{r['status']}` | {r['reason']} |")
    report.extend([
        "",
        "## Boundaries",
        "",
        "This product exercises the existing H1 ProxyJump route with strict host-key verification and non-interactive public-key authentication only. It never enrolls host keys, discovers credentials, falls back to root/sudo, changes routes, restarts services, mutates storage, or executes backup/restore operations.",
        "",
        "MariaDB evidence uses only local service/version/listener/path metadata and does not log into the database or read configuration contents. Redis/Valkey evidence uses no credentials and is limited to health/persistence/replication/count metadata; it never enumerates keys or retrieves values. Protected instances fail closed.",
        "",
        "ETHService and NodeServer remain application-owner evidence questions. MarketData Influx administrative retention remains authorization-gated. NexusDB remains design-approved but implementation-not-authorized. DR/Data Protection retains all protection, retention, restore, and recovery acceptance authority.",
        "",
    ])
    text = "\n".join(report)
    (run_dir / "REPORT.md").write_text(text, encoding="utf-8")
    (run_dir / "HANDOFF_TO_DISASTER_RECOVERY.md").write_text(text, encoding="utf-8")

    members = sorted(p for p in run_dir.rglob("*") if p.is_file())
    manifest = "".join(f"{sha256(p)}  {p.relative_to(run_dir).as_posix()}\n" for p in members)
    (run_dir / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")

    zip_path = out_root / f"{run_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(run_dir.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(run_dir).as_posix())
    (zip_path.with_suffix(zip_path.suffix + ".sha256")).write_text(
        f"{sha256(zip_path)}  {zip_path.name}\n", encoding="utf-8"
    )
    print(f"PASS: {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
