#!/usr/bin/env python3
"""BitStream Platform & Compute Phase-0 read-only infrastructure evidence collector.

This collector is intentionally evidence-gated and non-mutating. It never uses sudo,
never changes SSH trust, never writes to remote targets, and never assigns application,
protection, recovery, security, monitoring, or trading authority from host-level facts.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
import zipfile
from dataclasses import dataclass, asdict
from typing import Any, Iterable

CONTRACT = "bitstream-platformcompute-phase0-infrastructure-evidence-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
MUTATION_POLICY = "READ_ONLY_NO_MUTATION"


@dataclass
class Target:
    target_id: str
    ssh_target: str
    expected_ip: str
    scopes: list[str]
    notes: str


@dataclass
class Attempt:
    target_id: str
    route: str
    port: int | None
    status: str
    reason: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(cmd: list[str], *, input_text: str | None = None, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_targets(path: pathlib.Path) -> list[Target]:
    targets: list[Target] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 5:
                raise ValueError(f"Invalid target row (expected 5 tab-separated fields): {line!r}")
            target_id, ssh_target, expected_ip, scopes, notes = parts
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", target_id):
                raise ValueError(f"Unsafe target_id: {target_id!r}")
            targets.append(
                Target(
                    target_id=target_id,
                    ssh_target=ssh_target.strip(),
                    expected_ip=expected_ip.strip(),
                    scopes=[s.strip() for s in scopes.split(",") if s.strip()],
                    notes=notes.strip(),
                )
            )
    return targets


def ssh_config_aliases() -> set[str]:
    config = pathlib.Path.home() / ".ssh" / "config"
    aliases: set[str] = set()
    if not config.is_file():
        return aliases
    try:
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"\s*Host\s+(.+)$", line, re.IGNORECASE)
            if not m:
                continue
            for token in m.group(1).split():
                if not any(ch in token for ch in "*?!"):
                    aliases.add(token)
    except OSError:
        pass
    return aliases


def known_host_present(host: str, port: int | None = None) -> bool:
    if not shutil.which("ssh-keygen"):
        return False
    query = f"[{host}]:{port}" if port and port != 22 else host
    cp = run(["ssh-keygen", "-F", query], timeout=5)
    return cp.returncode == 0 and bool(cp.stdout.strip())


def candidate_routes(target: Target) -> list[tuple[str, int | None, str]]:
    """Return safe route candidates without ever enrolling host keys.

    Alias routes are attempted first because existing SSH config can carry the approved
    jump/port/user path. Direct IP fallbacks are attempted only when a matching host key
    is already present in known_hosts.
    """
    routes: list[tuple[str, int | None, str]] = []
    aliases = ssh_config_aliases()
    if target.ssh_target:
        # Prefer explicitly configured alias. If it is not in ~/.ssh/config, StrictHostKeyChecking
        # still prevents enrollment; we allow one attempt because system-wide SSH config may define it.
        routes.append((target.ssh_target, None, "configured_or_named_alias" if target.ssh_target in aliases else "named_target"))
    if target.expected_ip:
        if known_host_present(target.expected_ip, 22):
            routes.append((target.expected_ip, 22, "known_host_ip_port22"))
        if known_host_present(target.expected_ip, 69):
            routes.append((target.expected_ip, 69, "known_host_ip_port69"))
    # stable dedupe
    seen: set[tuple[str, int | None]] = set()
    out: list[tuple[str, int | None, str]] = []
    for host, port, why in routes:
        key = (host, port)
        if key not in seen:
            seen.add(key)
            out.append((host, port, why))
    return out


REMOTE_PROBE = r'''
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys

SCOPES = set(sys.argv[1].split(',')) if len(sys.argv) > 1 and sys.argv[1] else set()

def run(cmd, timeout=10):
    try:
        cp = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
        return {"rc": cp.returncode, "stdout": cp.stdout.strip(), "stderr": cp.stderr.strip()[:2000]}
    except Exception as exc:
        return {"rc": 999, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}"}

def utc(ts=None):
    if ts is None:
        ts = dt.datetime.now(dt.timezone.utc)
    return ts.replace(microsecond=0).isoformat().replace('+00:00','Z')

def os_release():
    p = pathlib.Path('/etc/os-release')
    out = {}
    if p.is_file():
        for line in p.read_text(encoding='utf-8', errors='replace').splitlines():
            if '=' in line:
                k,v = line.split('=',1)
                if k in {'ID','VERSION_ID','PRETTY_NAME'}:
                    out[k] = v.strip().strip('"')
    return out

def service_state(names):
    result=[]
    if not shutil.which('systemctl'):
        return result
    for name in names:
        show = run(['systemctl','show',name,'--no-pager','--property=LoadState,ActiveState,SubState,FragmentPath,User,Group'], 5)
        if show['rc'] != 0 and 'not-found' in show['stdout']:
            continue
        fields={}
        for line in show['stdout'].splitlines():
            if '=' in line:
                k,v=line.split('=',1); fields[k]=v
        if fields.get('LoadState') and fields.get('LoadState') != 'not-found':
            result.append({'unit':name, **fields})
    return result

def safe_du(path):
    p=pathlib.Path(path)
    if not p.exists():
        return None
    r=run(['du','-sxk',str(p)], 20) if shutil.which('du') else {'rc':127,'stdout':'','stderr':'du unavailable'}
    size_kib=None
    if r['rc']==0 and r['stdout']:
        try: size_kib=int(r['stdout'].split()[0])
        except Exception: pass
    try:
        st=p.stat(); mtime=utc(dt.datetime.fromtimestamp(st.st_mtime,dt.timezone.utc))
    except Exception:
        mtime=None
    return {'path':str(p),'size_kib':size_kib,'mtime_utc':mtime,'readable':os.access(p,os.R_OK),'du_rc':r['rc']}

def recent_write_proxy(path):
    if not pathlib.Path(path).exists() or not shutil.which('find'):
        return None
    # Count only; do not emit filenames or data-bearing paths below the requested root.
    cmd=['bash','-lc',f"find {shlex_quote(path)} -xdev -type f -mmin -60 -printf . 2>/dev/null | wc -c"]
    r=run(cmd, 20)
    count=None
    if r['rc']==0:
        try: count=int(r['stdout'].strip())
        except Exception: pass
    return {'modified_files_last_60m':count,'rc':r['rc']}

def shlex_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def parse_kv(stdout):
    out={}
    for line in stdout.splitlines():
        if '\t' in line:
            k,v=line.split('\t',1); out[k]=v
    return out

def mysql_probe():
    client=shutil.which('mariadb') or shutil.which('mysql')
    result={
      'service_units': service_state(['mariadb.service','mysql.service','mysqld.service']),
      'client_available': bool(client),
      'runtime_query': {'status':'UNAVAILABLE'},
      'operational_source_classification':'UNRESOLVED_REQUIRES_APPLICATION_OR_PLATFORM_AUTHORITY',
      'application_ownership':'UNRESOLVED_NOT_INFERRED_FROM_HOSTNAME_OR_DATABASE_NAMES',
      'protection_evidence':'UNRESOLVED_NOT_INFERRED_FROM_LOCAL_RUNTIME',
      'restore_evidence':'UNRESOLVED_NOT_INFERRED_FROM_LOCAL_RUNTIME'
    }
    if not client:
        return result
    sql=("SELECT CONCAT('hostname\\t',@@hostname);"
         "SELECT CONCAT('version\\t',@@version);"
         "SELECT CONCAT('datadir\\t',@@datadir);"
         "SELECT CONCAT('read_only\\t',@@read_only);"
         "SELECT CONCAT('log_bin\\t',@@log_bin);"
         "SELECT CONCAT('binlog_format\\t',@@binlog_format);"
         "SELECT CONCAT('innodb_flush_log_at_trx_commit\\t',@@innodb_flush_log_at_trx_commit);"
         "SELECT CONCAT('sync_binlog\\t',@@sync_binlog);"
         "SELECT CONCAT('server_id\\t',@@server_id);")
    q=run([client,'--no-defaults','--protocol=socket','--connect-timeout=2','--batch','--skip-column-names','-e',sql], 8)
    result['runtime_query']={'status':'PASS' if q['rc']==0 else 'BLOCKED_OR_UNAVAILABLE','rc':q['rc'],'stderr':q['stderr']}
    if q['rc']==0:
        settings=parse_kv(q['stdout']); result['settings']=settings
        datadir=settings.get('datadir')
        if datadir:
            result['datadir_evidence']=safe_du(datadir)
            result['recent_write_proxy']=recent_write_proxy(datadir)
        dbq=run([client,'--no-defaults','--protocol=socket','--connect-timeout=2','--batch','--skip-column-names','-e','SHOW DATABASES;'],8)
        if dbq['rc']==0:
            result['visible_database_names']=[x for x in dbq['stdout'].splitlines() if x][:200]
            result['database_name_warning']='Names are evidence only; ownership is not inferred from names.'
    return result

def redis_config_candidates():
    candidates=[]
    roots=['/etc/redis','/etc/redis.conf','/etc/redis/redis.conf','/etc/valkey','/etc/valkey.conf','/etc/valkey/valkey.conf']
    files=[]
    for raw in roots:
        p=pathlib.Path(raw)
        if p.is_file(): files.append(p)
        elif p.is_dir():
            files.extend(sorted([x for x in p.glob('*.conf') if x.is_file()])[:50])
    allow={'port','dir','dbfilename','appendonly','appenddirname','save'}
    for p in files:
        safe={}
        try:
            for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
                s=line.strip()
                if not s or s.startswith('#'): continue
                parts=s.split(None,1)
                if len(parts)==2 and parts[0].lower() in allow:
                    safe[parts[0].lower()]=parts[1]
        except Exception as exc:
            safe={'read_error':type(exc).__name__}
        candidates.append({'path':str(p),'non_secret_fields':safe})
    return candidates

def parse_redis_info(text):
    out={}
    for line in text.splitlines():
        if not line or line.startswith('#') or ':' not in line: continue
        k,v=line.split(':',1); out[k]=v
    return out

def redis_probe():
    client=shutil.which('redis-cli') or shutil.which('valkey-cli')
    result={
      'service_units': service_state(['redis.service','redis-server.service','valkey.service']),
      'client_available':bool(client),
      'config_candidates':redis_config_candidates(),
      'namespace_ownership':'UNRESOLVED_NOT_INFERRED_FROM_KEYSPACE_OR_VM_NAME',
      'protection_evidence':'UNRESOLVED_NOT_INFERRED_FROM_LOCAL_RUNTIME',
      'restore_evidence':'UNRESOLVED_NOT_INFERRED_FROM_LOCAL_RUNTIME',
      'instances':[]
    }
    if not client: return result
    ports={6379}
    for cfg in result['config_candidates']:
        val=cfg.get('non_secret_fields',{}).get('port')
        try:
            if val is not None: ports.add(int(val.split()[0]))
        except Exception: pass
    for port in sorted(p for p in ports if 0 < p < 65536)[:20]:
        ping=run([client,'--no-auth-warning','-h','127.0.0.1','-p',str(port),'PING'],4)
        inst={'port':port,'connect_status':'PASS' if ping['rc']==0 and ping['stdout'].strip()=='PONG' else 'BLOCKED_OR_UNAVAILABLE','ping_rc':ping['rc']}
        if inst['connect_status']=='PASS':
            for section in ['persistence','keyspace','memory']:
                rr=run([client,'--no-auth-warning','-h','127.0.0.1','-p',str(port),'INFO',section],5)
                inst[section]=parse_redis_info(rr['stdout']) if rr['rc']==0 else {'query_rc':rr['rc']}
            cfg={}
            for key in ['dir','dbfilename','appendonly','appenddirname']:
                rr=run([client,'--no-auth-warning','-h','127.0.0.1','-p',str(port),'CONFIG','GET',key],5)
                if rr['rc']==0:
                    lines=[x for x in rr['stdout'].splitlines() if x]
                    cfg[key]=lines[-1] if lines else ''
            inst['runtime_config']=cfg
            d=cfg.get('dir')
            if d:
                inst['persistent_path_evidence']=safe_du(d)
                inst['recent_write_proxy']=recent_write_proxy(d)
        else:
            inst['stderr']=ping['stderr']
        result['instances'].append(inst)
    return result

def influx_probe():
    paths=[]
    for p in ['/var/lib/influxdb','/var/lib/influxdb2','/etc/influxdb','/etc/influxdb2']:
        e=safe_du(p)
        if e: paths.append(e)
    return {
      'service_units': service_state(['influxdb.service','influxdb2.service']),
      'path_evidence': paths,
      'physical_ownership':'UNRESOLVED_UNLESS_CORROBORATED_BY_PLATFORM_INVENTORY',
      'application_semantics':'NOT_ASSIGNED_BY_PLATFORM_PROBE'
    }

def du_depth1(root, classification):
    p=pathlib.Path(root)
    if not p.exists() or not shutil.which('du'):
        return []
    r=run(['du','-xk','--max-depth=1',str(p)], 25)
    rows=[]
    if r['rc'] not in (0,1):
        ev=safe_du(root)
        if ev:
            ev['classification']=classification
            rows.append(ev)
        return rows
    for line in r['stdout'].splitlines()[:250]:
        parts=line.split(None,1)
        if len(parts)!=2: continue
        try: size_kib=int(parts[0])
        except Exception: continue
        path=parts[1]
        try:
            st=pathlib.Path(path).stat()
            mtime=utc(dt.datetime.fromtimestamp(st.st_mtime,dt.timezone.utc))
        except Exception:
            mtime=None
        rows.append({'path':path,'size_kib':size_kib,'mtime_utc':mtime,
                     'readable':os.access(path,os.R_OK),'du_rc':r['rc'],
                     'classification':classification})
    return rows

def local_state_probe():
    durable=[]
    rebuildable=[]
    for root in ['/var/lib','/srv','/opt','/etc']:
        durable.extend(du_depth1(root,'DURABLE_CANDIDATE_OWNER_REVIEW_REQUIRED'))
    for root in ['/var/cache','/tmp','/var/tmp']:
        rebuildable.extend(du_depth1(root,'REBUILDABLE_OR_TEMP_BY_PATH_CONVENTION_REVIEW_IF_EXCEPTION'))
    return {
      'durable_candidates':durable,
      'rebuildable_or_temp_candidates':rebuildable,
      'owner_assignment':'UNRESOLVED_REQUIRES_AUTHORITATIVE_OWNER_EVIDENCE',
      'rebuild_source':'UNRESOLVED_REQUIRES_AUTHORITATIVE_OWNER_EVIDENCE',
      'protection_evidence':'UNRESOLVED_NOT_INFERRED_FROM_LOCAL_PATHS',
      'restore_evidence':'UNRESOLVED_NOT_INFERRED_FROM_LOCAL_PATHS'
    }

def main():
    data={
      'observed_at_utc':utc(),
      'hostname':socket.gethostname(),
      'fqdn':socket.getfqdn(),
      'uid':os.geteuid(),
      'username':os.environ.get('USER') or os.environ.get('LOGNAME'),
      'kernel':run(['uname','-srmo'],5)['stdout'],
      'os_release':os_release(),
      'safety':{
        'sudo_used':False,
        'mutation_performed':False,
        'host_key_enrollment_performed':False,
        'service_restart_performed':False,
        'backup_restore_performed':False
      },
      'scopes_requested':sorted(SCOPES)
    }
    if 'mariadb' in SCOPES: data['mariadb']=mysql_probe()
    if 'redis' in SCOPES: data['redis']=redis_probe()
    if 'influx' in SCOPES: data['influx']=influx_probe()
    if 'local_state' in SCOPES: data['server_local_state']=local_state_probe()
    print(json.dumps(data,sort_keys=True))

main()
'''


def ssh_probe(host: str, port: int | None, scopes: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    ssh = shutil.which("ssh")
    if not ssh:
        raise RuntimeError("ssh executable not found")
    cmd = [
        ssh,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=6",
        "-o", "ConnectionAttempts=1",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0",
    ]
    if port:
        cmd += ["-p", str(port)]
    cmd += [host, "python3", "-", ",".join(scopes)]
    return run(cmd, input_text=REMOTE_PROBE, timeout=timeout)


def classify_ssh_error(stderr: str) -> str:
    s = stderr.lower()
    if "host key verification failed" in s or "no ed25519 host key is known" in s or "no rsa host key is known" in s:
        return "BLOCKED_HOST_KEY_NOT_PREAPPROVED"
    if "permission denied" in s:
        return "BLOCKED_AUTHORIZATION_OR_IDENTITY"
    if "could not resolve hostname" in s:
        return "BLOCKED_NAME_RESOLUTION"
    if "connection timed out" in s or "operation timed out" in s:
        return "BLOCKED_CONNECT_TIMEOUT"
    if "connection refused" in s:
        return "BLOCKED_CONNECTION_REFUSED"
    if "python3: command not found" in s or "python3: not found" in s:
        return "BLOCKED_REMOTE_PYTHON3_UNAVAILABLE"
    return "BLOCKED_SSH_OR_REMOTE_PROBE_FAILED"


def collect_target(target: Target, timeout: int) -> tuple[dict[str, Any], list[Attempt]]:
    attempts: list[Attempt] = []
    routes = candidate_routes(target)
    if not routes:
        return ({
            "target": asdict(target),
            "collection_status": "BLOCKED_NO_SAFE_ROUTE",
            "reason": "No SSH alias and no pre-approved known-host IP route were available.",
            "authority": AUTHORITY,
        }, attempts)

    for host, port, route_reason in routes:
        try:
            cp = ssh_probe(host, port, target.scopes, timeout)
        except subprocess.TimeoutExpired:
            attempts.append(Attempt(target.target_id, host, port, "BLOCKED", "BLOCKED_PROBE_TIMEOUT"))
            continue
        except Exception as exc:
            attempts.append(Attempt(target.target_id, host, port, "BLOCKED", f"COLLECTOR_ERROR:{type(exc).__name__}"))
            continue

        if cp.returncode != 0:
            reason = classify_ssh_error(cp.stderr)
            attempts.append(Attempt(target.target_id, host, port, "BLOCKED", reason))
            continue

        try:
            remote = json.loads(cp.stdout)
        except json.JSONDecodeError:
            attempts.append(Attempt(target.target_id, host, port, "BLOCKED", "INVALID_REMOTE_JSON"))
            continue

        attempts.append(Attempt(target.target_id, host, port, "PASS", route_reason))
        observed_host = remote.get("hostname") or ""
        result = {
            "target": asdict(target),
            "collection_status": "PASS_READ_ONLY_EVIDENCE_CAPTURED",
            "route_used": {"ssh_target": host, "port": port, "route_reason": route_reason},
            "observed": remote,
            "identity_assessment": {
                "expected_ip": target.expected_ip or None,
                "observed_hostname": observed_host or None,
                "application_ownership": "UNRESOLVED_NOT_INFERRED_FROM_VM_OR_HOST_NAME",
                "physical_platform_ownership": "OBSERVED_HOST_FACTS_CAPTURED_OWNER_ACCEPTANCE_REQUIRED",
            },
            "authority": AUTHORITY,
        }
        return result, attempts

    return ({
        "target": asdict(target),
        "collection_status": "BLOCKED_NO_SUCCESSFUL_SAFE_ROUTE",
        "reason": attempts[-1].reason if attempts else "NO_ROUTE_ATTEMPTED",
        "authority": AUTHORITY,
    }, attempts)


def write_json(path: pathlib.Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary_csv(path: pathlib.Path, results: list[dict[str, Any]]) -> None:
    fields = [
        "target_id", "ssh_target", "expected_ip", "collection_status", "observed_hostname",
        "mariadb_status", "redis_status", "influx_units", "local_state_status", "application_ownership"
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for item in results:
            target = item.get("target", {})
            obs = item.get("observed", {})
            maria = obs.get("mariadb", {})
            redis = obs.get("redis", {})
            influx = obs.get("influx", {})
            local = obs.get("server_local_state", {})
            w.writerow({
                "target_id": target.get("target_id"),
                "ssh_target": target.get("ssh_target"),
                "expected_ip": target.get("expected_ip"),
                "collection_status": item.get("collection_status"),
                "observed_hostname": obs.get("hostname"),
                "mariadb_status": maria.get("runtime_query", {}).get("status") if maria else "NOT_PROBED",
                "redis_status": "PROBED" if redis else "NOT_PROBED",
                "influx_units": len(influx.get("service_units", [])) if influx else 0,
                "local_state_status": "PROBED" if local else "NOT_PROBED",
                "application_ownership": item.get("identity_assessment", {}).get("application_ownership", "UNRESOLVED"),
            })


def write_report(path: pathlib.Path, run_id: str, results: list[dict[str, Any]], attempts: list[Attempt]) -> None:
    passed = sum(1 for x in results if x.get("collection_status", "").startswith("PASS"))
    blocked = len(results) - passed
    lines = [
        "# Platform & Compute Phase-0 Infrastructure Evidence Report",
        "",
        f"- Contract: `{CONTRACT}`",
        f"- Run ID: `{run_id}`",
        f"- Generated UTC: `{utc_now()}`",
        f"- Authority: `{AUTHORITY}`",
        f"- Mutation policy: `{MUTATION_POLICY}`",
        f"- Targets with read-only evidence: **{passed}**",
        f"- Targets blocked/unresolved: **{blocked}**",
        "",
        "## Safety statement",
        "",
        "This collector does not use `sudo`, does not disable SSH host-key verification, does not enroll host keys, does not create or modify accounts, does not restart services, does not change storage/networking, and does not execute backup or restore operations.",
        "",
        "Hostnames, VM names, database names, keyspace counts, and service placement are treated as evidence only. They do not assign application ownership, RPO/retention, backup acceptance, restore acceptance, monitoring-health meaning, security approval, or trading authority.",
        "",
        "## Target results",
        "",
    ]
    for item in results:
        target = item.get("target", {})
        tid = target.get("target_id", "UNKNOWN")
        lines += [f"### {tid}", "", f"- Status: `{item.get('collection_status')}`"]
        if item.get("reason"):
            lines.append(f"- Reason: `{item.get('reason')}`")
        if item.get("route_used"):
            r = item["route_used"]
            lines.append(f"- Safe route used: `{r.get('ssh_target')}` port `{r.get('port') or 'ssh-config'}`")
        obs = item.get("observed", {})
        if obs:
            lines.append(f"- Observed host: `{obs.get('hostname')}`")
            maria = obs.get("mariadb")
            if maria:
                lines.append(f"- MariaDB runtime query: `{maria.get('runtime_query',{}).get('status')}`")
                lines.append(f"- MariaDB operational-source role: `{maria.get('operational_source_classification')}`")
            redis = obs.get("redis")
            if redis:
                lines.append(f"- Redis/Valkey instances inspected: `{len(redis.get('instances',[]))}`")
                lines.append(f"- Redis namespace ownership: `{redis.get('namespace_ownership')}`")
            influx = obs.get("influx")
            if influx:
                lines.append(f"- Influx service units observed: `{len(influx.get('service_units',[]))}`")
            local = obs.get("server_local_state")
            if local:
                lines.append(f"- Durable-state candidates recorded: `{len(local.get('durable_candidates',[]))}`")
                lines.append(f"- Durable-state owner assignment: `{local.get('owner_assignment')}`")
        lines += [""]

    lines += ["## Connection attempts", ""]
    if attempts:
        for a in attempts:
            lines.append(f"- `{a.target_id}` → `{a.route}` port `{a.port or 'ssh-config'}`: `{a.status}` / `{a.reason}`")
    else:
        lines.append("- No network attempts were made.")
    lines += ["", "## Acceptance boundary", "", "This report is **Platform infrastructure evidence only**. Disaster Recovery / Data Protection and the applicable domain owners retain acceptance and policy authority.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def make_manifest(run_dir: pathlib.Path) -> pathlib.Path:
    manifest = run_dir / "MANIFEST.sha256"
    rows = []
    for path in sorted(p for p in run_dir.rglob("*") if p.is_file() and p.name not in {"MANIFEST.sha256"} and not p.name.endswith(".zip")):
        rows.append(f"{sha256_file(path)}  {path.relative_to(run_dir).as_posix()}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return manifest


def make_bundle(run_dir: pathlib.Path) -> pathlib.Path:
    bundle = run_dir.parent / f"{run_dir.name}.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(p for p in run_dir.rglob("*") if p.is_file()):
            zf.write(path, arcname=f"{run_dir.name}/{path.relative_to(run_dir).as_posix()}")
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect BitStream Platform & Compute Phase-0 read-only infrastructure evidence.")
    parser.add_argument("--targets", required=True, type=pathlib.Path)
    parser.add_argument("--output-root", required=True, type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=75, help="Per-target safe probe timeout in seconds")
    args = parser.parse_args(argv)

    targets = parse_targets(args.targets)
    if not targets:
        print("STOPPED: targets file contains no enabled target rows", file=sys.stderr)
        return 2

    run_stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0-readonly-{run_stamp}"
    run_dir = args.output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    results: list[dict[str, Any]] = []
    attempts: list[Attempt] = []
    for target in targets:
        result, at = collect_target(target, args.timeout)
        results.append(result)
        attempts.extend(at)
        write_json(run_dir / f"target_{target.target_id}.json", result)

    evidence = {
        "contract": CONTRACT,
        "run_id": run_id,
        "generated_at_utc": utc_now(),
        "authority": AUTHORITY,
        "mutation_policy": MUTATION_POLICY,
        "source_targets_file": str(args.targets),
        "targets": results,
        "attempts": [asdict(a) for a in attempts],
        "acceptance": "EVIDENCE_ONLY_NO_DR_OR_DATAPROTECTION_AUTO_ACCEPTANCE",
    }
    write_json(run_dir / "evidence.json", evidence)
    write_summary_csv(run_dir / "summary.csv", results)
    write_report(run_dir / "REPORT.md", run_id, results, attempts)

    receipt = {
        "contract": CONTRACT,
        "run_id": run_id,
        "generated_at_utc": utc_now(),
        "collector_host": socket.gethostname(),
        "collector_user": os.environ.get("USER") or os.environ.get("LOGNAME"),
        "targets_total": len(results),
        "targets_evidence_captured": sum(1 for x in results if x.get("collection_status", "").startswith("PASS")),
        "targets_blocked_or_unresolved": sum(1 for x in results if not x.get("collection_status", "").startswith("PASS")),
        "safety": {
            "sudo_used": False,
            "ssh_host_key_verification": "STRICT",
            "host_key_enrollment": "NEVER",
            "account_mutation": "NEVER",
            "service_restart": "NEVER",
            "storage_network_mutation": "NEVER",
            "backup_restore_execution": "NEVER",
            "rpo_retention_assignment": "NEVER",
        },
        "authority": AUTHORITY,
    }
    write_json(run_dir / "receipt.json", receipt)
    manifest = make_manifest(run_dir)
    bundle = make_bundle(run_dir)
    bundle_sha = sha256_file(bundle)
    (bundle.with_suffix(bundle.suffix + ".sha256")).write_text(f"{bundle_sha}  {bundle.name}\n", encoding="utf-8")

    print("============================================================")
    print(" PLATFORM & COMPUTE — PHASE-0 READ-ONLY INFRASTRUCTURE EVIDENCE")
    print("============================================================")
    print(f"CONTRACT={CONTRACT}")
    print(f"RUN_ID={run_id}")
    print(f"TARGETS={len(results)}")
    print(f"EVIDENCE_CAPTURED={receipt['targets_evidence_captured']}")
    print(f"BLOCKED_OR_UNRESOLVED={receipt['targets_blocked_or_unresolved']}")
    print(f"REPORT={run_dir / 'REPORT.md'}")
    print(f"EVIDENCE={run_dir / 'evidence.json'}")
    print(f"MANIFEST={manifest}")
    print(f"BUNDLE={bundle}")
    print(f"BUNDLE_SHA256={bundle_sha}")
    print("AUTHORITY=PLATFORM_INFRASTRUCTURE_FACTS_ONLY")
    print("MUTATION=NONE")
    print("PASS: Collector completed. Blocked targets remain explicit evidence gaps; they are not auto-accepted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
