#!/usr/bin/env python3
"""BitStream Platform & Compute Phase-0B read-only reconciliation collector.

Purpose:
- classify the failure layer for Phase-0 blocked targets without changing trust;
- refine host-level MariaDB / Redis-Valkey / Influx physical-runtime evidence;
- reduce broad server-local-state candidates into high-signal reconstruction classes;
- emit immutable evidence suitable for DR/Data Protection admission.

This collector does not assign application ownership, backup/restore acceptance, RPO,
retention, monitoring-health meaning, Security approval, or trading authority.
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
import shutil
import socket
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass
from typing import Any

CONTRACT = "bitstream-platformcompute-phase0b-infrastructure-reconciliation-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
MUTATION_POLICY = "READ_ONLY_NO_MUTATION"


@dataclass
class Target:
    target_id: str
    ssh_target: str
    expected_ip: str
    focus: list[str]
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
    rows: list[Target] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 5:
                raise ValueError(f"Invalid target row (expected 5 fields): {line!r}")
            target_id, ssh_target, expected_ip, focus, notes = parts
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", target_id):
                raise ValueError(f"Unsafe target_id: {target_id!r}")
            rows.append(
                Target(
                    target_id=target_id,
                    ssh_target=ssh_target.strip(),
                    expected_ip=expected_ip.strip(),
                    focus=[x.strip() for x in focus.split(",") if x.strip()],
                    notes=notes.strip(),
                )
            )
    return rows


def ssh_config(target: str) -> dict[str, Any]:
    ssh = shutil.which("ssh")
    if not ssh:
        return {"status": "UNAVAILABLE"}
    cp = run([ssh, "-G", target], timeout=8)
    if cp.returncode != 0:
        return {"status": "FAILED", "rc": cp.returncode, "error": sanitize_error(cp.stderr)}
    raw: dict[str, list[str]] = {}
    for line in cp.stdout.splitlines():
        if " " not in line:
            continue
        k, v = line.split(None, 1)
        raw.setdefault(k.lower(), []).append(v.strip())

    def first(name: str) -> str | None:
        vals = raw.get(name.lower()) or []
        return vals[0] if vals else None

    identity_files = raw.get("identityfile", [])
    return {
        "status": "PASS",
        "hostname": first("hostname"),
        "port": int(first("port") or "22") if (first("port") or "22").isdigit() else None,
        "user": first("user"),
        "proxyjump": first("proxyjump"),
        "proxycommand_present": bool(first("proxycommand") and first("proxycommand") != "none"),
        "strict_host_key_checking": first("stricthostkeychecking"),
        "identity_file_count": len(identity_files),
        "identity_file_basenames": [pathlib.Path(x).name for x in identity_files[:20]],
    }


def known_host_match_count(host: str, port: int | None = None) -> int:
    if not host or not shutil.which("ssh-keygen"):
        return 0
    query = f"[{host}]:{port}" if port and port != 22 else host
    cp = run(["ssh-keygen", "-F", query], timeout=5)
    if cp.returncode != 0:
        return 0
    # Count key-record lines only; never copy key material into evidence.
    return sum(1 for line in cp.stdout.splitlines() if line and not line.startswith("#"))


def route_get(ip: str) -> dict[str, Any]:
    if not ip or not shutil.which("ip"):
        return {"status": "UNAVAILABLE"}
    cp = run(["ip", "route", "get", ip], timeout=5)
    return {
        "status": "PASS" if cp.returncode == 0 else "FAILED",
        "rc": cp.returncode,
        "route": cp.stdout.splitlines()[0][:1000] if cp.stdout else "",
        "error": sanitize_error(cp.stderr),
    }


def tcp_connect(ip: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    if not ip:
        return {"status": "SKIPPED"}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = dt.datetime.now(dt.timezone.utc)
    try:
        rc = sock.connect_ex((ip, port))
        elapsed = (dt.datetime.now(dt.timezone.utc) - started).total_seconds()
        return {
            "port": port,
            "status": "TCP_CONNECT_PASS" if rc == 0 else "TCP_CONNECT_FAILED",
            "connect_ex": rc,
            "elapsed_ms": int(elapsed * 1000),
        }
    except socket.timeout:
        return {"port": port, "status": "TCP_CONNECT_TIMEOUT"}
    except OSError as exc:
        return {"port": port, "status": "TCP_CONNECT_ERROR", "errno": exc.errno, "error_type": type(exc).__name__}
    finally:
        sock.close()


def sanitize_error(text: str) -> str:
    s = (text or "").strip()
    s = re.sub(r"/home/[^/\s]+/\.ssh/[^\s:]+", "<SSH_PATH>", s)
    s = re.sub(r"(?i)(password|token|secret)=\S+", r"\1=<REDACTED>", s)
    return s[:2000]


def classify_ssh_error(stderr: str) -> str:
    s = (stderr or "").lower()
    if "host key verification failed" in s or "no ed25519 host key is known" in s or "no rsa host key is known" in s:
        return "BLOCKED_HOST_KEY_NOT_PREAPPROVED"
    if "permission denied" in s:
        return "BLOCKED_AUTHORIZATION_OR_IDENTITY"
    if "could not resolve hostname" in s or "name or service not known" in s:
        return "BLOCKED_NAME_RESOLUTION"
    if "connection timed out" in s or "operation timed out" in s:
        return "BLOCKED_CONNECT_TIMEOUT"
    if "connection refused" in s:
        return "BLOCKED_CONNECTION_REFUSED"
    if "no route to host" in s:
        return "BLOCKED_NO_ROUTE_TO_HOST"
    if "network is unreachable" in s:
        return "BLOCKED_NETWORK_UNREACHABLE"
    if "python3: command not found" in s or "python3: not found" in s:
        return "BLOCKED_REMOTE_PYTHON3_UNAVAILABLE"
    return "BLOCKED_SSH_OR_REMOTE_PROBE_FAILED"


def ssh_batch_test(target: str, timeout: int = 15) -> dict[str, Any]:
    ssh = shutil.which("ssh")
    if not ssh:
        return {"status": "UNAVAILABLE"}
    cmd = [
        ssh,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=6",
        "-o", "ConnectionAttempts=1",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0",
        target,
        "true",
    ]
    try:
        cp = run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "BLOCKED", "reason": "BLOCKED_PROBE_TIMEOUT"}
    if cp.returncode == 0:
        return {"status": "PASS", "reason": "SSH_BATCH_TRUE_PASS"}
    return {
        "status": "BLOCKED",
        "reason": classify_ssh_error(cp.stderr),
        "rc": cp.returncode,
        "stderr": sanitize_error(cp.stderr),
    }


def local_route_diagnostics(target: Target) -> dict[str, Any]:
    cfg = ssh_config(target.ssh_target)
    configured_host = cfg.get("hostname") if cfg.get("status") == "PASS" else None
    configured_port = cfg.get("port") if cfg.get("status") == "PASS" else None
    known_hosts = {
        "ssh_target_port22_matches": known_host_match_count(target.ssh_target, 22),
        "expected_ip_port22_matches": known_host_match_count(target.expected_ip, 22),
        "expected_ip_port69_matches": known_host_match_count(target.expected_ip, 69),
    }
    if configured_host:
        known_hosts["configured_hostname_configured_port_matches"] = known_host_match_count(
            str(configured_host), int(configured_port or 22)
        )
    ports = sorted({22, 69, int(configured_port or 22)})
    return {
        "target_id": target.target_id,
        "expected_ip": target.expected_ip,
        "ssh_target": target.ssh_target,
        "ssh_config": cfg,
        "known_host_preapproval": known_hosts,
        "ip_route": route_get(target.expected_ip),
        "tcp_reachability": [tcp_connect(target.expected_ip, p) for p in ports if 0 < p < 65536],
        "ssh_batch_test": ssh_batch_test(target.ssh_target),
        "trust_mutation_performed": False,
        "host_key_enrollment_performed": False,
        "classification_basis": "LOCAL_READ_ONLY_ROUTE_AND_TRUST_OBSERVATION",
    }


REMOTE_PROBE = r'''
import datetime as dt
import glob
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys

FOCUS=set(sys.argv[1].split(',')) if len(sys.argv)>1 and sys.argv[1] else set()

def run(cmd, timeout=10):
    try:
        cp=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        return {'rc':cp.returncode,'stdout':cp.stdout.strip(),'stderr':cp.stderr.strip()[:2000]}
    except Exception as exc:
        return {'rc':999,'stdout':'','stderr':f'{type(exc).__name__}: {exc}'}

def utc(ts=None):
    if ts is None: ts=dt.datetime.now(dt.timezone.utc)
    return ts.replace(microsecond=0).isoformat().replace('+00:00','Z')

def safe_stat(path):
    p=pathlib.Path(path)
    if not p.exists(): return None
    try:
        st=p.stat()
        return {'path':str(p),'is_dir':p.is_dir(),'size_bytes':st.st_size if p.is_file() else None,
                'mtime_utc':utc(dt.datetime.fromtimestamp(st.st_mtime,dt.timezone.utc)),
                'readable':os.access(p,os.R_OK)}
    except Exception as exc:
        return {'path':str(p),'stat_error':type(exc).__name__}

def safe_du(path, timeout=20):
    p=pathlib.Path(path)
    if not p.exists(): return None
    rr=run(['du','-sxk',str(p)],timeout) if shutil.which('du') else {'rc':127,'stdout':'','stderr':'du unavailable'}
    size=None
    if rr['rc']==0 and rr['stdout']:
        try: size=int(rr['stdout'].split()[0])
        except Exception: pass
    out=safe_stat(path) or {'path':str(p)}
    out['size_kib']=size; out['du_rc']=rr['rc']
    return out

def mount_evidence(path):
    if not shutil.which('findmnt') or not pathlib.Path(path).exists(): return None
    rr=run(['findmnt','-T',str(path),'-n','-o','SOURCE,FSTYPE,TARGET'],5)
    return {'status':'PASS' if rr['rc']==0 else 'UNAVAILABLE','value':rr['stdout'][:1000],'rc':rr['rc']}

def recent_write_proxy(path):
    if not pathlib.Path(path).exists() or not shutil.which('find'): return None
    quoted="'"+str(path).replace("'","'\\''")+"'"
    rr=run(['bash','-lc',f"find {quoted} -xdev -type f -mmin -60 -printf . 2>/dev/null | wc -c"],20)
    count=None
    if rr['rc']==0:
        try: count=int(rr['stdout'])
        except Exception: pass
    return {'modified_files_last_60m':count,'rc':rr['rc']}

def service_state(names):
    out=[]
    if not shutil.which('systemctl'): return out
    props='LoadState,ActiveState,SubState,FragmentPath,User,Group,MainPID,ExecMainStartTimestamp,UnitFileState'
    for name in names:
        rr=run(['systemctl','show',name,'--no-pager',f'--property={props}'],5)
        fields={}
        for line in rr['stdout'].splitlines():
            if '=' in line:
                k,v=line.split('=',1); fields[k]=v
        if fields.get('LoadState') and fields.get('LoadState')!='not-found':
            pid=fields.get('MainPID')
            proc={}
            if pid and pid.isdigit() and pid!='0':
                try: proc['exe']=os.readlink(f'/proc/{pid}/exe')
                except Exception: proc['exe']=None
            out.append({'unit':name,**fields,'process':proc})
    return out

def listeners(ports):
    if not shutil.which('ss'): return []
    rr=run(['ss','-lnt'],8)
    rows=[]
    if rr['rc']!=0: return rows
    for line in rr['stdout'].splitlines()[1:]:
        fields=line.split()
        if len(fields)<4: continue
        local=fields[3]
        m=re.search(r':(\d+)$',local)
        if not m: continue
        port=int(m.group(1))
        if port in ports:
            rows.append({'local_address':local,'port':port})
    return rows[:100]

def package_versions(names):
    out=[]
    if shutil.which('rpm'):
        for name in names:
            rr=run(['rpm','-q','--qf','%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n',name],5)
            if rr['rc']==0:
                for line in rr['stdout'].splitlines():
                    parts=line.split('\t',1)
                    out.append({'name':parts[0],'version':parts[1] if len(parts)>1 else ''})
    elif shutil.which('dpkg-query'):
        for name in names:
            rr=run(['dpkg-query','-W','-f=${Package}\t${Version}\n',name],5)
            if rr['rc']==0:
                for line in rr['stdout'].splitlines():
                    parts=line.split('\t',1); out.append({'name':parts[0],'version':parts[1] if len(parts)>1 else ''})
    return out

def parse_allowlisted_config(paths, allowed):
    rows=[]
    seen=set()
    for raw in paths:
        for name in glob.glob(raw):
            p=pathlib.Path(name)
            if not p.is_file() or str(p) in seen: continue
            seen.add(str(p)); fields={}
            try:
                for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
                    s=line.strip()
                    if not s or s.startswith(('#',';','[')): continue
                    if '=' in s:
                        k,v=s.split('=',1); k=k.strip().lower(); v=v.strip()
                    else:
                        parts=s.split(None,1)
                        if len(parts)!=2: continue
                        k,v=parts[0].lower(),parts[1].strip()
                    if k in allowed and not re.search(r'(?i)pass|token|secret|key',k):
                        fields[k]=v[:500]
            except Exception as exc:
                fields={'read_error':type(exc).__name__}
            rows.append({'path':str(p),'fields':fields,'metadata':safe_stat(str(p))})
    return rows[:100]

def parse_kv(stdout):
    out={}
    for line in stdout.splitlines():
        if '\t' in line:
            k,v=line.split('\t',1); out[k]=v
    return out

def mysql_probe():
    client=shutil.which('mariadb') or shutil.which('mysql')
    units=service_state(['mariadb.service','mysql.service','mysqld.service'])
    result={
      'service_units':units,
      'packages':package_versions(['mariadb-server','MariaDB-server','mysql-server','community-mysql-server']),
      'listeners':listeners({3306}),
      'config_evidence':parse_allowlisted_config(
          ['/etc/my.cnf','/etc/my.cnf.d/*.cnf','/etc/mysql/*.cnf','/etc/mysql/**/*.cnf'],
          {'datadir','port','socket','bind-address','skip-networking','log_bin','server_id','read_only'}),
      'client_available':bool(client),
      'runtime_query':{'status':'UNAVAILABLE'},
      'operational_source_classification':'UNRESOLVED_REQUIRES_APPLICATION_OWNER_CORROBORATION',
      'application_ownership':'UNRESOLVED_NOT_INFERRED_FROM_HOSTNAME_DATABASE_OR_SERVICE_NAME'
    }
    if client:
        sql=("SELECT CONCAT('hostname\\t',@@hostname);"
             "SELECT CONCAT('version\\t',@@version);"
             "SELECT CONCAT('datadir\\t',@@datadir);"
             "SELECT CONCAT('port\\t',@@port);"
             "SELECT CONCAT('socket\\t',@@socket);"
             "SELECT CONCAT('read_only\\t',@@read_only);"
             "SELECT CONCAT('log_bin\\t',@@log_bin);"
             "SELECT CONCAT('binlog_format\\t',@@binlog_format);"
             "SELECT CONCAT('innodb_flush_log_at_trx_commit\\t',@@innodb_flush_log_at_trx_commit);"
             "SELECT CONCAT('sync_binlog\\t',@@sync_binlog);"
             "SELECT CONCAT('server_id\\t',@@server_id);")
        rr=run([client,'--no-defaults','--protocol=socket','--connect-timeout=2','--batch','--skip-column-names','-e',sql],8)
        result['runtime_query']={'status':'PASS' if rr['rc']==0 else 'BLOCKED_OR_UNAVAILABLE','rc':rr['rc'],'stderr':rr['stderr'][:1000]}
        if rr['rc']==0:
            settings=parse_kv(rr['stdout']); result['settings']=settings
            datadir=settings.get('datadir')
            if datadir:
                result['datadir_evidence']=safe_du(datadir)
                result['datadir_mount']=mount_evidence(datadir)
                result['recent_write_proxy']=recent_write_proxy(datadir)
            dbq=run([client,'--no-defaults','--protocol=socket','--connect-timeout=2','--batch','--skip-column-names','-e','SHOW DATABASES;'],8)
            if dbq['rc']==0:
                result['visible_database_names']=[x for x in dbq['stdout'].splitlines() if x][:200]
                result['database_name_warning']='Names are evidence only; ownership is not inferred from names.'
    return result

def redis_configs():
    return parse_allowlisted_config(
      ['/etc/redis.conf','/etc/redis/*.conf','/etc/valkey.conf','/etc/valkey/*.conf'],
      {'port','dir','dbfilename','appendonly','appenddirname','save','bind','protected-mode'})

def parse_info(text):
    out={}
    for line in text.splitlines():
        if line and not line.startswith('#') and ':' in line:
            k,v=line.split(':',1); out[k]=v
    return out

def redis_probe():
    client=shutil.which('valkey-cli') or shutil.which('redis-cli')
    configs=redis_configs(); ports={6379,26379}
    for cfg in configs:
        raw=cfg.get('fields',{}).get('port')
        try:
            if raw is not None: ports.add(int(str(raw).split()[0]))
        except Exception: pass
    result={
      'service_units':service_state(['redis.service','redis-server.service','valkey.service','valkey-sentinel.service','redis-sentinel.service']),
      'packages':package_versions(['redis','valkey']),
      'listeners':listeners(set(ports)),
      'config_evidence':configs,
      'client_available':bool(client),
      'instances':[],
      'namespace_ownership':'UNRESOLVED_NOT_INFERRED_FROM_KEYSPACE_VM_OR_SERVICE_NAME'
    }
    if not client: return result
    for port in sorted(p for p in ports if 0<p<65536)[:20]:
        ping=run([client,'--no-auth-warning','-h','127.0.0.1','-p',str(port),'PING'],4)
        inst={'port':port,'connect_status':'PASS' if ping['rc']==0 and ping['stdout'].strip()=='PONG' else 'BLOCKED_OR_UNAVAILABLE','ping_rc':ping['rc']}
        if inst['connect_status']=='PASS':
            for section in ['persistence','keyspace','memory']:
                rr=run([client,'--no-auth-warning','-h','127.0.0.1','-p',str(port),'INFO',section],5)
                inst[section]=parse_info(rr['stdout']) if rr['rc']==0 else {'query_rc':rr['rc']}
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
                inst['persistent_path_mount']=mount_evidence(d)
        else:
            inst['stderr']=ping['stderr'][:1000]
        result['instances'].append(inst)
    return result

def influx_probe():
    config=parse_allowlisted_config(
      ['/etc/influxdb/influxdb.conf','/etc/influxdb/*.conf','/etc/influxdb2/*.yml','/etc/influxdb2/*.yaml'],
      {'dir','wal-dir','engine','index-version','bind-address','http-bind-address','bolt-path','engine-path'})
    paths=[]
    for p in ['/var/lib/influxdb','/var/lib/influxdb2','/etc/influxdb','/etc/influxdb2']:
        ev=safe_du(p)
        if ev:
            ev['mount']=mount_evidence(p); paths.append(ev)
    return {
      'service_units':service_state(['influxdb.service','influxdb2.service']),
      'packages':package_versions(['influxdb','influxdb2']),
      'listeners':listeners({8086,8088}),
      'config_evidence':config,
      'path_evidence':paths,
      'physical_host_role':'HOST_LEVEL_SERVICE_PLACEMENT_OBSERVED_OWNER_ACCEPTANCE_REQUIRED',
      'application_semantics':'NOT_ASSIGNED_BY_PLATFORM_PROBE'
    }

def classify_path(path):
    p=path.lower().rstrip('/')
    name=pathlib.Path(p).name
    if p.startswith('/var/cache') or p in {'/tmp','/var/tmp'}:
        return ('CACHE_OR_TEMPORARY_STATE','REBUILDABLE_BY_CONVENTION_REVIEW_IF_EXCEPTION')
    if any(p.startswith(x) for x in ['/var/lib/mysql','/var/lib/mariadb','/var/lib/redis','/var/lib/valkey','/var/lib/influxdb','/var/lib/postgresql']):
        return ('DATASTORE_RUNTIME_STATE','NON_REBUILDABLE_UNTIL_DATA_OWNER_PROVES_RECONSTRUCTION_SOURCE')
    if 'bitstream' in name or '/bitstream' in p:
        return ('BITSTREAM_APPLICATION_RUNTIME_STATE','OWNER_REVIEW_REQUIRED_FOR_RECONSTRUCTION_SOURCE')
    if p.startswith('/var/log'):
        return ('LOG_OR_OPERATIONAL_EVIDENCE','RETENTION_AND_RECOVERY_CLASS_REQUIRES_OWNER_POLICY')
    if p.startswith('/etc/letsencrypt') or p.startswith('/var/lib/letsencrypt'):
        return ('CERTIFICATE_STATE','SECURITY_AND_OWNER_REVIEW_REQUIRED')
    if p.startswith('/etc/systemd/system') or p.startswith('/etc/ssh') or p.startswith('/etc/networkmanager') or p in {'/etc/fstab','/etc/crypttab','/etc/hostname','/etc/hosts'}:
        return ('PLATFORM_IDENTITY_OR_CONFIGURATION','CONFIGURATION_REQUIRED_FOR_EXACT_RECONSTRUCTION_OWNER_REVIEW')
    if p.startswith('/var/lib/dnf') or p.startswith('/var/lib/rpm') or p.startswith('/var/lib/packagekit'):
        return ('PACKAGE_OR_SYSTEM_REBUILDABLE_STATE','REBUILDABLE_FROM_PACKAGE_OR_OS_SOURCE_WITH_CONFIG_REVIEW')
    if p.startswith('/srv') or p.startswith('/opt') or p.startswith('/var/lib'):
        return ('OWNER_REVIEW_REQUIRED','RECONSTRUCTION_SOURCE_UNRESOLVED')
    if p.startswith('/etc'):
        return ('PLATFORM_OR_APPLICATION_CONFIGURATION','OWNER_REVIEW_REQUIRED_FOR_RECONSTRUCTION_SOURCE')
    return ('OWNER_REVIEW_REQUIRED','RECONSTRUCTION_SOURCE_UNRESOLVED')

def candidate_paths():
    explicit=[
      '/var/lib/mysql','/var/lib/mariadb','/var/lib/redis','/var/lib/valkey','/var/lib/influxdb','/var/lib/influxdb2',
      '/var/lib/bitstream','/var/lib/bitstream-nexus','/var/lib/letsencrypt','/etc/letsencrypt','/var/log',
      '/etc/systemd/system','/etc/ssh','/etc/NetworkManager','/etc/fstab','/etc/crypttab','/srv','/opt'
    ]
    paths=[]; seen=set()
    for raw in explicit:
        p=pathlib.Path(raw)
        if p.exists() and str(p) not in seen:
            seen.add(str(p)); paths.append(str(p))
    for root in ['/var/lib','/srv','/opt']:
        rp=pathlib.Path(root)
        if not rp.is_dir(): continue
        try: children=sorted([x for x in rp.iterdir() if x.is_dir()])
        except Exception: children=[]
        for child in children[:300]:
            if str(child) in seen: continue
            ev=safe_du(str(child),8)
            size=(ev or {}).get('size_kib') or 0
            lname=child.name.lower()
            if size>=1024 or any(tok in lname for tok in ['bitstream','mysql','mariadb','redis','valkey','influx','postgres']):
                seen.add(str(child)); paths.append(str(child))
    return paths[:120]

def local_state_probe():
    rows=[]
    for path in candidate_paths():
        ev=safe_du(path,15)
        if not ev: continue
        cls,disp=classify_path(path)
        ev.update({
          'classification':cls,
          'reconstruction_disposition':disp,
          'classification_basis':'PATH_CONVENTION_AND_RUNTIME_CORROBORATION_ONLY',
          'mount':mount_evidence(path)
        })
        rows.append(ev)
    rows.sort(key=lambda x: ((x.get('classification') or ''), -(x.get('size_kib') or 0), x.get('path') or ''))
    return {
      'refined_candidates':rows,
      'candidate_count':len(rows),
      'owner_assignment':'UNRESOLVED_EXCEPT_HOST_LEVEL_CLASSIFICATION',
      'classification_warning':'Path class is infrastructure triage, not application ownership or DR acceptance.'
    }

def main():
    data={
      'observed_at_utc':utc(),
      'hostname':socket.gethostname(),
      'fqdn':socket.getfqdn(),
      'uid':os.geteuid(),
      'username':os.environ.get('USER') or os.environ.get('LOGNAME'),
      'kernel':run(['uname','-srmo'],5)['stdout'],
      'focus_requested':sorted(FOCUS),
      'safety':{
        'sudo_used':False,'mutation_performed':False,'host_key_enrollment_performed':False,
        'service_restart_performed':False,'network_storage_mutation_performed':False,
        'backup_restore_performed':False
      }
    }
    if 'mariadb' in FOCUS: data['mariadb']=mysql_probe()
    if 'redis' in FOCUS: data['redis']=redis_probe()
    if 'influx' in FOCUS: data['influx']=influx_probe()
    if 'local_state' in FOCUS: data['server_local_state']=local_state_probe()
    print(json.dumps(data,sort_keys=True))

main()
'''


def ssh_remote_probe(target: Target, timeout: int) -> subprocess.CompletedProcess[str]:
    ssh = shutil.which("ssh")
    if not ssh:
        raise RuntimeError("ssh executable not found")
    focus = [x for x in target.focus if x != "route_diag"]
    cmd = [
        ssh,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=6",
        "-o", "ConnectionAttempts=1",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "NumberOfPasswordPrompts=0",
        target.ssh_target,
        "python3", "-", ",".join(focus),
    ]
    return run(cmd, input_text=REMOTE_PROBE, timeout=timeout)


def collect_target(target: Target, timeout: int) -> tuple[dict[str, Any], list[Attempt]]:
    route = local_route_diagnostics(target)
    attempts: list[Attempt] = []
    batch = route.get("ssh_batch_test", {})

    if batch.get("status") != "PASS":
        reason = batch.get("reason") or "BLOCKED_NO_SUCCESSFUL_SAFE_ROUTE"
        attempts.append(Attempt(target.target_id, target.ssh_target, None, "BLOCKED", str(reason)))
        return ({
            "target": asdict(target),
            "collection_status": "BLOCKED_ROUTE_DIAG_CAPTURED",
            "route_diagnostics": route,
            "reason": reason,
            "remote_probe_performed": False,
            "authority": AUTHORITY,
        }, attempts)

    try:
        cp = ssh_remote_probe(target, timeout)
    except subprocess.TimeoutExpired:
        attempts.append(Attempt(target.target_id, target.ssh_target, None, "BLOCKED", "BLOCKED_PROBE_TIMEOUT"))
        return ({
            "target": asdict(target), "collection_status": "BLOCKED_ROUTE_DIAG_CAPTURED",
            "route_diagnostics": route, "reason": "BLOCKED_PROBE_TIMEOUT",
            "remote_probe_performed": True, "authority": AUTHORITY,
        }, attempts)
    except Exception as exc:
        reason = f"COLLECTOR_ERROR:{type(exc).__name__}"
        attempts.append(Attempt(target.target_id, target.ssh_target, None, "BLOCKED", reason))
        return ({
            "target": asdict(target), "collection_status": "BLOCKED_ROUTE_DIAG_CAPTURED",
            "route_diagnostics": route, "reason": reason,
            "remote_probe_performed": False, "authority": AUTHORITY,
        }, attempts)

    if cp.returncode != 0:
        reason = classify_ssh_error(cp.stderr)
        attempts.append(Attempt(target.target_id, target.ssh_target, None, "BLOCKED", reason))
        return ({
            "target": asdict(target), "collection_status": "BLOCKED_ROUTE_DIAG_CAPTURED",
            "route_diagnostics": route, "reason": reason,
            "remote_probe_error": sanitize_error(cp.stderr),
            "remote_probe_performed": True, "authority": AUTHORITY,
        }, attempts)

    try:
        observed = json.loads(cp.stdout)
    except json.JSONDecodeError:
        attempts.append(Attempt(target.target_id, target.ssh_target, None, "BLOCKED", "INVALID_REMOTE_JSON"))
        return ({
            "target": asdict(target), "collection_status": "BLOCKED_ROUTE_DIAG_CAPTURED",
            "route_diagnostics": route, "reason": "INVALID_REMOTE_JSON",
            "remote_probe_performed": True, "authority": AUTHORITY,
        }, attempts)

    attempts.append(Attempt(target.target_id, target.ssh_target, None, "PASS", "SSH_BATCH_AND_REMOTE_PROBE_PASS"))
    return ({
        "target": asdict(target),
        "collection_status": "PASS_REFINED_READ_ONLY_EVIDENCE_CAPTURED",
        "route_diagnostics": route,
        "remote_probe_performed": True,
        "observed": observed,
        "identity_assessment": {
            "expected_ip": target.expected_ip,
            "observed_hostname": observed.get("hostname"),
            "application_ownership": "UNRESOLVED_NOT_INFERRED_FROM_VM_HOST_DATABASE_SERVICE_OR_PATH_NAME",
            "physical_runtime_facts": "OBSERVED_PLATFORM_FACTS_CAPTURED_OWNER_ACCEPTANCE_REQUIRED",
        },
        "authority": AUTHORITY,
    }, attempts)


def write_json(path: pathlib.Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def target_by_id(results: list[dict[str, Any]], target_id: str) -> dict[str, Any] | None:
    for item in results:
        if item.get("target", {}).get("target_id") == target_id:
            return item
    return None


def build_blocker_matrix(results: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for item in results:
        t = item.get("target", {})
        route = item.get("route_diagnostics", {})
        batch = route.get("ssh_batch_test", {})
        rows.append({
            "target_id": t.get("target_id"),
            "ssh_target": t.get("ssh_target"),
            "expected_ip": t.get("expected_ip"),
            "collection_status": item.get("collection_status"),
            "blocker_reason": item.get("reason"),
            "ssh_batch_status": batch.get("status"),
            "ssh_batch_reason": batch.get("reason"),
            "configured_hostname": route.get("ssh_config", {}).get("hostname"),
            "configured_port": route.get("ssh_config", {}).get("port"),
            "host_key_preapproval": route.get("known_host_preapproval"),
            "tcp_reachability": route.get("tcp_reachability"),
        })
    return {
        "contract": CONTRACT,
        "authority": AUTHORITY,
        "rows": rows,
        "interpretation": "Blocker classifications are read-only route/trust evidence; no access control was modified.",
    }


def build_shared_service_ownership(results: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for item in results:
        if not str(item.get("collection_status", "")).startswith("PASS"):
            continue
        t = item.get("target", {})
        obs = item.get("observed", {})
        maria = obs.get("mariadb", {})
        redis = obs.get("redis", {})
        influx = obs.get("influx", {})
        rows.append({
            "target_id": t.get("target_id"),
            "observed_hostname": obs.get("hostname"),
            "mariadb": {
                "service_units": maria.get("service_units", []),
                "runtime_query": maria.get("runtime_query"),
                "settings": maria.get("settings"),
                "datadir_evidence": maria.get("datadir_evidence"),
                "datadir_mount": maria.get("datadir_mount"),
                "listeners": maria.get("listeners", []),
                "packages": maria.get("packages", []),
                "operational_source_classification": maria.get("operational_source_classification"),
            },
            "redis_valkey": {
                "service_units": redis.get("service_units", []),
                "listeners": redis.get("listeners", []),
                "instances": redis.get("instances", []),
                "packages": redis.get("packages", []),
                "namespace_ownership": redis.get("namespace_ownership"),
            },
            "influx": {
                "service_units": influx.get("service_units", []),
                "listeners": influx.get("listeners", []),
                "path_evidence": influx.get("path_evidence", []),
                "packages": influx.get("packages", []),
                "physical_host_role": influx.get("physical_host_role"),
            },
            "application_ownership": "UNRESOLVED_NOT_INFERRED_FROM_PLATFORM_FACTS",
        })
    return {"contract": CONTRACT, "authority": AUTHORITY, "hosts": rows}


def build_durable_state_refined(results: list[dict[str, Any]]) -> dict[str, Any]:
    hosts = []
    for item in results:
        if not str(item.get("collection_status", "")).startswith("PASS"):
            continue
        obs = item.get("observed", {})
        state = obs.get("server_local_state", {})
        hosts.append({
            "target_id": item.get("target", {}).get("target_id"),
            "observed_hostname": obs.get("hostname"),
            "candidate_count": state.get("candidate_count", 0),
            "refined_candidates": state.get("refined_candidates", []),
            "owner_assignment": state.get("owner_assignment"),
        })
    return {
        "contract": CONTRACT,
        "authority": AUTHORITY,
        "hosts": hosts,
        "acceptance_warning": "Infrastructure triage classes do not assign DR protection/restore acceptance or application ownership.",
    }


def write_summary_csv(path: pathlib.Path, results: list[dict[str, Any]]) -> None:
    fields = [
        "target_id", "expected_ip", "collection_status", "blocker_reason", "ssh_batch_reason",
        "observed_hostname", "mariadb_runtime", "redis_active_instances", "influx_active_units",
        "durable_refined_candidates", "application_ownership",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for item in results:
            obs = item.get("observed", {})
            maria = obs.get("mariadb", {})
            redis = obs.get("redis", {})
            influx = obs.get("influx", {})
            local = obs.get("server_local_state", {})
            active_redis = sum(1 for x in redis.get("instances", []) if x.get("connect_status") == "PASS")
            active_influx = sum(1 for x in influx.get("service_units", []) if x.get("ActiveState") == "active")
            w.writerow({
                "target_id": item.get("target", {}).get("target_id"),
                "expected_ip": item.get("target", {}).get("expected_ip"),
                "collection_status": item.get("collection_status"),
                "blocker_reason": item.get("reason"),
                "ssh_batch_reason": item.get("route_diagnostics", {}).get("ssh_batch_test", {}).get("reason"),
                "observed_hostname": obs.get("hostname"),
                "mariadb_runtime": maria.get("runtime_query", {}).get("status") if maria else "NOT_PROBED",
                "redis_active_instances": active_redis,
                "influx_active_units": active_influx,
                "durable_refined_candidates": local.get("candidate_count", 0),
                "application_ownership": item.get("identity_assessment", {}).get("application_ownership", "UNRESOLVED"),
            })


def write_report(path: pathlib.Path, run_id: str, results: list[dict[str, Any]]) -> None:
    captured = sum(1 for x in results if str(x.get("collection_status", "")).startswith("PASS"))
    blocked = len(results) - captured
    lines = [
        "# Platform & Compute Phase-0B Blocker / Ownership Reconciliation Report",
        "",
        f"- Contract: `{CONTRACT}`",
        f"- Run ID: `{run_id}`",
        f"- Generated UTC: `{utc_now()}`",
        f"- Authority: `{AUTHORITY}`",
        f"- Mutation policy: `{MUTATION_POLICY}`",
        f"- Targets with refined remote evidence: **{captured}**",
        f"- Targets with route/trust blocker evidence only: **{blocked}**",
        "",
        "## Safety statement",
        "",
        "This collector uses strict SSH host-key verification and does not use sudo, enroll host keys, create or modify accounts, restart services, alter network/storage state, or execute backup/restore operations.",
        "",
        "## Target results",
        "",
    ]
    for item in results:
        t = item.get("target", {})
        route = item.get("route_diagnostics", {})
        lines += [f"### {t.get('target_id')}", "", f"- Status: `{item.get('collection_status')}`"]
        if item.get("reason"):
            lines.append(f"- Blocker: `{item.get('reason')}`")
        cfg = route.get("ssh_config", {})
        lines.append(f"- SSH config: `{cfg.get('status')}` / host `{cfg.get('hostname')}` / port `{cfg.get('port')}`")
        lines.append(f"- SSH batch test: `{route.get('ssh_batch_test', {}).get('status')}` / `{route.get('ssh_batch_test', {}).get('reason')}`")
        if item.get("observed"):
            obs = item["observed"]
            lines.append(f"- Observed host: `{obs.get('hostname')}`")
            maria = obs.get("mariadb", {})
            if maria:
                lines.append(f"- MariaDB runtime: `{maria.get('runtime_query', {}).get('status')}`")
                if maria.get("datadir_evidence"):
                    lines.append(f"- MariaDB datadir: `{maria['datadir_evidence'].get('path')}` / `{maria['datadir_evidence'].get('size_kib')}` KiB")
            redis = obs.get("redis", {})
            if redis:
                lines.append(f"- Redis/Valkey active local instances: `{sum(1 for x in redis.get('instances',[]) if x.get('connect_status')=='PASS')}`")
            influx = obs.get("influx", {})
            if influx:
                lines.append(f"- Influx active service units: `{sum(1 for x in influx.get('service_units',[]) if x.get('ActiveState')=='active')}`")
            local = obs.get("server_local_state", {})
            if local:
                lines.append(f"- Refined server-local-state candidates: `{local.get('candidate_count',0)}`")
        lines += [""]
    lines += [
        "## Acceptance boundary", "",
        "This is Platform infrastructure evidence only. Application/domain ownership, Security authorization, backup/retention policy, restore acceptance, RPO, monitoring-health meaning, and trading authority remain with their owning departments.", "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def make_manifest(run_dir: pathlib.Path) -> pathlib.Path:
    manifest = run_dir / "MANIFEST.sha256"
    rows = []
    for p in sorted(x for x in run_dir.rglob("*") if x.is_file() and x.name != "MANIFEST.sha256"):
        rows.append(f"{sha256_file(p)}  {p.relative_to(run_dir).as_posix()}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return manifest


def make_bundle(run_dir: pathlib.Path) -> pathlib.Path:
    bundle = run_dir.parent / f"{run_dir.name}.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(x for x in run_dir.rglob("*") if x.is_file()):
            zf.write(p, arcname=f"{run_dir.name}/{p.relative_to(run_dir).as_posix()}")
    return bundle


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Collect Platform & Compute Phase-0B read-only reconciliation evidence.")
    ap.add_argument("--targets", required=True, type=pathlib.Path)
    ap.add_argument("--output-root", required=True, type=pathlib.Path)
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args(argv)

    targets = parse_targets(args.targets)
    if not targets:
        print("STOPPED: no enabled Phase-0B targets", file=sys.stderr)
        return 2

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0b-readonly-{stamp}"
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
        "targets": results,
        "attempts": [asdict(x) for x in attempts],
        "acceptance": "EVIDENCE_ONLY_NO_AUTO_ACCEPTANCE",
    }
    write_json(run_dir / "evidence.json", evidence)
    write_json(run_dir / "phase0b_blocker_matrix.json", build_blocker_matrix(results))
    write_json(run_dir / "shared_service_ownership.json", build_shared_service_ownership(results))
    write_json(run_dir / "durable_state_refined.json", build_durable_state_refined(results))

    clientapp = target_by_id(results, "H1_ClientAppDB")
    nexusdb = target_by_id(results, "H1_NexusDB")
    if clientapp is not None:
        write_json(run_dir / "clientappdb_safe_route.json", clientapp.get("route_diagnostics", {}))
    if nexusdb is not None:
        write_json(run_dir / "nexusdb_trust_boundary.json", nexusdb.get("route_diagnostics", {}))

    write_summary_csv(run_dir / "summary.csv", results)
    write_report(run_dir / "REPORT.md", run_id, results)

    receipt = {
        "contract": CONTRACT,
        "run_id": run_id,
        "generated_at_utc": utc_now(),
        "collector_host": socket.gethostname(),
        "collector_user": os.environ.get("USER") or os.environ.get("LOGNAME"),
        "targets_total": len(results),
        "targets_refined_remote_evidence": sum(1 for x in results if str(x.get("collection_status", "")).startswith("PASS")),
        "targets_route_or_trust_blocked": sum(1 for x in results if not str(x.get("collection_status", "")).startswith("PASS")),
        "safety": {
            "sudo_used": False,
            "ssh_host_key_verification": "STRICT",
            "host_key_enrollment": "NEVER",
            "account_mutation": "NEVER",
            "service_restart": "NEVER",
            "network_storage_mutation": "NEVER",
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
    print(" PLATFORM & COMPUTE — PHASE-0B RECONCILIATION EVIDENCE")
    print("============================================================")
    print(f"CONTRACT={CONTRACT}")
    print(f"RUN_ID={run_id}")
    print(f"TARGETS={len(results)}")
    print(f"REFINED_REMOTE_EVIDENCE={receipt['targets_refined_remote_evidence']}")
    print(f"ROUTE_OR_TRUST_BLOCKED={receipt['targets_route_or_trust_blocked']}")
    print(f"REPORT={run_dir / 'REPORT.md'}")
    print(f"BLOCKER_MATRIX={run_dir / 'phase0b_blocker_matrix.json'}")
    print(f"SHARED_SERVICE_OWNERSHIP={run_dir / 'shared_service_ownership.json'}")
    print(f"DURABLE_STATE_REFINED={run_dir / 'durable_state_refined.json'}")
    print(f"MANIFEST={manifest}")
    print(f"BUNDLE={bundle}")
    print(f"BUNDLE_SHA256={bundle_sha}")
    print(f"AUTHORITY={AUTHORITY}")
    print("MUTATION=NONE")
    print("PASS: Phase-0B completed. Blockers remain explicit; no authority was inferred or widened.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
