#!/usr/bin/env python3
"""BitStream Platform & Compute Phase-0C focused read-only completion collector.

This collector implements only the CURRENT Disaster Recovery / Data Protection
focused completion request dated 2026-09-05. It intentionally does not repeat
broad Phase-0/Phase-0B discovery and does not implement the NexusDB reader.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any

CONTRACT = "bitstream-platformcompute-phase0c-focused-infrastructure-completion-v1"
AUTHORITY = "PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
MUTATION_POLICY = "READ_ONLY_NO_MUTATION"

HERE = pathlib.Path(__file__).resolve().parent
P0B_PATH = HERE / "phase0b_infrastructure_reconciliation.py"
if not P0B_PATH.is_file():
    raise RuntimeError(f"Required Phase-0B dependency is missing: {P0B_PATH}")
spec = importlib.util.spec_from_file_location("platformcompute_phase0b_dependency", P0B_PATH)
p0b = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = p0b
spec.loader.exec_module(p0b)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: pathlib.Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value).replace("\n", " ").replace("\r", " ").strip()


def load_config(path: pathlib.Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    required = {"mariadb18", "redisserver6", "ethservice", "nodeserver", "clientappdb19", "marketdata_influx", "nexusdb"}
    missing = required - set(obj)
    if missing:
        raise ValueError(f"Phase-0C config missing sections: {sorted(missing)}")
    if obj["nexusdb"].get("platform_implementation_authorized") is not False:
        raise ValueError("Phase-0C must keep NexusDB implementation unauthorized")
    return obj


def route_observation(entry: dict[str, Any], *, run_ssh: bool) -> dict[str, Any]:
    alias = str(entry.get("ssh_target") or "")
    expected_ip = str(entry.get("expected_ip") or "")
    cfg = p0b.ssh_config(alias) if alias else {"status": "UNAVAILABLE"}
    configured_host = str(cfg.get("hostname") or "")
    configured_port = cfg.get("port") if isinstance(cfg.get("port"), int) else 22
    known = {
        "configured_target_matches": p0b.known_host_match_count(configured_host, configured_port) if configured_host else 0,
        "expected_ip_port22_matches": p0b.known_host_match_count(expected_ip, 22) if expected_ip else 0,
        "expected_ip_port69_matches": p0b.known_host_match_count(expected_ip, 69) if expected_ip else 0,
    }
    out = {
        "ssh_target": alias,
        "expected_ip": expected_ip,
        "ssh_config": cfg,
        "known_host_preapproval": known,
        "ip_route": p0b.route_get(expected_ip) if expected_ip else {"status": "NOT_REQUESTED"},
        "ssh_batch_test": {"status": "NOT_RUN", "reason": "LOCAL_EVIDENCE_ONLY"},
        "trust_mutation_performed": False,
        "host_key_enrollment_performed": False,
    }
    if run_ssh and alias:
        out["ssh_batch_test"] = p0b.ssh_batch_test(alias)
    return out


def resolved_host_from_local_evidence(entry: dict[str, Any]) -> dict[str, Any]:
    route = route_observation(entry, run_ssh=False)
    cfg = route.get("ssh_config", {})
    configured = str(cfg.get("hostname") or "")
    resolved: list[str] = []
    if configured:
        try:
            for item in socket.getaddrinfo(configured, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM):
                ip = item[4][0]
                if ip not in resolved:
                    resolved.append(ip)
        except OSError:
            pass
    exact = configured if configured and configured != str(entry.get("ssh_target") or "") else "UNRESOLVED"
    return {
        "local_route_evidence": route,
        "configured_hostname": configured or "UNRESOLVED",
        "resolved_addresses": resolved,
        "exact_host_vm_identity": exact,
        "network_connection_attempted": False,
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

MODE=sys.argv[1]

def run(cmd, timeout=10):
    try:
        cp=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        return {'rc':cp.returncode,'stdout':cp.stdout.strip(),'stderr':sanitize(cp.stderr)}
    except Exception as exc:
        return {'rc':999,'stdout':'','stderr':f'{type(exc).__name__}: {exc}'}

def sanitize(text):
    s=(text or '').strip()
    s=re.sub(r'(?i)(password|token|secret|authorization)[=: ]+\\S+',r'\\1=<REDACTED>',s)
    return s[:2000]

def utc(ts=None):
    if ts is None: ts=dt.datetime.now(dt.timezone.utc)
    return ts.replace(microsecond=0).isoformat().replace('+00:00','Z')

def safe_stat(path):
    p=pathlib.Path(path)
    if not p.exists(): return None
    try:
        st=p.stat()
        return {'path':str(p),'is_dir':p.is_dir(),'size_bytes':st.st_size if p.is_file() else None,
                'mtime_utc':utc(dt.datetime.fromtimestamp(st.st_mtime,dt.timezone.utc)),'readable':os.access(p,os.R_OK)}
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

def recent_write(path):
    p=pathlib.Path(path)
    if not p.exists() or not shutil.which('find'): return None
    q="'"+str(path).replace("'","'\\''")+"'"
    rr=run(['bash','-lc',f"find {q} -xdev -type f -mmin -60 -printf . 2>/dev/null | wc -c"],20)
    count=None
    if rr['rc']==0:
        try: count=int(rr['stdout'])
        except Exception: pass
    return {'modified_files_last_60m':count,'rc':rr['rc']}

def findmnt(path):
    if not shutil.which('findmnt') or not pathlib.Path(path).exists(): return None
    rr=run(['findmnt','-T',str(path),'-n','-o','SOURCE,FSTYPE,TARGET,OPTIONS'],5)
    return {'status':'PASS' if rr['rc']==0 else 'UNAVAILABLE','value':rr['stdout'][:1500],'rc':rr['rc']}

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
            pid=fields.get('MainPID'); proc={}
            if pid and pid.isdigit() and pid!='0':
                try: proc['exe']=os.readlink(f'/proc/{pid}/exe')
                except Exception: proc['exe']=None
            out.append({'unit':name,**fields,'process':proc})
    return out

def listeners(ports):
    if not shutil.which('ss'): return []
    rr=run(['ss','-lnt'],8); rows=[]
    if rr['rc']!=0: return rows
    for line in rr['stdout'].splitlines()[1:]:
        f=line.split()
        if len(f)<4: continue
        local=f[3]; m=re.search(r':(\\d+)$',local)
        if m and int(m.group(1)) in ports: rows.append({'local_address':local,'port':int(m.group(1))})
    return rows[:100]

def packages(names):
    out=[]
    if shutil.which('rpm'):
        for n in names:
            rr=run(['rpm','-q','--qf','%{NAME}\\t%{VERSION}-%{RELEASE}.%{ARCH}\\n',n],5)
            if rr['rc']==0:
                for line in rr['stdout'].splitlines():
                    p=line.split('\\t',1); out.append({'name':p[0],'version':p[1] if len(p)>1 else ''})
    elif shutil.which('dpkg-query'):
        for n in names:
            rr=run(['dpkg-query','-W','-f=${Package}\\t${Version}\\n',n],5)
            if rr['rc']==0:
                for line in rr['stdout'].splitlines():
                    p=line.split('\\t',1); out.append({'name':p[0],'version':p[1] if len(p)>1 else ''})
    return out

def config_fields(patterns, allowed):
    rows=[]; seen=set()
    for pattern in patterns:
        for name in glob.glob(pattern,recursive=True):
            p=pathlib.Path(name)
            if not p.is_file() or str(p) in seen: continue
            seen.add(str(p)); fields={}
            try:
                for raw in p.read_text(encoding='utf-8',errors='replace').splitlines():
                    s=raw.strip()
                    if not s or s.startswith(('#',';','[')): continue
                    if '=' in s:
                        k,v=s.split('=',1); k=k.strip().lower(); v=v.strip()
                    else:
                        parts=s.split(None,1)
                        if len(parts)!=2: continue
                        k,v=parts[0].lower(),parts[1].strip()
                    if k in allowed and not re.search(r'(?i)pass|token|secret|key|auth',k):
                        fields.setdefault(k,[]).append(v[:500])
            except Exception as exc:
                fields={'read_error':[type(exc).__name__]}
            rows.append({'path':str(p),'fields':fields,'metadata':safe_stat(str(p))})
    return rows[:100]

def visible_protection(path=None):
    tools=[]
    for name in ['mariabackup','mysqldump','restic','borg','rsnapshot','snapper','lvs','zfs','btrfs']:
        exe=shutil.which(name)
        if exe: tools.append({'tool':name,'path':exe})
    units=[]
    if shutil.which('systemctl'):
        rr=run(['systemctl','list-unit-files','--no-pager','--no-legend'],8)
        if rr['rc']==0:
            for line in rr['stdout'].splitlines():
                if re.search(r'(?i)backup|snapshot|restic|borg|mariabackup|mysqldump',line): units.append(line[:500])
    locations=[]
    for candidate in ['/var/backups','/backup','/backups','/srv/backup','/srv/backups']:
        x=safe_du(candidate,10)
        if x: locations.append(x)
    mount=findmnt(path) if path else None
    block=[]
    if shutil.which('lsblk'):
        rr=run(['lsblk','-o','NAME,TYPE,FSTYPE,SIZE,MOUNTPOINTS'],8)
        if rr['rc']==0: block=rr['stdout'].splitlines()[:80]
    return {'tools':tools,'systemd_units':units[:100],'artifact_locations':locations,'mount':mount,'block_layout':block}

def mysql_query(client, sql, timeout=8):
    return run([client,'--no-defaults','--protocol=socket','--connect-timeout=2','--batch','--skip-column-names','-e',sql],timeout)

def mariadb_probe():
    client=shutil.which('mariadb') or shutil.which('mysql')
    config=config_fields(['/etc/my.cnf','/etc/my.cnf.d/*.cnf','/etc/mysql/*.cnf','/etc/mysql/**/*.cnf'],
       {'datadir','port','socket','bind-address','skip-networking','log_bin','server_id','read_only','innodb_flush_log_at_trx_commit','sync_binlog','binlog_format'})
    out={'hostname':socket.gethostname(),'service_units':service_state(['mariadb.service','mysql.service','mysqld.service']),
         'packages':packages(['mariadb-server','MariaDB-server','mysql-server','community-mysql-server']),
         'listeners':listeners({3306}),'config_evidence':config,'runtime_query':{'status':'UNAVAILABLE'},
         'schema_inventory':[],'table_size_summary':[],'replication':{'status':'UNAVAILABLE'},'ownership':'NOT_INFERRED_FROM_SCHEMA_NAMES'}
    datadir=None
    if client:
        rr=mysql_query(client,"SELECT @@hostname,@@version,@@datadir,@@port,@@socket,@@read_only,@@log_bin,@@binlog_format,@@innodb_flush_log_at_trx_commit,@@sync_binlog,@@server_id;")
        if rr['rc']==0 and rr['stdout']:
            vals=rr['stdout'].split('\\t')
            keys=['hostname','version','datadir','port','socket','read_only','log_bin','binlog_format','innodb_flush_log_at_trx_commit','sync_binlog','server_id']
            out['runtime_query']={'status':'PASS',**{k:(vals[i] if i<len(vals) else '') for i,k in enumerate(keys)}}
            datadir=out['runtime_query'].get('datadir') or None
            db=mysql_query(client,"SHOW DATABASES;")
            if db['rc']==0: out['schema_inventory']=[x for x in db['stdout'].splitlines() if x][:500]
            ts=mysql_query(client,"SELECT TABLE_SCHEMA,COUNT(*),COALESCE(ROUND(SUM(DATA_LENGTH+INDEX_LENGTH)/1024/1024,2),0) FROM information_schema.TABLES GROUP BY TABLE_SCHEMA ORDER BY 3 DESC;",12)
            if ts['rc']==0:
                for line in ts['stdout'].splitlines()[:500]:
                    p=line.split('\\t');
                    if len(p)>=3: out['table_size_summary'].append({'schema':p[0],'table_count':p[1],'approx_mib':p[2]})
            repl=mysql_query(client,"SHOW REPLICA STATUS;",8)
            if repl['rc']!=0 or not repl['stdout']:
                repl=mysql_query(client,"SHOW SLAVE STATUS;",8)
            out['replication']={'status':'CONFIGURED_OR_VISIBLE' if repl['rc']==0 and bool(repl['stdout']) else 'NOT_OBSERVED_OR_UNAVAILABLE','rows_present':bool(repl['stdout']) if repl['rc']==0 else False,'rc':repl['rc']}
        else:
            out['runtime_query']={'status':'UNAVAILABLE','rc':rr['rc'],'error':rr['stderr'][:1000]}
    if not datadir:
        for row in config:
            vals=row.get('fields',{}).get('datadir') or []
            if vals: datadir=vals[0]; break
    if datadir:
        out['datadir']=datadir; out['datastore']=safe_du(datadir,30); out['mount']=findmnt(datadir); out['recent_write_activity']=recent_write(datadir)
    else:
        out['datadir']='UNRESOLVED'; out['datastore']=None; out['mount']=None; out['recent_write_activity']=None
    out['protection_observation']=visible_protection(datadir)
    return out

def redis_config_probe():
    rows=[]
    patterns=['/etc/redis*.conf','/etc/redis/*.conf','/etc/valkey/*.conf','/etc/valkey*.conf']
    for pattern in patterns:
        for name in glob.glob(pattern):
            p=pathlib.Path(name)
            if not p.is_file(): continue
            fields={}
            try:
                for raw in p.read_text(encoding='utf-8',errors='replace').splitlines():
                    s=raw.strip()
                    if not s or s.startswith('#'): continue
                    parts=s.split(None,1)
                    if len(parts)!=2: continue
                    k,v=parts[0].lower(),parts[1].strip()
                    if k in {'dir','dbfilename','appendonly','appendfilename','appenddirname','save','port','bind','replicaof','slaveof'}:
                        fields.setdefault(k,[]).append(v[:500])
                    elif k=='sentinel' and v.lower().startswith('monitor '):
                        fields.setdefault('sentinel_monitor',[]).append(v[:500])
            except Exception as exc:
                fields={'read_error':[type(exc).__name__]}
            rows.append({'path':str(p),'fields':fields,'metadata':safe_stat(str(p))})
    return rows[:100]

def redis_cli_info(port, section):
    cli=shutil.which('redis-cli')
    if not cli: return {'status':'UNAVAILABLE'}
    rr=run([cli,'--no-auth-warning','-p',str(port),'INFO',section],5)
    if rr['rc']!=0 or re.search(r'(?i)NOAUTH|WRONGPASS',rr['stdout']+' '+rr['stderr']):
        return {'status':'UNAVAILABLE_NO_UNAUTHENTICATED_METADATA','rc':rr['rc']}
    selected={}
    for line in rr['stdout'].splitlines():
        if not line or line.startswith('#') or ':' not in line: continue
        k,v=line.split(':',1)
        if section=='keyspace' and re.fullmatch(r'db\\d+',k): selected[k]=v[:500]
        elif section=='replication' and k in {'role','connected_slaves','connected_replicas','master_host','master_port','master_link_status'}: selected[k]=v[:500]
        elif section=='persistence' and k in {'loading','rdb_bgsave_in_progress','rdb_last_save_time','rdb_last_bgsave_status','aof_enabled','aof_rewrite_in_progress','aof_last_bgrewrite_status'}: selected[k]=v[:500]
        elif section=='sentinel' and re.match(r'^(sentinel_masters|master\\d+)$',k): selected[k]=v[:500]
    return {'status':'PASS','metadata':selected}

def redis_probe():
    cfg=redis_config_probe()
    out={'hostname':socket.gethostname(),'service_units':service_state(['redis.service','redis-server.service','valkey.service','valkey-sentinel.service','redis-sentinel.service']),
         'packages':packages(['redis','redis-server','valkey']),'listeners':listeners({6379,26379}),'config_evidence':cfg,
         'namespace_key_prefix_metadata':'NOT_SCANNED_TO_AVOID_KEY_NAME_OR_VALUE_DISCLOSURE'}
    dirs=[]; dbfiles=[]; aof=False; rdb=False; ports=set()
    for row in cfg:
        f=row.get('fields',{})
        dirs += f.get('dir',[]); dbfiles += f.get('dbfilename',[])
        if any(v.lower()=='yes' for v in f.get('appendonly',[])): aof=True
        if any(v.strip() not in {'', '""'} for v in f.get('save',[])): rdb=True
        for v in f.get('port',[]):
            try: ports.add(int(v.split()[0]))
            except Exception: pass
    if not ports: ports.add(6379)
    if aof and rdb: mode='BOTH'
    elif aof: mode='AOF'
    elif rdb: mode='RDB'
    elif cfg: mode='NONE_OR_DEFAULT_UNRESOLVED'
    else: mode='UNRESOLVED'
    out['persistence_mode']=mode
    paths=[]
    for d in dirs:
        paths.append(d)
        for fn in dbfiles: paths.append(str(pathlib.Path(d)/fn))
        for row in cfg:
            for ad in row.get('fields',{}).get('appenddirname',[]): paths.append(str(pathlib.Path(d)/ad))
    uniq=[]
    for p in paths:
        if p not in uniq: uniq.append(p)
    persistent=[]
    for p in uniq:
        evidence=safe_du(p,20)
        if evidence is not None: persistent.append(evidence)
    out['persistent_paths']=persistent
    out['recent_write_activity']=[{'path':p,'activity':recent_write(p)} for p in dirs if pathlib.Path(p).exists()]
    out['keyspace_metadata']={str(p):redis_cli_info(p,'keyspace') for p in sorted(ports)}
    out['replication_metadata']={str(p):redis_cli_info(p,'replication') for p in sorted(ports)}
    out['persistence_runtime_metadata']={str(p):redis_cli_info(p,'persistence') for p in sorted(ports)}
    out['sentinel_metadata']={'26379':redis_cli_info(26379,'sentinel')}
    out['protection_observation']=visible_protection(dirs[0] if dirs else None)
    return out

def clientappdb_probe():
    paths=[]
    for p in ['/var/lib/mysql','/var/lib/mariadb','/var/lib/redis','/var/lib/valkey','/var/lib/influxdb','/var/lib/postgresql']:
        x=safe_du(p,20)
        if x: paths.append(x)
    units=service_state(['mariadb.service','mysql.service','mysqld.service','redis.service','redis-server.service','valkey.service','influxdb.service','postgresql.service'])
    return {'hostname':socket.gethostname(),'service_units':units,'datastore_paths':paths,'listeners':listeners({3306,6379,26379,5432,8086})}

if MODE=='mariadb': result=mariadb_probe()
elif MODE=='redis': result=redis_probe()
elif MODE=='clientappdb': result=clientappdb_probe()
else: result={'error':'unsupported mode'}
print(json.dumps(result,sort_keys=True))
'''


def ssh_remote_probe(entry: dict[str, Any], mode: str, timeout: int) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    target = str(entry.get("ssh_target") or "")
    route = route_observation(entry, run_ssh=True)
    batch = route.get("ssh_batch_test", {})
    if batch.get("status") != "PASS":
        return None, route
    ssh = shutil.which("ssh")
    if not ssh:
        route["ssh_batch_test"] = {"status": "BLOCKED", "reason": "SSH_BINARY_UNAVAILABLE"}
        return None, route
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
        "python3", "-", mode,
    ]
    try:
        cp = subprocess.run(cmd, input=REMOTE_PROBE, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        route["remote_probe"] = {"status": "BLOCKED", "reason": "BLOCKED_REMOTE_PROBE_TIMEOUT"}
        return None, route
    if cp.returncode != 0:
        route["remote_probe"] = {"status": "BLOCKED", "reason": p0b.classify_ssh_error(cp.stderr),
                                 "rc": cp.returncode, "stderr": p0b.sanitize_error(cp.stderr)}
        return None, route
    try:
        obj = json.loads(cp.stdout)
    except json.JSONDecodeError:
        route["remote_probe"] = {"status": "BLOCKED", "reason": "BLOCKED_REMOTE_PROBE_INVALID_JSON",
                                 "stdout_prefix": cp.stdout[:1000], "stderr": p0b.sanitize_error(cp.stderr)}
        return None, route
    route["remote_probe"] = {"status": "PASS", "reason": "REMOTE_READ_ONLY_JSON_CAPTURED"}
    return obj, route


def first_package_version(obs: dict[str, Any]) -> str:
    rows = obs.get("packages") or []
    return ";".join(f"{x.get('name')} {x.get('version')}" for x in rows) if rows else "UNRESOLVED"


def active_service_summary(obs: dict[str, Any]) -> str:
    rows = obs.get("service_units") or []
    if not rows:
        return "NOT_OBSERVED"
    return ";".join(f"{x.get('unit')}:{x.get('ActiveState')}/{x.get('SubState')}" for x in rows)


def mariadb18_lane(entry: dict[str, Any], timeout: int) -> dict[str, Any]:
    obs, route = ssh_remote_probe(entry, "mariadb", timeout)
    if obs is None:
        return {"status": "BLOCKED", "blocker": route.get("remote_probe", route.get("ssh_batch_test", {})).get("reason", "BLOCKED"),
                "route": route, "observed": None}
    return {"status": "PASS_READ_ONLY_EVIDENCE_CAPTURED", "blocker": "", "route": route, "observed": obs,
            "owner_context": entry.get("owner_context"), "application_ownership_inferred": False}


def redis6_lane(entry: dict[str, Any], timeout: int) -> dict[str, Any]:
    obs, route = ssh_remote_probe(entry, "redis", timeout)
    if obs is None:
        return {"status": "BLOCKED", "blocker": route.get("remote_probe", route.get("ssh_batch_test", {})).get("reason", "BLOCKED"),
                "route": route, "observed": None}
    return {"status": "PASS_READ_ONLY_EVIDENCE_CAPTURED", "blocker": "", "route": route, "observed": obs,
            "values_scanned": False, "secrets_scanned": False}


def owner_scope_lane(entry: dict[str, Any]) -> dict[str, Any]:
    local = resolved_host_from_local_evidence(entry)
    exact = local.get("exact_host_vm_identity")
    owner = str(entry.get("owner") or "UNRESOLVED_REQUIRES_OWNER_EVIDENCE")
    available = exact != "UNRESOLVED" and owner not in {"", "UNRESOLVED_REQUIRES_OWNER_EVIDENCE"}
    blocker = "" if available else "OWNER_AND_DURABLE_STATE_SCOPE_NOT_ESTABLISHED_FROM_EXISTING_PLATFORM_EVIDENCE"
    return {
        "status": "OWNER_EVIDENCE_AVAILABLE" if available else "BLOCKED_SCOPE_INCOMPLETE_NO_NEW_READER_REQUESTED",
        "host": exact,
        "owner": owner,
        "durable_paths": [],
        "rebuildable_paths": [],
        "durable_size": "UNRESOLVED",
        "rebuild_source": "UNRESOLVED_REQUIRES_OWNER_EVIDENCE",
        "owner_evidence_path_available": available,
        "blocker": blocker,
        "local_platform_evidence": local,
        "guest_connection_attempted": False,
        "security_exception_requested": False,
    }


def clientappdb19_lane(entry: dict[str, Any], timeout: int) -> dict[str, Any]:
    obs, route = ssh_remote_probe(entry, "clientappdb", timeout)
    if obs is None:
        reason = route.get("remote_probe", route.get("ssh_batch_test", {})).get("reason", "BLOCKED")
        return {
            "status": "BLOCKED_SAFE_ROUTE",
            "classification": "UNRESOLVED",
            "data_bearing": "UNRESOLVED",
            "blocker": reason,
            "next_read_only_action": "RECONCILE_EXISTING_PROXYJUMP_SESSION_FORWARDING_PATH_WITHOUT_TRUST_WEAKENING",
            "route": route,
            "owner_context": entry.get("owner_context"),
            "observed": None,
        }
    material = []
    for row in obs.get("datastore_paths", []):
        size = row.get("size_kib")
        if isinstance(size, int) and size > 4:
            material.append(row)
    classification = "DATA_BEARING" if material else "UNRESOLVED"
    data_bearing = "YES" if material else "UNRESOLVED"
    return {
        "status": "PASS_FOCUSED_SAFE_ROUTE_EVIDENCE_CAPTURED",
        "classification": classification,
        "data_bearing": data_bearing,
        "blocker": "" if material else "NO_POSITIVE_DATA_BEARING_PROOF_AND_NO_OWNER_RETIREMENT_AUTHORITY",
        "next_read_only_action": "OWNER_CORROBORATION_REQUIRED_BEFORE_RETIRED_OR_REBUILDABLE_CLASSIFICATION" if not material else "ROUTE_DATA_BEARING_EVIDENCE_TO_CLIENTAPP_AND_DR",
        "route": route,
        "owner_context": entry.get("owner_context"),
        "observed": obs,
    }


def marketdata_influx_lane(entry: dict[str, Any], timeout: int) -> dict[str, Any]:
    authorized = os.environ.get("BITSTREAM_PLATFORMCOMPUTE_MARKETDATA_INFLUX_ADMIN_READ_AUTHORIZED", "").strip().upper() == "YES"
    auth_id = os.environ.get("BITSTREAM_PLATFORMCOMPUTE_MARKETDATA_INFLUX_AUTHORIZATION_ID", "").strip()
    token = os.environ.get("BITSTREAM_PLATFORMCOMPUTE_MARKETDATA_INFLUX_TOKEN", "")
    base = {
        "endpoint": entry.get("endpoint"), "physical_target": entry.get("physical_target"),
        "org": entry.get("org"), "bucket_requested": entry.get("bucket"),
        "token_persisted": False, "token_printed": False, "credential_search_performed": False,
        "authorization_id": auth_id if authorized else "",
    }
    if not authorized:
        return {**base, "status": "BLOCKED_NO_AUTHORIZED_ADMIN_READ", "metadata": None,
                "blocker": "BLOCKED_NO_AUTHORIZED_ADMIN_READ"}
    if not auth_id or not token:
        return {**base, "status": "BLOCKED_AUTHORIZED_CAPABILITY_NOT_EXPLICITLY_SUPPLIED", "metadata": None,
                "blocker": "BLOCKED_AUTHORIZED_CAPABILITY_NOT_EXPLICITLY_SUPPLIED"}
    query = urllib.parse.urlencode({"org": str(entry.get("org")), "name": str(entry.get("bucket"))})
    url = str(entry.get("endpoint")).rstrip("/") + "/api/v2/buckets?" + query
    req = urllib.request.Request(url, headers={"Authorization": "Token " + token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=min(timeout, 15)) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return {**base, "status": "BLOCKED_AUTHORIZED_READ_HTTP_ERROR", "metadata": None,
                "blocker": f"HTTP_{exc.code}"}
    except Exception as exc:
        return {**base, "status": "BLOCKED_AUTHORIZED_READ_FAILED", "metadata": None,
                "blocker": type(exc).__name__}
    buckets = payload.get("buckets") if isinstance(payload, dict) else None
    selected = None
    if isinstance(buckets, list):
        for b in buckets:
            if isinstance(b, dict) and b.get("name") == entry.get("bucket"):
                selected = b; break
    if not selected:
        return {**base, "status": "AUTHORIZED_READ_BUCKET_NOT_FOUND", "metadata": None, "blocker": "BUCKET_NOT_FOUND"}
    rules = []
    for r in selected.get("retentionRules") or []:
        if isinstance(r, dict):
            rules.append({k: r.get(k) for k in ("type", "everySeconds", "shardGroupDurationSeconds")})
    metadata = {"id": selected.get("id"), "name": selected.get("name"), "orgID": selected.get("orgID"), "retentionRules": rules}
    return {**base, "status": "PASS_AUTHORIZED_NON_SECRET_METADATA_CAPTURED", "metadata": metadata, "blocker": ""}


def nexusdb_lane(entry: dict[str, Any]) -> dict[str, Any]:
    route = route_observation(entry, run_ssh=False)
    return {
        "status": "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED",
        "security_decision": entry.get("security_decision"),
        "allowed_identity": entry.get("allowed_identity"),
        "platform_implementation_authorization": "NO",
        "action": "SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED",
        "route_reconciled": "NO",
        "host_key_attested_out_of_band": "NO",
        "collector_identity_pinned": "NO",
        "reader_implemented": "NO",
        "blocker": "PLATFORM_IMPLEMENTATION_AUTHORIZATION_NOT_GRANTED",
        "local_route_observation": route,
        "ssh_connection_attempted": False,
        "known_hosts_mutation_performed": False,
        "reader_implementation_attempted": False,
    }


def mariadb_summary(lane: dict[str, Any]) -> dict[str, str]:
    obs = lane.get("observed") or {}
    runtime = obs.get("runtime_query") or {}
    schemas = obs.get("schema_inventory") or []
    datastore = obs.get("datastore") or {}
    protection = obs.get("protection_observation") or {}
    repl = obs.get("replication") or {}
    tools = protection.get("tools") or []
    artifact = protection.get("artifact_locations") or []
    if artifact:
        protection_seen = "VISIBLE_TOOLING_OR_ARTIFACT_LOCATION_NOT_ACCEPTANCE"
    elif tools:
        protection_seen = "VISIBLE_TOOLING_ONLY_NOT_ACCEPTANCE"
    else:
        protection_seen = "NOT_OBSERVED" if lane.get("status", "").startswith("PASS") else "UNRESOLVED"
    return {
        "MARIADB18_OBSERVED": "YES" if lane.get("status", "").startswith("PASS") else "NO",
        "MARIADB18_BLOCKER": safe_scalar(lane.get("blocker")),
        "MARIADB18_DATABASE_SERVICE": active_service_summary(obs),
        "MARIADB18_DATABASE_VERSION": safe_scalar(runtime.get("version") or first_package_version(obs)),
        "MARIADB18_DATADIR": safe_scalar(obs.get("datadir") or runtime.get("datadir") or "UNRESOLVED"),
        "MARIADB18_DATASTORE_SIZE": (f"{datastore.get('size_kib')} KiB" if datastore.get("size_kib") is not None else "UNRESOLVED"),
        "MARIADB18_SCHEMA_COUNT": str(len(schemas)) if lane.get("status", "").startswith("PASS") else "UNRESOLVED",
        "MARIADB18_BINLOG_STATUS": safe_scalar(runtime.get("log_bin") or "UNRESOLVED"),
        "MARIADB18_REPLICATION_OBSERVED": "YES" if repl.get("rows_present") else ("NO_OR_UNAVAILABLE" if lane.get("status", "").startswith("PASS") else "UNRESOLVED"),
        "MARIADB18_PROTECTION_OBSERVED": protection_seen,
    }


def redis_summary(lane: dict[str, Any]) -> dict[str, str]:
    obs = lane.get("observed") or {}
    paths = obs.get("persistent_paths") or []
    total = sum(x.get("size_kib") or 0 for x in paths if isinstance(x, dict))
    keyspace = obs.get("keyspace_metadata") or {}
    replication = {"replication": obs.get("replication_metadata"), "sentinel": obs.get("sentinel_metadata")}
    protection = obs.get("protection_observation") or {}
    return {
        "REDISSERVER6_OBSERVED": "YES" if lane.get("status", "").startswith("PASS") else "NO",
        "REDISSERVER6_BLOCKER": safe_scalar(lane.get("blocker")),
        "REDIS_PRODUCT_VERSION": first_package_version(obs),
        "REDIS_SERVICE_STATE": active_service_summary(obs),
        "REDIS_PERSISTENCE_MODE": safe_scalar(obs.get("persistence_mode") or "UNRESOLVED"),
        "REDIS_PERSISTENT_PATHS": safe_scalar([x.get("path") for x in paths if isinstance(x, dict)]),
        "REDIS_PERSISTENT_SIZE": f"{total} KiB" if paths else "UNRESOLVED",
        "REDIS_KEYSPACE_METADATA": safe_scalar(keyspace),
        "REDIS_REPLICATION_SENTINEL": safe_scalar(replication),
        "REDIS_PROTECTION_OBSERVED": ("VISIBLE_TOOLING_OR_ARTIFACT_LOCATION_NOT_ACCEPTANCE" if protection.get("artifact_locations") else ("VISIBLE_TOOLING_ONLY_NOT_ACCEPTANCE" if protection.get("tools") else ("NOT_OBSERVED" if lane.get("status", "").startswith("PASS") else "UNRESOLVED"))),
    }


def owner_summary(prefix: str, lane: dict[str, Any]) -> dict[str, str]:
    return {
        f"{prefix}_HOST": safe_scalar(lane.get("host")),
        f"{prefix}_OWNER": safe_scalar(lane.get("owner")),
        f"{prefix}_DURABLE_PATHS": safe_scalar(lane.get("durable_paths")),
        f"{prefix}_REBUILDABLE_PATHS": safe_scalar(lane.get("rebuildable_paths")),
        f"{prefix}_DURABLE_SIZE": safe_scalar(lane.get("durable_size")),
        f"{prefix}_REBUILD_SOURCE": safe_scalar(lane.get("rebuild_source")),
        f"{prefix}_OWNER_EVIDENCE_PATH_AVAILABLE": "YES" if lane.get("owner_evidence_path_available") else "NO",
        f"{prefix}_BLOCKER": safe_scalar(lane.get("blocker")),
    }


def build_summary(results: dict[str, Any]) -> dict[str, str]:
    summary: dict[str, str] = {}
    summary.update(mariadb_summary(results["mariadb18"]))
    summary.update(redis_summary(results["redisserver6"]))
    summary.update(owner_summary("ETHSERVICE", results["ethservice"]))
    summary.update(owner_summary("NODESERVER", results["nodeserver"]))
    c = results["clientappdb19"]
    summary.update({
        "CLIENTAPPDB19_CLASSIFICATION": safe_scalar(c.get("classification")),
        "CLIENTAPPDB19_DATA_BEARING": safe_scalar(c.get("data_bearing")),
        "CLIENTAPPDB19_BLOCKER": safe_scalar(c.get("blocker")),
        "CLIENTAPPDB19_NEXT_READ_ONLY_ACTION": safe_scalar(c.get("next_read_only_action")),
    })
    m = results["marketdata_influx"]
    metadata = m.get("metadata") or {}
    rules = metadata.get("retentionRules") or []
    summary.update({
        "MARKETDATA_INFLUX_RETENTION_METADATA": "PASS" if m.get("status") == "PASS_AUTHORIZED_NON_SECRET_METADATA_CAPTURED" else safe_scalar(m.get("status")),
        "MARKETDATA_INFLUX_RETENTION_SECONDS": safe_scalar([r.get("everySeconds") for r in rules]) if rules else "",
        "MARKETDATA_INFLUX_RETENTION_TYPE": safe_scalar([r.get("type") for r in rules]) if rules else "",
        "MARKETDATA_INFLUX_RETENTION_BLOCKER": safe_scalar(m.get("blocker")),
    })
    n = results["nexusdb"]
    summary.update({
        "NEXUSDB_ACTION": safe_scalar(n.get("action")),
        "NEXUSDB_PLATFORM_IMPLEMENTATION_AUTHORIZATION": safe_scalar(n.get("platform_implementation_authorization")),
        "NEXUSDB_ROUTE_RECONCILED": safe_scalar(n.get("route_reconciled")),
        "NEXUSDB_HOST_KEY_ATTESTED_OUT_OF_BAND": safe_scalar(n.get("host_key_attested_out_of_band")),
        "NEXUSDB_COLLECTOR_IDENTITY_PINNED": safe_scalar(n.get("collector_identity_pinned")),
        "NEXUSDB_READER_IMPLEMENTED": safe_scalar(n.get("reader_implemented")),
        "NEXUSDB_BLOCKER": safe_scalar(n.get("blocker")),
        "PRODUCTION_MUTATION": "NONE",
        "SSH_TRUST_WEAKENING": "NONE",
        "ACCOUNT_MUTATION": "NONE",
        "SERVICE_RESTART": "NONE",
        "NETWORK_STORAGE_MUTATION": "NONE",
        "BACKUP_RESTORE_EXECUTION": "NONE",
        "RPO_RETENTION_ASSIGNMENT": "NONE",
    })
    return summary


def write_summary_env(path: pathlib.Path, summary: dict[str, str]) -> None:
    path.write_text("".join(f"{k}={safe_scalar(v)}\n" for k, v in summary.items()), encoding="utf-8")


def write_summary_csv(path: pathlib.Path, summary: dict[str, str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["field", "value"])
        for k, v in summary.items(): w.writerow([k, v])


def write_report(path: pathlib.Path, run_id: str, results: dict[str, Any], summary: dict[str, str]) -> None:
    lines = [
        "# Platform & Compute Phase-0C Focused Infrastructure Completion Report", "",
        f"- Contract: `{CONTRACT}`", f"- Run ID: `{run_id}`", f"- Generated UTC: `{utc_now()}`",
        f"- Authority: `{AUTHORITY}`", f"- Mutation policy: `{MUTATION_POLICY}`", "",
        "## Scope", "", "This run is limited to the CURRENT DR focused completion request. It does not repeat broad Phase-0/Phase-0B discovery.", "",
        "## Lane disposition", "",
        f"- MariaDB18: `{results['mariadb18'].get('status')}` / blocker `{results['mariadb18'].get('blocker')}`",
        f"- RedisServer6: `{results['redisserver6'].get('status')}` / blocker `{results['redisserver6'].get('blocker')}`",
        f"- ETHService: `{results['ethservice'].get('status')}` / blocker `{results['ethservice'].get('blocker')}`",
        f"- NodeServer: `{results['nodeserver'].get('status')}` / blocker `{results['nodeserver'].get('blocker')}`",
        f"- ClientAppDB19: `{results['clientappdb19'].get('classification')}` / blocker `{results['clientappdb19'].get('blocker')}`",
        f"- MarketData Influx retention: `{results['marketdata_influx'].get('status')}`",
        f"- NexusDB: `{results['nexusdb'].get('action')}` / reader implemented `NO`", "",
        "## Requested summary", "", "```text",
    ]
    lines.extend(f"{k}={v}" for k, v in summary.items())
    lines += ["```", "", "## Safety / authority boundary", "",
              "No root fallback, sudo, TOFU, host-key enrollment, known_hosts mutation, account mutation, service restart/reboot, network/storage mutation, backup/restore execution, retention change, RPO assignment, durability-class assignment, Phase-0 auto-acceptance, or trading-authority change was performed by this collector.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_handoff(path: pathlib.Path, run_id: str, results: dict[str, Any], summary: dict[str, str]) -> None:
    lines = [
        "# BitStream Platform & Compute → Disaster Recovery / Data Protection",
        "## Phase-0C Focused Infrastructure Completion Return", "",
        f"**Run ID:** `{run_id}`  ", f"**Contract:** `{CONTRACT}`  ",
        f"**Authority:** `{AUTHORITY}`  ", "**Production mutation:** `NONE`", "",
        "Platform & Compute completed the bounded Phase-0C read-only pass requested in the CURRENT 2026-09-05 DR completion request. Broad Phase-0/Phase-0B collection was not repeated.", "",
        "## Result summary", "", "```text",
    ]
    for k, v in summary.items(): lines.append(f"{k}={v}")
    lines += ["```", "", "## Authority notes", "",
              "- MariaDB schema/database names are evidence only and were not used to infer application ownership.",
              "- Redis values, credentials, private keys, authentication secrets, process environments, and key names were not scanned or emitted.",
              "- ETHService and NodeServer received no new guest reader or Security exception; only existing local Platform route/identity evidence was consulted.",
              "- ClientAppDB19 is not classified as retired/rebuildable merely from owner description or inaccessibility; if the safe route failed it remains unresolved.",
              "- MarketData Influx retention was queried only if an already-authorized capability was explicitly supplied; no token is persisted in evidence.",
              "- NexusDB reader implementation was not attempted because Security approved the design but Platform implementation authorization remains NO.", "",
              "## Requested DR disposition", "",
              "Admit the immutable Phase-0C packet as focused infrastructure evidence, retain every explicit blocker as unresolved, and route remaining owner/Security authorization decisions to the responsible departments without widening Platform authority.", "",
              "**Platform & Compute disposition:** `PHASE0C_FOCUSED_COMPLETION_RETURNED_WITH_EXPLICIT_UNRESOLVED_ITEMS_AS_OBSERVED`", ""]
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
    ap = argparse.ArgumentParser(description="Collect Platform & Compute Phase-0C focused read-only completion evidence.")
    ap.add_argument("--config", required=True, type=pathlib.Path)
    ap.add_argument("--output-root", required=True, type=pathlib.Path)
    ap.add_argument("--timeout", type=int, default=90)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"platformcompute-phase0c-readonly-{stamp}"
    run_dir = args.output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    results = {
        "mariadb18": mariadb18_lane(cfg["mariadb18"], args.timeout),
        "redisserver6": redis6_lane(cfg["redisserver6"], args.timeout),
        "ethservice": owner_scope_lane(cfg["ethservice"]),
        "nodeserver": owner_scope_lane(cfg["nodeserver"]),
        "clientappdb19": clientappdb19_lane(cfg["clientappdb19"], args.timeout),
        "marketdata_influx": marketdata_influx_lane(cfg["marketdata_influx"], args.timeout),
        "nexusdb": nexusdb_lane(cfg["nexusdb"]),
    }

    filenames = {
        "mariadb18": "mariadb18_evidence.json",
        "redisserver6": "redisserver6_evidence.json",
        "ethservice": "ethservice_owner_scope.json",
        "nodeserver": "nodeserver_owner_scope.json",
        "clientappdb19": "clientappdb19_classification.json",
        "marketdata_influx": "marketdata_influx_retention.json",
        "nexusdb": "nexusdb_security_boundary.json",
    }
    for key, name in filenames.items(): write_json(run_dir / name, results[key])
    write_json(run_dir / "evidence.json", {"contract": CONTRACT, "run_id": run_id, "generated_at_utc": utc_now(),
                                           "authority": AUTHORITY, "mutation_policy": MUTATION_POLICY,
                                           "results": results, "acceptance": "EVIDENCE_ONLY_NO_AUTO_ACCEPTANCE"})
    summary = build_summary(results)
    write_summary_env(run_dir / "summary.env", summary)
    write_summary_csv(run_dir / "summary.csv", summary)
    write_report(run_dir / "REPORT.md", run_id, results, summary)
    write_handoff(run_dir / "HANDOFF_TO_DISASTER_RECOVERY.md", run_id, results, summary)

    receipt = {
        "contract": CONTRACT, "run_id": run_id, "generated_at_utc": utc_now(),
        "collector_host": socket.gethostname(), "collector_user": os.environ.get("USER") or os.environ.get("LOGNAME"),
        "authority": AUTHORITY, "mutation_policy": MUTATION_POLICY,
        "safety": {
            "root_fallback": "NONE", "sudo_used": False, "ssh_host_key_verification": "STRICT",
            "tofu": "NONE", "host_key_enrollment": "NONE", "known_hosts_mutation": "NONE",
            "account_mutation": "NONE", "service_restart_reboot": "NONE", "network_storage_mutation": "NONE",
            "backup_restore_execution": "NONE", "retention_change": "NONE", "rpo_assignment": "NONE",
            "durability_class_assignment": "NONE", "phase0_auto_acceptance": "NONE", "trading_authority_change": "NONE"
        },
        "marketdata_influx": {"credential_search_performed": False, "token_persisted": False, "token_printed": False},
        "nexusdb": {"reader_implementation_attempted": False, "platform_implementation_authorized": False},
    }
    write_json(run_dir / "receipt.json", receipt)
    manifest = make_manifest(run_dir)
    bundle = make_bundle(run_dir)
    bundle_sha = sha256_file(bundle)
    sha_path = bundle.with_suffix(bundle.suffix + ".sha256")
    sha_path.write_text(f"{bundle_sha}  {bundle.name}\n", encoding="utf-8")

    print("============================================================")
    print(" PLATFORM & COMPUTE — PHASE-0C FOCUSED COMPLETION EVIDENCE")
    print("============================================================")
    print(f"CONTRACT={CONTRACT}")
    print(f"RUN_ID={run_id}")
    for k in ["MARIADB18_OBSERVED","MARIADB18_BLOCKER","REDISSERVER6_OBSERVED","REDISSERVER6_BLOCKER",
              "ETHSERVICE_OWNER","NODESERVER_OWNER","CLIENTAPPDB19_CLASSIFICATION","CLIENTAPPDB19_BLOCKER",
              "MARKETDATA_INFLUX_RETENTION_METADATA","NEXUSDB_ACTION","NEXUSDB_READER_IMPLEMENTED"]:
        print(f"{k}={summary.get(k,'')}")
    print(f"REPORT={run_dir / 'REPORT.md'}")
    print(f"HANDOFF={run_dir / 'HANDOFF_TO_DISASTER_RECOVERY.md'}")
    print(f"SUMMARY={run_dir / 'summary.env'}")
    print(f"MANIFEST={manifest}")
    print(f"BUNDLE={bundle}")
    print(f"BUNDLE_SHA256={bundle_sha}")
    print(f"AUTHORITY={AUTHORITY}")
    print("PRODUCTION_MUTATION=NONE")
    print("PASS: Phase-0C focused completion finished. Unsupported facts remain explicit; no authority was widened.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
