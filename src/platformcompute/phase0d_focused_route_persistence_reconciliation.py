from __future__ import annotations
import argparse, csv, datetime as dt, hashlib, json, os, pathlib, shutil, socket, subprocess, sys, zipfile
from typing import Any

HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import phase0b_infrastructure_reconciliation as p0b
import phase0c_focused_infrastructure_completion as p0c

CONTRACT="bitstream-platformcompute-phase0d-focused-route-persistence-reconciliation-v1"
AUTHORITY="PLATFORM_INFRASTRUCTURE_FACTS_ONLY"
MUTATION_POLICY="READ_ONLY_NO_MUTATION"

def utcnow(): return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
def sha256_file(p:pathlib.Path):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def write_json(p,obj): p.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def safe(v):
    if v is None:return ''
    if isinstance(v,(dict,list)): return json.dumps(v,sort_keys=True,separators=(',',':'))
    return str(v).replace('\n',' ').replace('\r',' ')

def run(cmd,timeout=30,input_text=None):
    try:
        cp=subprocess.run(cmd,input=input_text,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        return {'rc':cp.returncode,'stdout':cp.stdout,'stderr':p0b.sanitize_error(cp.stderr)}
    except subprocess.TimeoutExpired as e:
        return {'rc':124,'stdout':(e.stdout or '') if isinstance(e.stdout,str) else '', 'stderr':'TIMEOUT'}

def load_config(p):
    cfg=json.loads(p.read_text(encoding='utf-8'))
    if cfg.get('contract')!=CONTRACT: raise ValueError('Phase-0D contract mismatch')
    if cfg.get('nexusdb',{}).get('platform_implementation_authorized') is not False: raise ValueError('NexusDB implementation must remain unauthorized')
    return cfg

def baseline_status(repo_root,cfg):
    b=cfg['baseline']; p=repo_root/b['relative_path']; out={'expected_run_id':b['run_id'],'expected_sha256':b['sha256'],'path':str(p),'present':p.is_file()}
    if p.is_file():
        out['observed_sha256']=sha256_file(p); out['verified']=out['observed_sha256']==b['sha256']
    else: out['verified']=False
    return out

HYPERVISOR_PROBE=r"""
import json,subprocess,socket,sys,os

def run(cmd,t=12):
    try:
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=t,check=False)
        return {'rc':p.returncode,'stdout':p.stdout.strip(),'stderr':p.stderr.strip()}
    except Exception as e:return {'rc':124,'stdout':'','stderr':type(e).__name__}
def tcp(ip,port,timeout):
    s=socket.socket();s.settimeout(timeout)
    try:s.connect((ip,port));return {'status':'OPEN'}
    except ConnectionRefusedError:return {'status':'REFUSED'}
    except socket.timeout:return {'status':'TIMEOUT'}
    except OSError as e:return {'status':'ERROR','error':str(e)}
    finally:s.close()
req=json.loads(sys.stdin.read()); out={'hostname':socket.gethostname(),'virsh_available':bool(shutil.which('virsh')) if False else None,'vms':{}}
for item in req['targets']:
    name=item['vm_name']; ip=item.get('expected_ip',''); v={'vm_name':name,'expected_ip':ip}
    v['domstate']=run(['virsh','domstate',name]); v['dominfo']=run(['virsh','dominfo',name]); v['domiflist']=run(['virsh','domiflist',name]); v['domifaddr']=run(['virsh','domifaddr',name,'--source','arp'])
    v['domblklist']=run(['virsh','domblklist',name,'--details'])
    v['tcp']={str(port):tcp(ip,int(port),float(req.get('tcp_timeout',3))) for port in req.get('guest_ports',[22,69])} if ip else {}
    out['vms'][name]=v
print(json.dumps(out,sort_keys=True))
"""

def hypervisor_probe(cfg):
    ssh=shutil.which('ssh')
    if not ssh:return {'status':'BLOCKED','blocker':'SSH_BINARY_UNAVAILABLE'}
    target=cfg['gateway']['ssh_target']
    req={'guest_ports':cfg['gateway'].get('guest_ports',[22,69]),'tcp_timeout':cfg['limits'].get('tcp_timeout_seconds',3),'targets':[]}
    for g in cfg['guest_targets']: req['targets'].append({'vm_name':g['ssh_target'],'expected_ip':g['expected_ip']})
    for o in cfg['owner_targets'].values(): req['targets'].append(o)
    cmd=[ssh,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ConnectionAttempts=1','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','NumberOfPasswordPrompts=0',target,'python3','-c',HYPERVISOR_PROBE]
    r=run(cmd,cfg['limits'].get('gateway_timeout_seconds',60),json.dumps(req))
    if r['rc']!=0:return {'status':'BLOCKED','blocker':p0b.classify_ssh_error(r['stderr']),'ssh':r}
    try: obj=json.loads(r['stdout'])
    except Exception:return {'status':'BLOCKED','blocker':'HYPERVISOR_PROBE_INVALID_JSON','stdout_prefix':r['stdout'][:1000],'stderr':r['stderr']}
    return {'status':'PASS','blocker':'','observed':obj}

def known(ip,port): return p0b.known_host_match_count(ip,int(port))
def explicit_guest_probe(g,port,timeout):
    ip=g['expected_ip']; user=g.get('existing_user','root'); jump=g.get('gateway','hv') or 'hv'; mode=g['mode']
    route={'expected_ip':ip,'port':int(port),'proxyjump':jump,'known_host_preapproval':known(ip,port),'host_key_enrollment_performed':False,'trust_mutation_performed':False}
    if route['known_host_preapproval']<1:return None,{**route,'status':'BLOCKED','blocker':'BLOCKED_HOST_KEY_NOT_PREAPPROVED'}
    ssh=shutil.which('ssh')
    if not ssh:return None,{**route,'status':'BLOCKED','blocker':'SSH_BINARY_UNAVAILABLE'}
    dest=f'{user}@{ip}'
    cmd=[ssh,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ConnectionAttempts=1','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','NumberOfPasswordPrompts=0','-o',f'ProxyJump={jump}','-p',str(port),dest,'python3','-',mode]
    r=run(cmd,timeout,p0c.REMOTE_PROBE)
    if r['rc']!=0:return None,{**route,'status':'BLOCKED','blocker':p0b.classify_ssh_error(r['stderr']),'ssh':r}
    try: obs=json.loads(r['stdout'])
    except Exception:return None,{**route,'status':'BLOCKED','blocker':'REMOTE_PROBE_INVALID_JSON','stdout_prefix':r['stdout'][:1000]}
    return obs,{**route,'status':'PASS','blocker':''}

def guest_lane(g,hv,timeout):
    vm=(hv.get('observed') or {}).get('vms',{}).get(g['ssh_target'],{})
    tcp=vm.get('tcp',{})
    cfgport=int(g.get('configured_port',69)); candidates=[]
    for p in [cfgport,22,69]:
        if p not in candidates:candidates.append(p)
    attempts=[]; obs=None; chosen=None
    for p in candidates:
        st=(tcp.get(str(p)) or {}).get('status','UNRESOLVED'); pre=known(g['expected_ip'],p)
        item={'port':p,'hypervisor_tcp_status':st,'collector_known_host_preapproval':pre,'ssh_attempted':False}
        if st=='OPEN' and pre>0:
            item['ssh_attempted']=True; candidate,route=explicit_guest_probe({**g,'gateway':'hv'},p,timeout); item['route']=route
            if candidate is not None: obs=candidate;chosen=p;attempts.append(item);break
        attempts.append(item)
    if obs is not None:
        status='PASS_READ_ONLY_EVIDENCE_CAPTURED'; blocker=''
    else:
        open_ports=[int(p) for p,s in tcp.items() if isinstance(s,dict) and s.get('status')=='OPEN']
        approved_open=[p for p in open_ports if known(g['expected_ip'],p)>0]
        if not open_ports:blocker='BLOCKED_NO_OPEN_GUEST_SSH_PORT_FROM_HYPERVISOR'
        elif not approved_open:blocker='BLOCKED_REACHABLE_PORT_HAS_NO_PREAPPROVED_HOST_KEY'
        else:blocker='BLOCKED_STRICT_SSH_FAILED_ON_PREAPPROVED_REACHABLE_PORT'
        status='BLOCKED'
    out={'status':status,'blocker':blocker,'target':g,'hypervisor_vm':vm,'candidate_attempts':attempts,'chosen_port':chosen,'observed':obs,'application_ownership_inferred':False}
    if g['key']=='clientappdb19':
        material=[]
        if obs:
            for row in obs.get('datastore_paths',[]):
                if isinstance(row,dict) and isinstance(row.get('size_kib'),int) and row['size_kib']>4:material.append(row)
        out['classification']='DATA_BEARING' if material else 'UNRESOLVED'; out['data_bearing']='YES' if material else 'UNRESOLVED'
        if not material and not blocker: out['blocker']='NO_POSITIVE_DATA_BEARING_PROOF_AND_NO_OWNER_RETIREMENT_AUTHORITY'
    return out

def parse_block_sources(text):
    rows=[]
    for line in text.splitlines():
        parts=line.split()
        if len(parts)>=4 and parts[0] in {'file','block'}:
            rows.append({'type':parts[0],'device':parts[1],'target':parts[2],'source':' '.join(parts[3:])})
    return rows

def owner_lane(key,entry,hv):
    vm=(hv.get('observed') or {}).get('vms',{}).get(entry['vm_name'],{})
    state=(vm.get('domstate') or {}).get('stdout','UNRESOLVED'); blocks=parse_block_sources((vm.get('domblklist') or {}).get('stdout',''))
    return {'status':'PLATFORM_VM_SCOPE_REFINED_OWNER_STILL_REQUIRED','host':entry.get('expected_ip'),'vm_name':entry['vm_name'],'vm_state':state,'physical_block_sources':blocks,'owner':'UNRESOLVED_REQUIRES_OWNER_EVIDENCE','durable_paths':[],'rebuildable_paths':[],'durable_size':'UNRESOLVED_GUEST_INTERNAL_STATE','rebuild_source':'VM_BLOCK_SOURCE_IDENTIFIED_BUT_APPLICATION_REBUILD_SOURCE_UNRESOLVED' if blocks else 'UNRESOLVED_REQUIRES_OWNER_EVIDENCE','owner_evidence_path_available':False,'blocker':'APPLICATION_OWNER_AND_GUEST_DURABLE_PATH_SCOPE_REMAINS_REQUIRED','guest_connection_attempted':False,'security_exception_requested':False}

def summary(results):
    m=results['mariadb18']; r=results['redisserver6']; c=results['clientappdb19']; e=results['ethservice']; n=results['nodeserver']
    mo=m.get('observed') or {}; ro=r.get('observed') or {}
    ms=p0c.mariadb_summary({'status':m['status'],'blocker':m['blocker'],'observed':mo})
    rs=p0c.redis_summary({'status':r['status'],'blocker':r['blocker'],'observed':ro})
    out={**ms,**rs,
      'ETHSERVICE_HOST':safe(e.get('host')),'ETHSERVICE_OWNER':safe(e.get('owner')),'ETHSERVICE_DURABLE_PATHS':safe(e.get('durable_paths')),'ETHSERVICE_OWNER_EVIDENCE_PATH_AVAILABLE':'YES' if e.get('owner_evidence_path_available') else 'NO',
      'NODESERVER_HOST':safe(n.get('host')),'NODESERVER_OWNER':safe(n.get('owner')),'NODESERVER_DURABLE_PATHS':safe(n.get('durable_paths')),'NODESERVER_OWNER_EVIDENCE_PATH_AVAILABLE':'YES' if n.get('owner_evidence_path_available') else 'NO',
      'CLIENTAPPDB19_CLASSIFICATION':safe(c.get('classification')),'CLIENTAPPDB19_DATA_BEARING':safe(c.get('data_bearing')),'CLIENTAPPDB19_BLOCKER':safe(c.get('blocker')),
      'MARKETDATA_INFLUX_RETENTION_METADATA':safe(results['marketdata_influx'].get('status')),'MARKETDATA_INFLUX_RETENTION_SECONDS':'',
      'NEXUSDB_ACTION':safe(results['nexusdb'].get('action')),'NEXUSDB_PLATFORM_IMPLEMENTATION_AUTHORIZATION':'NO','NEXUSDB_READER_IMPLEMENTED':'NO',
      'PRODUCTION_MUTATION':'NONE','SSH_TRUST_WEAKENING':'NONE','ACCOUNT_MUTATION':'NONE','SERVICE_RESTART':'NONE','NETWORK_STORAGE_MUTATION':'NONE','BACKUP_RESTORE_EXECUTION':'NONE','RPO_RETENTION_ASSIGNMENT':'NONE'}
    return out

def manifest(run_dir):
    p=run_dir/'MANIFEST.sha256'; rows=[]
    for f in sorted(x for x in run_dir.rglob('*') if x.is_file() and x.name!='MANIFEST.sha256'): rows.append(f'{sha256_file(f)}  {f.relative_to(run_dir).as_posix()}')
    p.write_text('\n'.join(rows)+'\n',encoding='utf-8'); return p

def bundle(run_dir):
    z=run_dir.parent/f'{run_dir.name}.zip'
    with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as out:
        for f in sorted(x for x in run_dir.rglob('*') if x.is_file()): out.write(f,f'{run_dir.name}/{f.relative_to(run_dir).as_posix()}')
    pathlib.Path(str(z)+'.sha256').write_text(f'{sha256_file(z)}  {z.name}\n',encoding='utf-8'); return z

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument('--config',type=pathlib.Path,required=True); ap.add_argument('--output-root',type=pathlib.Path,required=True); ap.add_argument('--repo-root',type=pathlib.Path,required=True); args=ap.parse_args(argv)
    cfg=load_config(args.config); stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'); rid=f'platformcompute-phase0d-readonly-{stamp}'; rd=args.output_root/rid; rd.mkdir(parents=True,exist_ok=False)
    base=baseline_status(args.repo_root,cfg); hv=hypervisor_probe(cfg)
    results={'baseline':base,'gateway':hv}
    for g in cfg['guest_targets']: results[g['key']]=guest_lane(g,hv,cfg['limits'].get('guest_timeout_seconds',180))
    results['ethservice']=owner_lane('ethservice',cfg['owner_targets']['ethservice'],hv); results['nodeserver']=owner_lane('nodeserver',cfg['owner_targets']['nodeserver'],hv)
    results['marketdata_influx']=p0c.marketdata_influx_lane(cfg['marketdata_influx'],30); results['nexusdb']=p0c.nexusdb_lane(cfg['nexusdb'])
    s=summary(results)
    write_json(rd/'gateway_h1_route_inventory.json',hv); write_json(rd/'mariadb18_route_persistence.json',results['mariadb18']); write_json(rd/'redisserver6_route_persistence.json',results['redisserver6']); write_json(rd/'clientappdb19_route_classification.json',results['clientappdb19']); write_json(rd/'ethservice_platform_vm_scope.json',results['ethservice']); write_json(rd/'nodeserver_platform_vm_scope.json',results['nodeserver']); write_json(rd/'marketdata_influx_retention.json',results['marketdata_influx']); write_json(rd/'nexusdb_security_boundary.json',results['nexusdb']); write_json(rd/'evidence.json',results)
    (rd/'summary.env').write_text(''.join(f'{k}={safe(v)}\n' for k,v in s.items()),encoding='utf-8')
    with (rd/'summary.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['field','value']);w.writerows(s.items())
    report=['# Platform & Compute Phase-0D Focused Route / Persistence Reconciliation','',f'- Contract: `{CONTRACT}`',f'- Run ID: `{rid}`',f'- Generated UTC: `{utcnow()}`',f'- Authority: `{AUTHORITY}`','- Production mutation: `NONE`','', '## Purpose','','Phase-0D reconciles the Phase-0C connection timeouts at the H1 gateway/guest-route layer. It does not repeat broad discovery and does not alter trust, routing, VM state, services, storage, accounts, backup/restore, retention, RPO, or NexusDB reader state.','', '## Disposition','',f"- H1 gateway observation: `{hv.get('status')}` / `{hv.get('blocker','')}`",f"- MariaDB18: `{results['mariadb18']['status']}` / `{results['mariadb18']['blocker']}`",f"- RedisServer6: `{results['redisserver6']['status']}` / `{results['redisserver6']['blocker']}`",f"- ClientAppDB19: `{results['clientappdb19'].get('classification')}` / `{results['clientappdb19']['blocker']}`",f"- ETHService: VM scope refined; owner remains `{results['ethservice']['owner']}`",f"- NodeServer: VM scope refined; owner remains `{results['nodeserver']['owner']}`",f"- MarketData retention: `{results['marketdata_influx'].get('status')}`",f"- NexusDB: `{results['nexusdb'].get('action')}` / reader implemented `NO`",'', '## Summary','', '```text']+[f'{k}={v}' for k,v in s.items()]+['```','','## Safety','','Only read-only SSH/virsh/socket metadata probes were attempted. Guest SSH is attempted only for a hypervisor-reachable port whose exact host key is already pre-approved on the collector. No key enrollment, TOFU, route mutation, VM lifecycle action, offline disk mounting, or privilege escalation is permitted.','']
    (rd/'REPORT.md').write_text('\n'.join(report),encoding='utf-8')
    handoff=['# BitStream Platform & Compute → Disaster Recovery / Data Protection','## Phase-0D Focused Route / Persistence Reconciliation Return','',f'**Run ID:** `{rid}`  ',f'**Contract:** `{CONTRACT}`  ','**Production mutation:** `NONE`','', 'Phase-0D was designed specifically to advance the three Phase-0C connection-timeout lanes without repeating broad collection. It observes the existing H1 gateway and VM topology first, then attempts guest evidence only on an already reachable and already trusted exact port.','', '## Result summary','', '```text']+[f'{k}={v}' for k,v in s.items()]+['```','','## DR interpretation rules','','- Hypervisor TCP reachability distinguishes guest-port/path failure from workstation-to-private-network routing artifacts.','- A reachable port without a pre-approved collector host key remains blocked; this collector never enrolls a key.','- VM state/block-device metadata for ETHService and NodeServer refines Platform scope but does not establish application ownership or guest durable paths.','- ClientAppDB19 remains UNRESOLVED unless positive data-bearing evidence is captured; powered-off/inaccessible state alone is never retirement authority.','- MarketData administrative metadata and NexusDB implementation remain under their prior authority boundaries.','', '**Disposition:** `PHASE0D_ROUTE_RECONCILIATION_COMPLETE_WITH_EXPLICIT_BLOCKERS_OR_PERSISTENCE_EVIDENCE_AS_OBSERVED`','']
    (rd/'HANDOFF_TO_DISASTER_RECOVERY.md').write_text('\n'.join(handoff),encoding='utf-8')
    receipt={'contract':CONTRACT,'run_id':rid,'generated_at_utc':utcnow(),'authority':AUTHORITY,'mutation_policy':MUTATION_POLICY,'baseline':base,'safety':{'sudo_used':False,'root_fallback':'NONE','host_key_enrollment':'NONE','tofu':'NONE','known_hosts_mutation':'NONE','route_mutation':'NONE','vm_lifecycle_mutation':'NONE','service_restart':'NONE','network_storage_mutation':'NONE','offline_disk_mount':'NONE','account_mutation':'NONE','backup_restore_execution':'NONE','retention_rpo_assignment':'NONE','nexusdb_reader_implementation':'NONE'}}
    write_json(rd/'receipt.json',receipt); manifest(rd); z=bundle(rd)
    print(f'CONTRACT={CONTRACT}');print(f'RUN_ID={rid}');print(f'H1_GATEWAY={hv.get("status")}');print(f'MARIADB18={results["mariadb18"]["status"]}:{results["mariadb18"]["blocker"]}');print(f'REDISSERVER6={results["redisserver6"]["status"]}:{results["redisserver6"]["blocker"]}');print(f'CLIENTAPPDB19={results["clientappdb19"].get("classification")}:{results["clientappdb19"]["blocker"]}');print(f'REPORT={rd/"REPORT.md"}');print(f'HANDOFF={rd/"HANDOFF_TO_DISASTER_RECOVERY.md"}');print(f'MANIFEST={rd/"MANIFEST.sha256"}');print(f'BUNDLE={z}');print(f'BUNDLE_SHA256={sha256_file(z)}');print('AUTHORITY=PLATFORM_INFRASTRUCTURE_FACTS_ONLY');print('PRODUCTION_MUTATION=NONE');print('PASS: Phase-0D focused route/persistence reconciliation completed.')
    return 0
if __name__=='__main__': raise SystemExit(main())
