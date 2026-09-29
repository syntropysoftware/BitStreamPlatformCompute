#!/usr/bin/env python3
"""Read-only Phase-0J four-defect closure evidence capture."""
from __future__ import annotations
import argparse, ast, datetime as dt, hashlib, json, os, re, shutil, subprocess, sys, zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

TARGET='CBAdvMarketDataDBDEV'; NETWORK='ServicesDEV'; SERVICE_IP='192.168.200.27'; SERVICE_ENDPOINT='192.168.200.27:8086'; HV_ALIAS='hv2'
PHASE0J_FILES=[
'contracts/phase0j_marketdata_influx_capacity_gate_v1.json',
'config/phase0j_scope.template.json','config/phase0j_assessment.template.json',
'src/platformcompute/phase0j_marketdata_influx_capacity_gate.py',
'scripts/run_phase0j_marketdata_influx_capacity_gate_readonly.sh',
'tests/test_phase0j_marketdata_influx_capacity_gate.py',
'handoffs/PlatformCompute_Phase0J_Operator_Usage.md']
DR_REPO_CANDIDATES=['~/Documents/Business/Entities/BitStream/BitStreamDisasterRecovery','~/IdeaProjects/BitStreamDisasterRecovery','~/PhpstormProjects/BitStreamDisasterRecovery']
FORBIDDEN_REMOTE_TOKENS=('sudo ','systemctl ','service ','dnf ','yum ','apt ','virsh destroy','virsh start','virsh shutdown','virsh reboot','virsh define','virsh undefine','virsh attach','virsh detach','virsh edit','virsh net-edit','virsh pool-','rm ','mv ','cp ','chmod ','chown ','firewall-cmd','iptables','nft ','mount ','umount ','truncate ','dd ','qemu-img resize','lvextend')
REMOTE_SCRIPT=r'''set -eu
TARGET="CBAdvMarketDataDBDEV"
NETWORK="ServicesDEV"
printf 'EVIDENCE_UTC=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'HYPERVISOR_HOSTNAME='; hostname -f 2>/dev/null || hostname
printf '\n=== DOMAIN UUID ===\n'; virsh domuuid "$TARGET"
printf '\n=== DOMAIN INFO ===\n'; virsh dominfo "$TARGET"
printf '\n=== DOMAIN INTERFACES ===\n'; virsh domiflist "$TARGET"
MAC="$(virsh domiflist "$TARGET" | awk '$3=="network" && $4=="ServicesDEV" {print $5; exit}')"
printf '\nTARGET_SERVICESDEV_MAC=%s\n' "$MAC"
printf '\n=== SERVICESDEV TARGET LEASE ===\n'
if [ -n "$MAC" ]; then virsh net-dhcp-leases "$NETWORK" --mac "$MAC" || true; else echo 'UNVERIFIED_NO_SERVICESDEV_MAC'; fi
printf '\n=== DOMAIN BLOCK DEVICES ===\n'; virsh domblklist "$TARGET" --details
printf '\n=== BACKING PATH HOST MOUNTS ===\n'
virsh domblklist "$TARGET" --details | awk '$2=="disk" && $4 != "-" {print $4}' | while IFS= read -r src; do
  printf '\nSOURCE=%s\n' "$src"
  if [ -e "$src" ]; then
    stat -Lc 'STAT device=%d inode=%i mode=%A size=%s owner=%U group=%G path=%n' "$src" || true
    findmnt -T "$src" -n -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || echo 'FINDMNT_UNVERIFIED'
  else echo 'SOURCE_NOT_VISIBLE_AS_HOST_PATH'; fi
done
'''

def utc_now(): return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def run(cmd:List[str],cwd:Optional[Path]=None,timeout:int=60):
    p=subprocess.run(cmd,cwd=str(cwd) if cwd else None,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    return {'cmd':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
def sha256_file(p:Path):
    h=hashlib.sha256(); f=p.open('rb')
    with f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()
def write_json(p:Path,o:Any): p.write_text(json.dumps(o,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def find_repo_root(explicit):
    if explicit:
        p=Path(explicit).expanduser().resolve()
        if (p/'.git').exists(): return p
        raise SystemExit(f'ERROR: not a Git checkout: {p}')
    r=run(['git','rev-parse','--show-toplevel'])
    if r['returncode']==0: return Path(r['stdout'].strip()).resolve()
    p=Path('~/Documents/Business/Entities/BitStream/BitStreamPlatformCompute').expanduser()
    if (p/'.git').exists(): return p.resolve()
    raise SystemExit('ERROR: cannot locate BitStreamPlatformCompute; use --repo-root')
def git_attestation(repo:Path):
    def g(*a): return run(['git',*a],cwd=repo)
    head=g('rev-parse','HEAD'); om=g('rev-parse','refs/remotes/origin/main'); br=g('branch','--show-current'); st=g('status','--porcelain=v1','--untracked-files=all'); d=g('diff','--no-ext-diff','--quiet'); dc=g('diff','--cached','--quiet')
    return {'repo_root':str(repo),'head':head,'origin_main':om,'branch':br,'status_porcelain':st,'worktree_tracked_clean':d['returncode']==0 and dc['returncode']==0,'head_equals_origin_main':head['returncode']==0 and om['returncode']==0 and head['stdout'].strip()==om['stdout'].strip(),'captured_utc':utc_now(),'note':'No git fetch/reset/checkout/pull performed.'}
def phase0j_file_attestation(repo:Path,raw:Path):
    items={}; missing=[]
    for rel in PHASE0J_FILES:
        p=repo/rel
        if not p.is_file(): items[rel]={'exists':False}; missing.append(rel); continue
        b=p.read_bytes(); items[rel]={'exists':True,'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}
        dst=raw/'phase0j_source'/rel; dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(b)
    return {'files':items,'missing':missing}
def static_value(n):
    try:return ast.literal_eval(n)
    except:return None
def extract_python_operations(path:Path):
    t=path.read_text(encoding='utf-8'); tree=ast.parse(t,filename=str(path)); ext=[]; fs=[]; dyn=False
    local={'stat','statvfs','exists','is_file','is_dir','read_text','read_bytes','open','disk_usage','iterdir','glob','rglob','resolve'}
    for n in ast.walk(tree):
        if not isinstance(n,ast.Call): continue
        fn=''
        if isinstance(n.func,ast.Name): fn=n.func.id
        elif isinstance(n.func,ast.Attribute):
            parts=[]; c=n.func
            while isinstance(c,ast.Attribute): parts.append(c.attr); c=c.value
            if isinstance(c,ast.Name): parts.append(c.id)
            fn='.'.join(reversed(parts))
        if fn in {'subprocess.run','subprocess.check_call','subprocess.check_output','subprocess.Popen','os.system'}:
            a=static_value(n.args[0]) if n.args else None
            if a is None: dyn=True; ext.append({'call':fn,'argv':'DYNAMIC'})
            else: ext.append({'call':fn,'argv':a})
        if fn.split('.')[-1] in local: fs.append(fn)
    terms=sorted(set(re.findall(r'(?i)\b(data(?:_path|_dir)?|wal(?:_path|_dir)?|index(?:_path|_dir)?|metadata(?:_path|_dir)?|backup(?:_path|_dir|_paths)?|mount|filesystem)\b',t)))
    return {'external_command_calls':ext,'dynamic_external_command_present':dyn,'filesystem_api_calls':sorted(set(fs)),'storage_path_terms_present':terms}
def extract_runner_operations(path:Path):
    rows=[]
    for n,raw in enumerate(path.read_text(encoding='utf-8').splitlines(),1):
        s=raw.strip()
        if not s or s.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*=',s) or s in {'set -e','set -eu','set -euo pipefail','set -o pipefail'}: continue
        rows.append({'line':n,'text':s})
    return {'non_comment_non_assignment_lines':rows}
def contract_operation_fields(path:Path):
    try:o=json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:return {'parse_error':str(e),'operation_like_fields':[]}
    hits=[]
    def walk(v,p='$'):
        if isinstance(v,dict):
            for k,vv in v.items():
                kp=f'{p}.{k}'
                if re.search(r'(?i)(allow|operation|command|read|path|collect)',k): hits.append({'path':kp,'value':vv})
                walk(vv,kp)
        elif isinstance(v,list):
            for i,vv in enumerate(v): walk(vv,f'{p}[{i}]')
    walk(o); return {'operation_like_fields':hits}
def run_validation(repo:Path):
    rel='tests/test_phase0j_marketdata_influx_capacity_gate.py'; tf=repo/rel
    if not tf.is_file(): return {'result':'UNVERIFIED','reason':f'missing {rel}'}
    attempts=[]
    for cmd in ([sys.executable,'-m','unittest','-v',rel],[sys.executable,str(tf)]):
        r=run(cmd,cwd=repo,timeout=180); attempts.append(r)
        if r['returncode']==0:return {'result':'PASS','successful_command':cmd,'attempts':attempts}
    return {'result':'FAIL','attempts':attempts}
def validate_remote_script():
    low=REMOTE_SCRIPT.lower()
    for tok in FORBIDDEN_REMOTE_TOKENS:
        if tok.lower() in low: raise RuntimeError(f'forbidden remote token: {tok}')
def ssh_config(alias):
    r=run(['ssh','-G',alias],timeout=20); selected={}
    if r['returncode']==0:
        for line in r['stdout'].splitlines():
            if ' ' not in line: continue
            k,v=line.split(' ',1)
            if k in {'hostname','user','port','proxyjump','stricthostkeychecking','userknownhostsfile','identityfile','batchmode'}: selected.setdefault(k,[]).append(v)
    return {'raw':r,'selected':selected}
def collect_hv(alias):
    validate_remote_script(); cfg=ssh_config(alias)
    p=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=12',alias,'bash','-s'],input=REMOTE_SCRIPT,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    return {'ssh_config':cfg,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
def parse_hv(raw):
    o={'target_guest':TARGET,'network':NETWORK,'service_ip_expected':SERVICE_IP,'service_endpoint':SERVICE_ENDPOINT}
    m=re.search(r'=== DOMAIN UUID ===\s*\n([0-9a-fA-F-]{16,})',raw); o['domain_uuid']=m.group(1).strip() if m else None
    m=re.search(r'TARGET_SERVICESDEV_MAC=([0-9a-fA-F:]+)',raw); o['servicesdev_mac']=m.group(1) if m else None
    o['servicesdev_network_seen']=bool(re.search(r'\bnetwork\s+ServicesDEV\b',raw)); o['service_ip_seen_in_lease']=SERVICE_IP in raw
    disks=[]; b=re.search(r'=== DOMAIN BLOCK DEVICES ===\s*\n(.*?)(?:\n=== BACKING PATH HOST MOUNTS ===)',raw,re.S)
    if b:
        for line in b.group(1).splitlines():
            s=line.strip()
            if not s or s.lower().startswith('type') or set(s)<={'-'}: continue
            p=s.split(None,3)
            if len(p)==4 and p[1]=='disk': disks.append({'type':p[0],'device':p[1],'target':p[2],'source':p[3]})
    o['disk_bindings']=disks; return o
def find_dr_repo(explicit):
    for c in ([explicit] if explicit else DR_REPO_CANDIDATES):
        if not c: continue
        p=Path(c).expanduser().resolve()
        if (p/'.git').exists(): return p
    return None
def dr_scope(repo,raw):
    if repo is None:return {'status':'UNVERIFIED','reason':'local BitStreamDisasterRecovery checkout not found','candidates':DR_REPO_CANDIDATES}
    markers=('bitstream-dr-inventory','SSH_ORIGINAL_COMMAND','ForceCommand','forced-command','sanitized','snapshot','authorized_keys'); matches=[]; hashes={}
    for p in repo.rglob('*'):
        if not p.is_file(): continue
        rel=p.relative_to(repo)
        if any(x in {'.git','venv','.venv','__pycache__','node_modules'} for x in rel.parts): continue
        try:
            if p.stat().st_size>2_000_000: continue
            t=p.read_text(encoding='utf-8',errors='ignore')
        except: continue
        if any(m.lower() in t.lower() for m in markers):
            ls=[]
            for i,line in enumerate(t.splitlines(),1):
                if any(m.lower() in line.lower() for m in markers): ls.append({'line':i,'text':line[:1000]})
            matches.append({'file':rel.as_posix(),'matches':ls[:80]}); hashes[rel.as_posix()]=sha256_file(p)
            dst=raw/'dr_scope_sources'/rel; dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(p.read_bytes())
    return {'status':'FOUND','repo_root':str(repo),'git':git_attestation(repo),'matched_files':matches,'sha256':hashes,'note':'No DR command executed.'}
def derive_op(fa,py,runner,contract):
    missing=fa['missing']; dyn=py.get('dynamic_external_command_present',True); status='PROVEN' if not missing and not dyn else 'NOT_PROVEN'
    return {'EXACT_OPERATION_SET':status,'basis':{'all_required_files_present':not bool(missing),'dynamic_external_command_present':dyn,'contract_operation_like_fields_count':len(contract.get('operation_like_fields',[]))},'python_operations':py,'runner_operations':runner,'contract_operation_fields':contract.get('operation_like_fields',[]),'review_note':'Security must review captured sources and operation inventory.'}
def build_manifest(root):
    rows=[]
    for p in sorted(root.rglob('*')):
        if p.is_file() and p.name!='MANIFEST.sha256': rows.append(f'{sha256_file(p)}  {p.relative_to(root).as_posix()}\n')
    (root/'MANIFEST.sha256').write_text(''.join(rows),encoding='utf-8')
def zip_dir(root,zp):
    with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(root.rglob('*')):
            if p.is_file(): z.write(p,arcname=f'{root.name}/{p.relative_to(root).as_posix()}')
    return sha256_file(zp)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--repo-root'); ap.add_argument('--dr-repo'); ap.add_argument('--hv-alias',default=HV_ALIAS); ap.add_argument('--output-dir',default=str(Path('~/Downloads').expanduser())); ap.add_argument('--skip-hv2',action='store_true'); a=ap.parse_args()
    repo=find_repo_root(a.repo_root); stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'); parent=Path(a.output_dir).expanduser().resolve(); parent.mkdir(parents=True,exist_ok=True); ev=parent/f'PlatformCompute-Phase0J-FourDefect-Closure-{stamp}'; raw=ev/'raw'; raw.mkdir(parents=True)
    result={'packet':{'id':f'platformcompute-phase0j-four-defect-closure-{stamp}','evidence_utc':utc_now(),'authority':'PLATFORM_INFRASTRUCTURE_FACTS_ONLY','no_access_expansion':True,'phase0j_collector_executed':False,'segment_c_authorized':False}}
    ga=git_attestation(repo); result['source_git']=ga; write_json(raw/'platform_git_attestation.json',ga)
    fa=phase0j_file_attestation(repo,raw); result['phase0j_files']=fa; write_json(raw/'phase0j_file_hashes.json',fa)
    sp=repo/'src/platformcompute/phase0j_marketdata_influx_capacity_gate.py'; rp=repo/'scripts/run_phase0j_marketdata_influx_capacity_gate_readonly.sh'; cp=repo/'contracts/phase0j_marketdata_influx_capacity_gate_v1.json'
    py=extract_python_operations(sp) if sp.is_file() else {'error':'source missing','dynamic_external_command_present':True}; ro=extract_runner_operations(rp) if rp.is_file() else {'error':'runner missing'}; co=contract_operation_fields(cp) if cp.is_file() else {'error':'contract missing','operation_like_fields':[]}; op=derive_op(fa,py,ro,co); result['operation_set']=op; write_json(raw/'phase0j_operation_inventory.json',op)
    val=run_validation(repo); result['validation']=val; write_json(raw/'phase0j_validation.json',val)
    parsed={}; hv={'status':'NOT_PROVEN','reason':'--skip-hv2'} if a.skip_hv2 else None
    if not a.skip_hv2:
        try:
            hv=collect_hv(a.hv_alias); (raw/'hypervisor02_target_evidence.stdout.txt').write_text(hv['stdout'],encoding='utf-8'); (raw/'hypervisor02_target_evidence.stderr.txt').write_text(hv['stderr'],encoding='utf-8'); write_json(raw/'hv2_ssh_config.json',hv['ssh_config']); parsed=parse_hv(hv['stdout'])
        except Exception as e: hv={'status':'NOT_PROVEN','error':repr(e)}
    result['hypervisor_collection']={'returncode':hv.get('returncode'),'status':'CAPTURED' if hv.get('returncode')==0 else hv.get('status','NOT_PROVEN'),'parsed':parsed,'safety':{'target':TARGET,'alias':a.hv_alias,'alternate_host_probing':False,'trust_mutation':False,'remote_mutation':False,'guest_access':False}}
    dr=dr_scope(find_dr_repo(a.dr_repo),raw); result['dr_existing_scope']=dr; write_json(raw/'dr_existing_scope_inventory.json',dr)
    uuid=parsed.get('domain_uuid'); disks=parsed.get('disk_bindings') or []; target_ok=bool(uuid and parsed.get('servicesdev_network_seen')); storage_ok=bool(disks); source_clean=bool(ga.get('head_equals_origin_main') and ga.get('worktree_tracked_clean') and not fa.get('missing') and val.get('result')=='PASS'); exact_ok=op.get('EXACT_OPERATION_SET')=='PROVEN' and source_clean
    auth_reason='Existing DR scope source captured for DR/Security comparison; helper never self-authorizes.' if dr.get('status')=='FOUND' else 'DR forced-command source not located locally.'
    result['closure']={'TARGET_IDENTITY':'PROVEN' if target_ok else 'NOT_PROVEN','TARGET_GUEST':TARGET,'TARGET_PLATFORM_IDENTITY':uuid or 'UNVERIFIED','OWNING_HYPERVISOR':'Hypervisor02','NETWORK':NETWORK,'SERVICE_ENDPOINT':SERVICE_ENDPOINT,'SERVICE_IP_LEASE_CORRELATION':'PROVEN' if parsed.get('service_ip_seen_in_lease') else 'UNVERIFIED','REQUIRED_STORAGE_BINDING':'PROVEN' if storage_ok else 'NOT_PROVEN','GUEST_DISK_BINDINGS':disks,'EXACT_OPERATION_SET':'PROVEN' if exact_ok else 'NOT_PROVEN','ACCEPTED_HEAD':ga.get('head',{}).get('stdout','').strip() or 'UNVERIFIED','SOURCE_STATE':'ACCEPTED_HEAD_CLEAN_VALIDATED' if source_clean else 'NOT_PROVEN','VALIDATION_RESULT':val.get('result','UNVERIFIED'),'EXISTING_AUTHORIZATION_FOR_EXACT_OPERATION_SET':'NOT_PROVEN','EXISTING_AUTHORIZATION_REVIEW_REASON':auth_reason,'ALL_REQUIRED_HOPS_AND_TRUST':'NOT_PROVEN','NO_ACCESS_EXPANSION':True,'PHASE0J_COLLECTOR_EXECUTION_AUTHORIZED':False,'SEGMENT_C_MAY_PROCEED':False}
    write_json(ev/'phase0j_four_defect_closure.json',result)
    lines=['# Platform & Compute — Phase-0J Four-Defect Closure Evidence','',f"Evidence UTC: `{result['packet']['evidence_utc']}`",'','```text']
    for k in ('TARGET_IDENTITY','TARGET_PLATFORM_IDENTITY','REQUIRED_STORAGE_BINDING','EXACT_OPERATION_SET','EXISTING_AUTHORIZATION_FOR_EXACT_OPERATION_SET','ALL_REQUIRED_HOPS_AND_TRUST','NO_ACCESS_EXPANSION','VALIDATION_RESULT','ACCEPTED_HEAD','SOURCE_STATE'): lines.append(f"{k} = {result['closure'].get(k)}")
    lines += ['PHASE0J_COLLECTOR_EXECUTION_AUTHORIZED = NO','SEGMENT_C_MAY_PROCEED = NO','```','','Return this packet to the MarketData centralized integration/closure point.','This tool did not run Phase-0J or expand access.']
    (ev/'README.md').write_text('\n'.join(lines)+'\n',encoding='utf-8'); build_manifest(ev); zp=parent/f'{ev.name}.zip'; zs=zip_dir(ev,zp); (parent/f'{zp.name}.sha256').write_text(f'{zs}  {zp.name}\n',encoding='utf-8')
    print(f'PACKET_ZIP={zp}'); print(f'PACKET_SHA256={zs}'); print('CLOSURE_STATUS_BEGIN')
    for k,v in result['closure'].items():
        if not isinstance(v,(dict,list)): print(f'{k}={v}')
    print('CLOSURE_STATUS_END'); return 0
if __name__=='__main__': raise SystemExit(main())
