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
MAC="$(virsh domiflist "$TARGET" | awk '$2=="network" && $3=="ServicesDEV" {print $5; exit}')"
printf '\nTARGET_SERVICESDEV_MAC=%s\n' "$MAC"
printf '\n=== SERVICESDEV TARGET LEASE ===\n'
if [ -n "$MAC" ]; then virsh net-dhcp-leases "$NETWORK" --mac "$MAC" || true; else echo 'UNVERIFIED_NO_SERVICESDEV_MAC'; fi
printf '\n=== SERVICESDEV NETWORK XML ===\n'; virsh net-dumpxml "$NETWORK"
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
    head=g('rev-parse','HEAD'); om=g('rev-parse','refs/remotes/origin/main'); od=g('rev-parse','refs/remotes/origin/david'); br=g('branch','--show-current'); st=g('status','--porcelain=v1','--untracked-files=all'); d=g('diff','--no-ext-diff','--quiet'); dc=g('diff','--cached','--quiet')
    return {
        'repo_root':str(repo),'head':head,'origin_main':om,'origin_david':od,'branch':br,
        'status_porcelain':st,
        'worktree_tracked_clean':d['returncode']==0 and dc['returncode']==0,
        'head_equals_origin_main':head['returncode']==0 and om['returncode']==0 and head['stdout'].strip()==om['stdout'].strip(),
        'head_equals_origin_david':head['returncode']==0 and od['returncode']==0 and head['stdout'].strip()==od['stdout'].strip(),
        'captured_utc':utc_now(),
        'note':'No git fetch/reset/checkout/pull performed.'
    }
def phase0j_file_attestation(repo:Path,raw:Path):
    items={}; missing=[]; accepted_ref='refs/remotes/origin/main'; all_match=True
    for rel in PHASE0J_FILES:
        p=repo/rel
        if not p.is_file():
            items[rel]={'exists':False,'matches_origin_main':False}; missing.append(rel); all_match=False; continue
        b=p.read_bytes(); work_sha=hashlib.sha256(b).hexdigest()
        show=run(['git','show',f'{accepted_ref}:{rel}'],cwd=repo)
        accepted_bytes=show['stdout'].encode('utf-8') if show['returncode']==0 else None
        # git show in text mode is safe for these text artifacts. Compare hashes of canonical LF text bytes.
        accepted_sha=hashlib.sha256(accepted_bytes).hexdigest() if accepted_bytes is not None else None
        match=accepted_sha==work_sha if accepted_sha is not None else False
        all_match=all_match and match
        items[rel]={'exists':True,'size':len(b),'sha256':work_sha,'origin_main_sha256':accepted_sha,'matches_origin_main':match,'git_show_returncode':show['returncode']}
        dst=raw/'phase0j_source'/rel; dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(b)
        if accepted_bytes is not None:
            adst=raw/'phase0j_origin_main'/rel; adst.parent.mkdir(parents=True,exist_ok=True); adst.write_bytes(accepted_bytes)
    return {'files':items,'missing':missing,'accepted_ref':accepted_ref,'all_required_files_match_origin_main':all_match}
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

    recognized_git_wrapper = bool(re.search(r'def\s+verify_accepted_source\b[\s\S]*?subprocess\.run\(\[\"git\",\s*\*args\]', t))
    exact_git_reads = [
        ['git','rev-parse','HEAD'],
        ['git','rev-parse','origin/main'],
        ['git','status','--porcelain','--untracked-files=no'],
    ] if recognized_git_wrapper else []
    guest_local_required = all(token in t for token in ('verified_local_hostname','data_path','wal_path','os.statvfs'))
    return {
        'external_command_calls':ext,
        'dynamic_external_command_present':dyn,
        'dynamic_external_is_recognized_read_only_git_wrapper':recognized_git_wrapper,
        'exact_git_read_operations':exact_git_reads,
        'filesystem_api_calls':sorted(set(fs)),
        'storage_path_terms_present':terms,
        'guest_local_influx_paths_required_by_collect':guest_local_required,
        'host_collect_operation_allowlist':[
            'git rev-parse HEAD',
            'git rev-parse origin/main',
            'git status --porcelain --untracked-files=no',
            'read external non-secret scope JSON',
            'socket.gethostname local identity check',
            'Path.is_dir for data_path and wal_path (and backup_path only when owner declares local)',
            'read /proc/self/mountinfo',
            'os.statvfs on approved local paths',
            'os.stat on approved local paths',
            'read /proc/meminfo',
            'read /proc/diskstats',
            'os.getloadavg',
            'write local evidence snapshot outside Influx storage'
        ],
        'network_operations_by_collect':[],
        'ssh_operations_by_collect':[],
        'influx_api_operations_by_collect':[],
    }
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
    o['servicesdev_network_seen']=bool(re.search(r'\bnetwork\s+ServicesDEV\b',raw))
    lease_block=re.search(r'=== SERVICESDEV TARGET LEASE ===\s*\n(.*?)(?:\n=== SERVICESDEV NETWORK XML ===)',raw,re.S)
    lease_text=lease_block.group(1) if lease_block else ''
    o['service_ip_seen_in_lease']=SERVICE_IP in lease_text
    net_block=re.search(r'=== SERVICESDEV NETWORK XML ===\s*\n(.*?)(?:\n=== DOMAIN BLOCK DEVICES ===)',raw,re.S)
    net_text=net_block.group(1) if net_block else ''
    mac=o.get('servicesdev_mac') or ''
    ip_xml=False
    if mac and SERVICE_IP in net_text:
        # Require MAC and IP to occur in the same host element when possible.
        for host in re.findall(r'<host\b[^>]*>',net_text,re.I):
            if mac.lower() in host.lower() and SERVICE_IP in host:
                ip_xml=True; break
    o['service_ip_seen_in_network_xml_reservation']=ip_xml
    o['service_ip_binding_proven']=bool(o['service_ip_seen_in_lease'] or ip_xml)
    disks=[]; b=re.search(r'=== DOMAIN BLOCK DEVICES ===\s*\n(.*?)(?:\n=== BACKING PATH HOST MOUNTS ===)',raw,re.S)
    if b:
        for line in b.group(1).splitlines():
            ss=line.strip()
            if not ss or ss.lower().startswith('type') or set(ss)<={'-'}: continue
            pp=ss.split(None,3)
            if len(pp)==4 and pp[1]=='disk': disks.append({'type':pp[0],'device':pp[1],'target':pp[2],'source':pp[3]})
    o['disk_bindings']=disks
    mounts=[]
    mb=re.search(r'=== BACKING PATH HOST MOUNTS ===\s*\n(.*)$',raw,re.S)
    if mb:
        current=None
        for line in mb.group(1).splitlines():
            line=line.strip()
            if line.startswith('SOURCE='):
                current={'source_path':line.split('=',1)[1]}; mounts.append(current)
            elif current and line.startswith('/'):
                parts=line.split(None,3)
                if len(parts)>=3:
                    current['mountpoint']=parts[0]; current['mount_source']=parts[1]; current['fstype']=parts[2]
    o['backing_mounts']=mounts
    return o
def local_guest_path_evidence(alias:str='CBAdvMarketDataDBDEV'):
    cfg=ssh_config(alias)
    selected=cfg.get('selected',{})
    hostname=(selected.get('hostname') or [''])[0]
    port=(selected.get('port') or ['22'])[0]
    strict=(selected.get('stricthostkeychecking') or [''])[0]
    user=(selected.get('user') or [''])[0]
    # ssh -G always synthesizes defaults; require an exact Host stanza in ~/.ssh/config to call this configured.
    configured=False
    config_path=Path('~/.ssh/config').expanduser()
    if config_path.is_file():
        try:
            for line in config_path.read_text(encoding='utf-8',errors='ignore').splitlines():
                st=line.strip()
                if st.lower().startswith('host '):
                    pats=st.split()[1:]
                    if alias in pats: configured=True; break
        except OSError:
            pass
    kh_match=None
    if hostname:
        lookup=f'[{hostname}]:{port}' if str(port)!='22' else hostname
        kh=run(['ssh-keygen','-F',lookup],timeout=15)
        kh_match=kh['returncode']==0 and bool(kh['stdout'].strip())
    return {
        'alias':alias,'exact_host_stanza_present':configured,'selected':selected,
        'configured_hostname':hostname or None,'configured_user':user or None,'configured_port':port or None,
        'strict_host_key_checking':strict or None,'known_hosts_match_present':kh_match,
        'connection_attempted':False,
        'authorization_proven':False,
        'note':'Configuration/trust evidence only. No guest connection was attempted and no owner authorization is inferred.'
    }

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
    missing=fa['missing']
    dyn=py.get('dynamic_external_command_present',True)
    recognized=py.get('dynamic_external_is_recognized_read_only_git_wrapper',False)
    source_identity=bool(fa.get('all_required_files_match_origin_main'))
    status='PROVEN' if (not missing and source_identity and (not dyn or recognized)) else 'NOT_PROVEN'
    return {
        'EXACT_OPERATION_SET':status,
        'basis':{
            'all_required_files_present':not bool(missing),
            'all_required_files_match_origin_main':source_identity,
            'dynamic_external_command_present':dyn,
            'dynamic_external_is_recognized_read_only_git_wrapper':recognized,
            'contract_operation_like_fields_count':len(contract.get('operation_like_fields',[]))
        },
        'python_operations':py,
        'runner_operations':runner,
        'contract_operation_fields':contract.get('operation_like_fields',[]),
        'review_note':'Exact host-side collect operation set derived from accepted origin/main source. Offline evaluate remains local file processing and packet generation.'
    }
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
    guest_path=local_guest_path_evidence(); result['existing_guest_path_candidate']=guest_path; write_json(raw/'existing_guest_path_candidate.json',guest_path)
    uuid=parsed.get('domain_uuid'); disks=parsed.get('disk_bindings') or []
    target_ok=bool(uuid and parsed.get('servicesdev_network_seen') and parsed.get('service_ip_binding_proven'))
    storage_ok=bool(disks and parsed.get('backing_mounts'))
    accepted_source_identity=bool(ga.get('worktree_tracked_clean') and fa.get('all_required_files_match_origin_main') and not fa.get('missing') and val.get('result')=='PASS')
    exact_ok=op.get('EXACT_OPERATION_SET')=='PROVEN' and accepted_source_identity
    guest_local_required=bool(op.get('python_operations',{}).get('guest_local_influx_paths_required_by_collect'))
    guest_candidate=bool(guest_path.get('exact_host_stanza_present') and guest_path.get('known_hosts_match_present'))
    auth_reason=(
        'Phase-0J accepted collect source requires guest-local data_path/wal_path metadata. Existing hypervisor DR inventory scope does not itself authorize guest-local Phase-0J operations. ' +
        ('A pre-existing configured/pinned exact guest SSH path candidate exists, but owner authorization and exact allowed guest operations are not proven by this capture.' if guest_candidate else 'No pre-existing configured+pinned exact guest path was proven by this capture.')
    )
    result['closure']={
        'TARGET_IDENTITY':'PROVEN' if target_ok else 'NOT_PROVEN',
        'TARGET_GUEST':TARGET,
        'TARGET_PLATFORM_IDENTITY':uuid or 'UNVERIFIED',
        'OWNING_HYPERVISOR':'Hypervisor02',
        'NETWORK':NETWORK,
        'SERVICE_ENDPOINT':SERVICE_ENDPOINT,
        'SERVICE_IP_BINDING':'PROVEN' if parsed.get('service_ip_binding_proven') else 'NOT_PROVEN',
        'REQUIRED_STORAGE_BINDING':'PROVEN' if storage_ok else 'NOT_PROVEN',
        'GUEST_DISK_BINDINGS':disks,
        'BACKING_MOUNTS':parsed.get('backing_mounts') or [],
        'GUEST_LOCAL_INFLUX_PATHS_REQUIRED':'YES' if guest_local_required else 'NO',
        'EXACT_OPERATION_SET':'PROVEN' if exact_ok else 'NOT_PROVEN',
        'ACCEPTED_BRANCH':'origin/main',
        'ACCEPTED_HEAD':ga.get('origin_main',{}).get('stdout','').strip() or 'UNVERIFIED',
        'CURRENT_CHECKOUT_HEAD':ga.get('head',{}).get('stdout','').strip() or 'UNVERIFIED',
        'CURRENT_CHECKOUT_BRANCH':ga.get('branch',{}).get('stdout','').strip() or 'UNVERIFIED',
        'SOURCE_STATE':'ACCEPTED_ORIGIN_MAIN_FILES_BYTE_IDENTICAL_AND_VALIDATED' if accepted_source_identity else 'NOT_PROVEN',
        'CURRENT_CHECKOUT_READY_FOR_PHASE0J_COLLECT':'YES' if ga.get('head_equals_origin_main') and ga.get('worktree_tracked_clean') else 'NO',
        'VALIDATION_RESULT':val.get('result','UNVERIFIED'),
        'EXISTING_GUEST_PATH_CANDIDATE':'FOUND_CONFIG_AND_PINNED_TRUST' if guest_candidate else 'NOT_PROVEN',
        'EXISTING_AUTHORIZATION_FOR_EXACT_OPERATION_SET':'NOT_PROVEN',
        'EXISTING_AUTHORIZATION_REVIEW_REASON':auth_reason,
        'ALL_REQUIRED_HOPS_AND_TRUST':'NOT_PROVEN',
        'NO_ACCESS_EXPANSION':True,
        'PHASE0J_COLLECTOR_EXECUTION_AUTHORIZED':False,
        'SEGMENT_C_MAY_PROCEED':False
    }
    write_json(ev/'phase0j_four_defect_closure.json',result)
    lines=['# Platform & Compute — Phase-0J Four-Defect Closure Evidence','',f"Evidence UTC: `{result['packet']['evidence_utc']}`",'','```text']
    for k in ('TARGET_IDENTITY','TARGET_PLATFORM_IDENTITY','SERVICE_IP_BINDING','REQUIRED_STORAGE_BINDING','GUEST_LOCAL_INFLUX_PATHS_REQUIRED','EXACT_OPERATION_SET','EXISTING_GUEST_PATH_CANDIDATE','EXISTING_AUTHORIZATION_FOR_EXACT_OPERATION_SET','ALL_REQUIRED_HOPS_AND_TRUST','NO_ACCESS_EXPANSION','VALIDATION_RESULT','ACCEPTED_HEAD','CURRENT_CHECKOUT_HEAD','SOURCE_STATE','CURRENT_CHECKOUT_READY_FOR_PHASE0J_COLLECT'): lines.append(f"{k} = {result['closure'].get(k)}")
    lines += ['PHASE0J_COLLECTOR_EXECUTION_AUTHORIZED = NO','SEGMENT_C_MAY_PROCEED = NO','```','','Return this packet to the MarketData centralized integration/closure point.','This tool did not run Phase-0J or expand access.']
    (ev/'README.md').write_text('\n'.join(lines)+'\n',encoding='utf-8'); build_manifest(ev); zp=parent/f'{ev.name}.zip'; zs=zip_dir(ev,zp); (parent/f'{zp.name}.sha256').write_text(f'{zs}  {zp.name}\n',encoding='utf-8')
    print(f'PACKET_ZIP={zp}'); print(f'PACKET_SHA256={zs}'); print('CLOSURE_STATUS_BEGIN')
    for k,v in result['closure'].items():
        if not isinstance(v,(dict,list)): print(f'{k}={v}')
    print('CLOSURE_STATUS_END'); return 0
if __name__=='__main__': raise SystemExit(main())
