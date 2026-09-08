#!/usr/bin/env python3
import importlib.util,json,pathlib,sys,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]; D=ROOT/'src'/'platformcompute';sys.path.insert(0,str(D)); M=D/'phase0d_focused_route_persistence_reconciliation.py'
s=importlib.util.spec_from_file_location('pc_p0d',M);pc=importlib.util.module_from_spec(s);sys.modules[s.name]=pc;s.loader.exec_module(pc)
class T(unittest.TestCase):
 def test_contract(self): self.assertEqual(pc.CONTRACT,'bitstream-platformcompute-phase0d-focused-route-persistence-reconciliation-v1')
 def test_nexus_guard(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'c.json';p.write_text(json.dumps({'contract':pc.CONTRACT,'nexusdb':{'platform_implementation_authorized':True}}))
   with self.assertRaises(ValueError):pc.load_config(p)
 def test_explicit_probe_requires_preapproval(self):
  g={'expected_ip':'10.0.0.1','existing_user':'root','mode':'mariadb'}
  with mock.patch.object(pc,'known',return_value=0):
   obs,route=pc.explicit_guest_probe(g,22,1)
  self.assertIsNone(obs);self.assertEqual(route['blocker'],'BLOCKED_HOST_KEY_NOT_PREAPPROVED')
 def test_guest_lane_does_not_ssh_closed_ports(self):
  g={'key':'mariadb18','ssh_target':'MariaDB','expected_ip':'10.0.0.1','configured_port':69,'mode':'mariadb'}
  hv={'observed':{'vms':{'MariaDB':{'tcp':{'22':{'status':'REFUSED'},'69':{'status':'TIMEOUT'}}}}}}
  with mock.patch.object(pc,'explicit_guest_probe') as m:
   out=pc.guest_lane(g,hv,1)
  m.assert_not_called();self.assertEqual(out['status'],'BLOCKED')
 def test_owner_lane_no_guest_access(self):
  hv={'observed':{'vms':{'ETHService':{'domstate':{'stdout':'running'},'domblklist':{'stdout':'Type Device Target Source\nfile disk vda /x.qcow2'}}}}}
  o=pc.owner_lane('ethservice',{'vm_name':'ETHService','expected_ip':'1.2.3.4'},hv)
  self.assertFalse(o['guest_connection_attempted']);self.assertEqual(o['owner'],'UNRESOLVED_REQUIRES_OWNER_EVIDENCE')
 def test_hypervisor_probe_has_no_mutation_tokens(self):
  low=pc.HYPERVISOR_PROBE.lower()
  for x in ['virsh start','virsh shutdown','virsh destroy','virsh reboot','virsh undefine','virsh define','mount ','sudo ','ssh-keyscan']:
   self.assertNotIn(x,low)
 def test_source_has_no_trust_weakening(self):
  low=M.read_text().lower();self.assertNotIn('stricthostkeychecking=no',low);self.assertNotIn('ssh-keyscan',low)
if __name__=='__main__':unittest.main()
