import importlib.util
from pathlib import Path
import unittest
SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'phase0j_four_defect_closure_evidence.py'
spec=importlib.util.spec_from_file_location('p',SCRIPT); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class T(unittest.TestCase):
    def test_remote_safe(self): m.validate_remote_script()
    def test_parse(self):
        s='''=== DOMAIN UUID ===\n11111111-2222-3333-4444-555555555555\n=== DOMAIN INTERFACES ===\n vnet1 network ServicesDEV virtio 52:54:00:aa:bb:cc\nTARGET_SERVICESDEV_MAC=52:54:00:aa:bb:cc\n=== SERVICESDEV TARGET LEASE ===\n192.168.200.27/24\n=== DOMAIN BLOCK DEVICES ===\n file disk vda /mnt/Storage/x.qcow2\n=== BACKING PATH HOST MOUNTS ===\n'''
        p=m.parse_hv(s); self.assertEqual(p['domain_uuid'],'11111111-2222-3333-4444-555555555555'); self.assertTrue(p['servicesdev_network_seen']); self.assertTrue(p['service_ip_seen_in_lease']); self.assertEqual(p['disk_bindings'][0]['target'],'vda')
    def test_fail_closed_dynamic(self): self.assertEqual(m.derive_op({'missing':[]},{'dynamic_external_command_present':True},{},{'operation_like_fields':[]})['EXACT_OPERATION_SET'],'NOT_PROVEN')
if __name__=='__main__': unittest.main()
