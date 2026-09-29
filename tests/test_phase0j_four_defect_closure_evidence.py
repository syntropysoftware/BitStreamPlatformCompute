import importlib.util
from pathlib import Path
import unittest
SCRIPT=Path(__file__).resolve().parents[1]/'scripts'/'phase0j_four_defect_closure_evidence.py'
spec=importlib.util.spec_from_file_location('p',SCRIPT); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class T(unittest.TestCase):
    def test_remote_safe(self):
        m.validate_remote_script()

    def test_parse_current_target_identity_storage_and_ip(self):
        s='''=== DOMAIN UUID ===\n11111111-2222-3333-4444-555555555555\n=== DOMAIN INTERFACES ===\n vnet1 network ServicesDEV virtio 52:54:00:aa:bb:cc\nTARGET_SERVICESDEV_MAC=52:54:00:aa:bb:cc\n=== SERVICESDEV TARGET LEASE ===\n2026-09-29 15:00:00 52:54:00:aa:bb:cc ipv4 192.168.200.27/24\n=== SERVICESDEV NETWORK XML ===\n<network><ip><dhcp><host mac='52:54:00:aa:bb:cc' name='CBAdvMarketDataDBDEV' ip='192.168.200.27'/></dhcp></ip></network>\n=== DOMAIN BLOCK DEVICES ===\n file disk vda /mnt/Storage/x.qcow2\n=== BACKING PATH HOST MOUNTS ===\nSOURCE=/mnt/Storage/x.qcow2\n/mnt/Storage /dev/sdc ext4 rw,relatime\n'''
        p=m.parse_hv(s)
        self.assertEqual(p['domain_uuid'],'11111111-2222-3333-4444-555555555555')
        self.assertTrue(p['servicesdev_network_seen'])
        self.assertTrue(p['service_ip_binding_proven'])
        self.assertEqual(p['disk_bindings'][0]['target'],'vda')
        self.assertEqual(p['backing_mounts'][0]['mount_source'],'/dev/sdc')

    def test_fail_closed_unknown_dynamic_external(self):
        out=m.derive_op(
            {'missing':[],'all_required_files_match_origin_main':True},
            {'dynamic_external_command_present':True,'dynamic_external_is_recognized_read_only_git_wrapper':False},
            {},{'operation_like_fields':[]})
        self.assertEqual(out['EXACT_OPERATION_SET'],'NOT_PROVEN')

    def test_accept_recognized_read_only_git_wrapper(self):
        out=m.derive_op(
            {'missing':[],'all_required_files_match_origin_main':True},
            {'dynamic_external_command_present':True,'dynamic_external_is_recognized_read_only_git_wrapper':True},
            {},{'operation_like_fields':[]})
        self.assertEqual(out['EXACT_OPERATION_SET'],'PROVEN')

if __name__=='__main__': unittest.main()
