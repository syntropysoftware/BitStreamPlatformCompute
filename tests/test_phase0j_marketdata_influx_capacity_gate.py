"""Phase-0J regression and safety tests using the repository's stdlib unittest.

No pytest dependency or network/production access is required. The master helper
runs unittest discovery under Python 3.8, so these tests must be discoverable by
that runner and use standard-library temporary directories and mocks only.
"""
import hashlib
import importlib.util
import json
import socket
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src/platformcompute/phase0j_marketdata_influx_capacity_gate.py'
spec = importlib.util.spec_from_file_location('p0j', SRC)
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)


def source():
    return {
        'status': 'ACCEPTED_SOURCE_PASS', 'accepted_ref': 'origin/main',
        'head': 'a' * 40, 'accepted_ref_sha': 'a' * 40,
        'tracked_worktree_clean': True,
    }


def scope(tmp_path):
    return {
        'verified_local_hostname': socket.gethostname(),
        'actual_influx_guest_id': 'OWNER_VERIFIED_GUEST_1',
        'hypervisor_id': 'OWNER_VERIFIED_HV1',
        'inventory_evidence_ref': 'inventory:sha256:deadbeef',
        'endpoint_mapping_evidence_ref': 'endpoint:sha256:feedface',
        'data_path': str(tmp_path), 'wal_path': str(tmp_path),
        'backup_path': None, 'backup_path_local': False,
    }


def snapshot(tmp_path):
    out = p.collect(scope(tmp_path), source_gate=source())
    out['volumes']['data_path']['fs_available_unprivileged_bytes'] = 20_000_000_000
    out['volumes']['data_path']['inode_available_unprivileged'] = 1000
    out['volumes']['wal_path']['fs_available_unprivileged_bytes'] = 20_000_000_000
    return out


def assessment():
    return json.loads((ROOT / 'config/phase0j_assessment.template.json').read_text())


def full_assessment():
    a = assessment()
    a.update({
        'scope_evidence_ref': 'scope:sha256:abc',
        'dev_live_isolation': 'VERIFIED',
        'dev_live_isolation_evidence_ref': 'isolation:sha256:abc',
        'bucket_inventory_names': [
            'CBAdvMarketTrades-BTC-USD', 'CBAdvMarketData-BTC-USD',
            'CBAdvMarketData-ETH-USD',
        ],
        'bucket_inventory_complete_evidence_ref': 'bucketinventory:sha256:abc',
        'bucket_retention_proof': [
            {
                'bucket': name, 'retention_seconds': 0,
                'source_ref': 'retention:sha256:' + str(i),
                'owner_confirmed_no_other_pruning': True,
            }
            for i, name in enumerate([
                'CBAdvMarketTrades-BTC-USD', 'CBAdvMarketData-BTC-USD',
                'CBAdvMarketData-ETH-USD',
            ])
        ],
        'lifecycle_no_pruning_evidence_ref': 'lifecycle:sha256:abc',
        'retention_owner_signoff_ref': 'retentionowner:sha256:abc',
        'retention_safe_for_506_day_research': 'YES',
        'attributed_storage_windows': [
            {
                'source_ref': 'measurement:sha256:abc',
                'attributed_raw_trades': 100000,
                'attributed_persisted_storage_delta_bytes': 10_000_000,
                'exclusive_bucket_attribution': True,
                'engine_and_index_included': True,
                'steady_state_compaction_checked': True,
            },
            {
                'source_ref': 'measurement:sha256:def',
                'attributed_raw_trades': 100000,
                'attributed_persisted_storage_delta_bytes': 20_000_000,
                'exclusive_bucket_attribution': True,
                'engine_and_index_included': True,
                'steady_state_compaction_checked': True,
            },
        ],
        'measured_peak_day_trades': 600000,
        'measured_peak_day_source_ref': 'peak:sha256:abc',
        'measured_wal_and_compaction_headroom_bytes': 100_000_000,
        'headroom_source_ref': 'headroom:sha256:abc',
        'measured_min_free_bytes_policy': 500_000_000,
        'free_space_policy_source_ref': 'policy:sha256:abc',
        'measured_live_and_eth_concurrent_write_budget_bytes_per_sec': 100000,
        'throughput_and_latency_source_ref': 'throughput:sha256:abc',
        'max_pilot_days_owner_policy': 1,
        'max_staged_batch_days_owner_policy': 7,
        'stop_conditions_owner_evidence_ref': 'stop:sha256:abc',
        'dr_backup_restore_io_and_offhost_dependency_ref': 'dr:sha256:abc',
        'backup_volume_capacity_evidence_ref': 'backup:sha256:abc',
        'backup_restore_required_headroom_bytes': 500_000_000,
        'reviewer': 'PlatformComputeOwner',
        'review_utc': '2026-09-23T19:00:00Z',
        'explicit_segment_c_capacity_signoff': 'APPROVED',
    })
    return a


class Phase0JMarketDataInfluxCapacityGateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='platformcompute-phase0j-tests-')
        self.addCleanup(temp.cleanup)
        self.tmp_path = Path(temp.name)

    def test_contract_scope_refuses_endpoint_host_inference(self):
        s = scope(self.tmp_path)
        s['verified_local_hostname'] = '192.168.200.27'
        with self.assertRaisesRegex(ValueError, 'WRONG_LOCAL_HOST'):
            p.collect(s, source_gate=source())

    def test_no_source_no_collection(self):
        with self.assertRaisesRegex(ValueError, 'ACCEPTED_SOURCE'):
            p.collect(scope(self.tmp_path))

    def test_no_secret_fields_in_scope(self):
        s = scope(self.tmp_path)
        s['api_token'] = 'sensitive'
        with self.assertRaisesRegex(ValueError, 'unknown fields'):
            p.collect(s, source_gate=source())

    def test_local_snapshot_reports_actual_volume_and_unverified_remote_backup(self):
        val = snapshot(self.tmp_path)
        self.assertEqual(val['endpoint_reference_only'], '192.168.200.27:8086')
        self.assertGreater(val['volumes']['data_path']['fs_total_bytes'], 0)
        self.assertGreater(val['volumes']['data_path']['inode_total'], 0)
        self.assertEqual(
            val['volumes']['backup_path']['status'],
            'UNVERIFIED_REMOTE_BACKUP_OWNER_EVIDENCE_REQUIRED',
        )
        self.assertEqual(
            val['capture_mode'],
            'LOCAL_ONLY_NO_NETWORK_NO_INFLUX_API_NO_SSH_NO_CREDENTIAL_READ',
        )
        self.assertEqual(val['source_gate']['status'], 'ACCEPTED_SOURCE_PASS')

    def test_missing_measurements_never_approve(self):
        gate = p.assess(snapshot(self.tmp_path), assessment(), 'a' * 64)
        self.assertEqual(gate['segment_c_capacity'], 'UNVERIFIED')
        self.assertEqual(gate['retention_safe_for_506_day_research'], 'UNVERIFIED')
        self.assertIsNone(gate['max_pilot_days'])
        self.assertEqual(gate['segments']['A']['status'], 'UNVERIFIED')

    def test_measured_range_still_requires_owner_signoff(self):
        a = full_assessment()
        a['explicit_segment_c_capacity_signoff'] = 'UNVERIFIED'
        gate = p.assess(snapshot(self.tmp_path), a, 'b' * 64)
        self.assertEqual(gate['bytes_per_trade_range'], {'lower': '100', 'upper': '200'})
        self.assertEqual(gate['segments']['C']['base_stored_bytes_upper'], 8_760_000_000)
        self.assertEqual(gate['segments']['A']['days'], 303)
        self.assertEqual(gate['segments']['B']['days'], 130)
        self.assertEqual(gate['segment_c_capacity'], 'UNVERIFIED')
        self.assertIsNone(gate['max_pilot_days'])

    def test_full_documented_signoff_can_approve_capacity_not_backfill(self):
        gate = p.assess(snapshot(self.tmp_path), full_assessment(), 'c' * 64)
        self.assertEqual(gate['segment_c_capacity'], 'APPROVED')
        self.assertEqual(gate['max_pilot_days'], 1)
        self.assertEqual(gate['max_staged_batch_days'], 7)
        self.assertIs(gate['backfill_launched'], False)
        self.assertIs(gate['dr_acceptance_claimed'], False)
        self.assertIn('DR_RESTORE_ACCEPTANCE_SEPARATE_FROM_PLATFORM_CAPACITY', gate['dependencies'])

    def test_missing_retention_bucket_proof_blocks_approval(self):
        a = full_assessment()
        a['bucket_retention_proof'] = a['bucket_retention_proof'][:2]
        gate = p.assess(snapshot(self.tmp_path), a, 'd' * 64)
        self.assertEqual(gate['segment_c_capacity'], 'UNVERIFIED')
        self.assertEqual(gate['retention_safe_for_506_day_research'], 'UNVERIFIED')

    def test_separate_wal_requires_measured_wal_margin(self):
        s = snapshot(self.tmp_path)
        s['volumes']['wal_path']['st_dev'] = 'different'
        gate = p.assess(s, full_assessment(), 'e' * 64)
        self.assertEqual(gate['segment_c_capacity'], 'UNVERIFIED')
        self.assertIn('SEPARATE_WAL_VOLUME_MARGIN_UNVERIFIED', gate['dependencies'])

    def test_measured_capacity_shortfall_is_not_approved(self):
        s = snapshot(self.tmp_path)
        s['volumes']['data_path']['fs_available_unprivileged_bytes'] = 1_000_000_000
        gate = p.assess(s, full_assessment(), 'f' * 64)
        self.assertEqual(gate['segment_c_capacity'], 'NOT_APPROVED')
        self.assertIn('MEASURED_SEGMENT_C_CAPACITY_DEFICIT', gate['dependencies'])

    def test_explicit_not_approved_honored(self):
        a = full_assessment()
        a['explicit_segment_c_capacity_signoff'] = 'NOT_APPROVED'
        gate = p.assess(snapshot(self.tmp_path), a, 'a' * 64)
        self.assertEqual(gate['segment_c_capacity'], 'NOT_APPROVED')

    def test_bad_snapshot_provenance_fails_closed(self):
        s = snapshot(self.tmp_path)
        s['source_gate']['status'] = 'INVALID'
        with self.assertRaisesRegex(ValueError, 'provenance'):
            p.assess(s, full_assessment(), 'a' * 64)

    def test_bad_window_attribution_fails_closed(self):
        a = full_assessment()
        a['attributed_storage_windows'][0]['exclusive_bucket_attribution'] = False
        gate = p.assess(snapshot(self.tmp_path), a, 'a' * 64)
        self.assertEqual(gate['segment_c_capacity'], 'UNVERIFIED')
        self.assertIsNone(gate['bytes_per_trade_range'])

    def test_untrusted_unknown_assessment_fields_rejected(self):
        a = assessment()
        a['influxdb_token'] = 'do not leak'
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            p.assess(snapshot(self.tmp_path), a, 'a' * 64)

    def test_output_inside_influx_data_refusal(self):
        scope_path = self.tmp_path / 'scope.json'
        scope_path.write_text(json.dumps(scope(self.tmp_path)))
        with mock.patch.object(p, 'verify_accepted_source', return_value=source()):
            result = p.main([
                'collect', '--scope', str(scope_path),
                '--output', str(self.tmp_path / 'snapshot.json'),
            ])
        self.assertEqual(result, 3)
        self.assertFalse((self.tmp_path / 'snapshot.json').exists())

    def test_offline_packet_self_verification(self):
        snap = snapshot(self.tmp_path)
        raw = p.dump(snap)
        ar = p.dump(assessment())
        gate = p.assess(snap, assessment(), hashlib.sha256(raw).hexdigest())
        path, digest = p.make_packet(raw, ar, gate, self.tmp_path / 'out')
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        with zipfile.ZipFile(path) as zf:
            entries = {
                name: zf.read(name) for name in zf.namelist()
                if name != 'MANIFEST.sha256'
            }
            p._verify_members(entries, zf.read('MANIFEST.sha256').decode())
            self.assertIn('SEGMENT_C_CAPACITY = UNVERIFIED', zf.read('HANDOFF_TO_MARKETDATA.md').decode())
        self.assertTrue((self.tmp_path / 'out' / (path.name + '.sha256')).is_file())

    def test_manifest_tampering_detected(self):
        members = {'gate.json': b'abc'}
        manifest = hashlib.sha256(b'abc').hexdigest() + '  gate.json\n'
        p._verify_members(members, manifest)
        with self.assertRaisesRegex(ValueError, 'INTEGRITY'):
            p._verify_members({'gate.json': b'abd'}, manifest)


if __name__ == '__main__':
    unittest.main()
