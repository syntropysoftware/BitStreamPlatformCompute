#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
cd "$REPO_ROOT"

printf '%s\n' '============================================================'
printf '%s\n' ' PLATFORM & COMPUTE — REPOSITORY VALIDATION'
printf '%s\n' '============================================================'

for script in scripts/*.sh; do
  [[ -f "$script" ]] || continue
  bash -n "$script"
done

for source in \
  src/platformcompute/phase0_infrastructure_evidence.py \
  src/platformcompute/phase0b_infrastructure_reconciliation.py \
  src/platformcompute/phase0c_focused_infrastructure_completion.py \
  src/platformcompute/phase0d_focused_route_persistence_reconciliation.py
do
  [[ -f "$source" ]] || { printf 'STOPPED: required source missing: %s\n' "$source" >&2; exit 2; }
  python3 -m py_compile "$source"
done

python3 -m unittest discover -s tests -p 'test_phase0*.py'

python3 - <<'PY'
import json
import pathlib
root=pathlib.Path('.')
contract=json.loads((root/'contracts/phase0c_focused_infrastructure_completion_v1.json').read_text())
assert contract['contract']=='bitstream-platformcompute-phase0c-focused-infrastructure-completion-v1'
assert contract['authority']=='PLATFORM_INFRASTRUCTURE_FACTS_ONLY'
assert contract['mutation_policy']=='READ_ONLY_NO_MUTATION'
assert contract['nexusdb_security_state']['platform_implementation_authorized'] is False
cfg=json.loads((root/'config/phase0c_targets.json').read_text())
assert cfg['mariadb18']['expected_ip']=='192.168.200.18'
assert cfg['redisserver6']['expected_ip']=='192.168.200.6'
assert cfg['clientappdb19']['expected_ip']=='192.168.200.19'
assert cfg['marketdata_influx']['bucket']=='CBAdvMarketData-BTC-USD'
assert cfg['nexusdb']['platform_implementation_authorized'] is False
print('PASS: Phase-0C contract, target identities, and NexusDB authority boundary validated.')
PY


python3 - <<'PY_PHASE0D'
import json
import pathlib
root=pathlib.Path('.')
contract=json.loads((root/'contracts/phase0d_focused_route_persistence_reconciliation_v1.json').read_text())
cfg=json.loads((root/'config/phase0d_targets.json').read_text())
assert contract['contract']==cfg['contract']=='bitstream-platformcompute-phase0d-focused-route-persistence-reconciliation-v1'
assert contract['authority']=='PLATFORM_INFRASTRUCTURE_FACTS_ONLY'
assert contract['mutation_policy']=='READ_ONLY_NO_MUTATION'
assert contract['nexusdb_implementation_authorized'] is False
assert cfg['baseline']['sha256']=='025dd06bf367659eaf94a7d65bd6c30efa36d6a0272ae941d2b1465efa6c669d'
assert cfg['guest_targets'][0]['expected_ip']=='192.168.200.18'
assert cfg['guest_targets'][1]['expected_ip']=='192.168.200.6'
assert cfg['guest_targets'][2]['expected_ip']=='192.168.200.19'
assert cfg['nexusdb']['platform_implementation_authorized'] is False
print('PASS: Phase-0D route/persistence contract and authority boundary validated.')
PY_PHASE0D

printf '%s\n' 'PASS: Platform & Compute repository validation completed.'
