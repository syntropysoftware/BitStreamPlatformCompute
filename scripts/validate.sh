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

python3 -m py_compile src/platformcompute/phase0_infrastructure_evidence.py
python3 -m py_compile src/platformcompute/phase0b_infrastructure_reconciliation.py
python3 -m unittest discover -s tests -p 'test_phase0*.py'

python3 - <<'PY'
import json
import pathlib

root=pathlib.Path('.')
contract=json.loads((root/'contracts/phase0b_infrastructure_reconciliation_v1.json').read_text())
assert contract['contract']=='bitstream-platformcompute-phase0b-infrastructure-reconciliation-v1'
assert contract['authority']=='PLATFORM_INFRASTRUCTURE_FACTS_ONLY'
assert contract['mutation_policy']=='READ_ONLY_NO_MUTATION'

rows=[]
for raw in (root/'config/phase0b_targets.tsv').read_text().splitlines():
    if not raw or raw.lstrip().startswith('#'):
        continue
    parts=raw.split('\t')
    assert len(parts)==5, raw
    rows.append(parts)
assert {x[0] for x in rows} == {'H1_NexusDB','H1_ClientAppDB','H1_CBAdvClientAppDB','H1_Nexus'}
print(f'PASS: Phase-0B contract and {len(rows)} target rows validated.')
PY

printf '%s\n' 'PASS: Platform & Compute repository validation completed.'
