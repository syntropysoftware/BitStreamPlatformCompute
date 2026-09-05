#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
TARGETS_FILE="${BITSTREAM_PLATFORMCOMPUTE_PHASE0B_TARGETS_FILE:-${REPO_ROOT}/config/phase0b_targets.tsv}"
OUTPUT_ROOT="${BITSTREAM_PLATFORMCOMPUTE_PHASE0B_OUTPUT_ROOT:-${REPO_ROOT}/output/phase0b}"
COLLECTOR="${REPO_ROOT}/src/platformcompute/phase0b_infrastructure_reconciliation.py"
ACCEPTANCE_GATE="${REPO_ROOT}/scripts/validate_repository_acceptance_state.sh"

printf '%s\n' '============================================================'
printf '%s\n' ' PLATFORM & COMPUTE — PHASE-0B BLOCKER / OWNERSHIP RECONCILIATION'
printf '%s\n' '============================================================'
printf 'REPO_ROOT=%s\n' "$REPO_ROOT"
printf 'TARGETS_FILE=%s\n' "$TARGETS_FILE"
printf 'OUTPUT_ROOT=%s\n' "$OUTPUT_ROOT"
printf '%s\n' 'AUTHORITY=PLATFORM_INFRASTRUCTURE_FACTS_ONLY'
printf '%s\n' 'SAFETY=READ_ONLY / NO_SUDO / STRICT_HOST_KEYS / NO_TRUST_ENROLLMENT / NO_MUTATION'

for REQUIRED in "$TARGETS_FILE" "$COLLECTOR" "$ACCEPTANCE_GATE"; do
  if [[ ! -f "$REQUIRED" ]]; then
    printf 'STOPPED: required file not found: %s\n' "$REQUIRED" >&2
    exit 2
  fi
done

for CMD in python3 ssh git; do
  if ! command -v "$CMD" >/dev/null 2>&1; then
    printf 'STOPPED: %s is required on the invoking workstation.\n' "$CMD" >&2
    exit 2
  fi
done

printf '%s\n' ''
printf '%s\n' '=== Accepted-source gate ==='
bash "$ACCEPTANCE_GATE"

printf '%s\n' ''
printf '%s\n' '=== Regression tests ==='
python3 -m unittest discover -s "${REPO_ROOT}/tests" -p 'test_phase0*.py'

mkdir -p "$OUTPUT_ROOT"
printf '%s\n' ''
printf '%s\n' '=== Phase-0B read-only collection ==='
python3 "$COLLECTOR" --targets "$TARGETS_FILE" --output-root "$OUTPUT_ROOT"

printf '%s\n' 'PASS: Platform & Compute Phase-0B reconciliation helper completed.'
