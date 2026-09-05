#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
CONFIG="${BITSTREAM_PLATFORMCOMPUTE_PHASE0C_CONFIG:-${REPO_ROOT}/config/phase0c_targets.json}"
OUTPUT_ROOT="${BITSTREAM_PLATFORMCOMPUTE_PHASE0C_OUTPUT_ROOT:-${REPO_ROOT}/output/phase0c}"
COLLECTOR="${REPO_ROOT}/src/platformcompute/phase0c_focused_infrastructure_completion.py"
ACCEPTANCE_GATE="${REPO_ROOT}/scripts/validate_repository_acceptance_state.sh"

printf '%s\n' '============================================================'
printf '%s\n' ' PLATFORM & COMPUTE — PHASE-0C FOCUSED INFRASTRUCTURE COMPLETION'
printf '%s\n' '============================================================'
printf 'REPO_ROOT=%s\n' "$REPO_ROOT"
printf 'CONFIG=%s\n' "$CONFIG"
printf 'OUTPUT_ROOT=%s\n' "$OUTPUT_ROOT"
printf '%s\n' 'AUTHORITY=PLATFORM_INFRASTRUCTURE_FACTS_ONLY'
printf '%s\n' 'SAFETY=READ_ONLY / NO_SUDO / STRICT_HOST_KEYS / NO_TOFU / NO_TRUST_ENROLLMENT / NO_MUTATION'
printf '%s\n' 'NEXUSDB=SECURITY_DESIGN_APPROVED_IMPLEMENTATION_NOT_AUTHORIZED'

for REQUIRED in "$CONFIG" "$COLLECTOR" "$ACCEPTANCE_GATE"; do
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
printf '%s\n' '=== Repository regression validation ==='
bash "${REPO_ROOT}/scripts/validate.sh"

mkdir -p "$OUTPUT_ROOT"
printf '%s\n' ''
printf '%s\n' '=== Phase-0C bounded read-only collection ==='
python3 "$COLLECTOR" --config "$CONFIG" --output-root "$OUTPUT_ROOT"

printf '%s\n' 'PASS: Platform & Compute Phase-0C focused completion helper completed.'
