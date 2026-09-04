#!/usr/bin/env bash
set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
TARGETS_FILE="${BITSTREAM_PLATFORMCOMPUTE_TARGETS_FILE:-${REPO_ROOT}/config/phase0_targets.tsv}"
OUTPUT_ROOT="${BITSTREAM_PLATFORMCOMPUTE_OUTPUT_ROOT:-${REPO_ROOT}/output/phase0}"
COLLECTOR="${REPO_ROOT}/src/platformcompute/phase0_infrastructure_evidence.py"

printf '%s\n' '============================================================'
printf '%s\n' ' PLATFORM & COMPUTE — PHASE-0 READ-ONLY EVIDENCE'
printf '%s\n' '============================================================'
printf 'REPO_ROOT=%s\n' "$REPO_ROOT"
printf 'TARGETS_FILE=%s\n' "$TARGETS_FILE"
printf 'OUTPUT_ROOT=%s\n' "$OUTPUT_ROOT"
printf '%s\n' 'SAFETY=READ_ONLY / NO_SUDO / STRICT_HOST_KEYS / NO_MUTATION'

if [[ ! -f "$TARGETS_FILE" ]]; then
  printf 'STOPPED: targets file not found: %s\n' "$TARGETS_FILE" >&2
  exit 2
fi
if [[ ! -f "$COLLECTOR" ]]; then
  printf 'STOPPED: collector not found: %s\n' "$COLLECTOR" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'STOPPED: python3 is required on the invoking workstation.' >&2
  exit 2
fi
if ! command -v ssh >/dev/null 2>&1; then
  printf '%s\n' 'STOPPED: ssh is required on the invoking workstation.' >&2
  exit 2
fi

mkdir -p "$OUTPUT_ROOT"
python3 "$COLLECTOR" --targets "$TARGETS_FILE" --output-root "$OUTPUT_ROOT"
RC=$?

if [[ $RC -ne 0 ]]; then
  printf 'FAIL: Phase-0 read-only collector returned rc=%s\n' "$RC" >&2
  exit "$RC"
fi

printf '%s\n' 'PASS: Platform & Compute Phase-0 evidence helper completed.'
